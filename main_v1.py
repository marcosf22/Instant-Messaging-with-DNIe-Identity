import asyncio
import sys
import socket
import threading
import queue
import json  # <--- NECESARIO PARA GUARDAR EN DISCO
import os

from crypto import KeyManager, SessionCrypto
from protocol import ChatProtocol, MSG_HELLO, MSG_DATA, MSG_DISCOVERY

PORT = 8888 
SESSION_FILE = "sessions.json" # Archivo donde se guardarán las claves

def get_best_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 1)) 
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

class ChatClient:
    def __init__(self, name):
        self.name = name
        self.loop = asyncio.get_running_loop()
        self.my_ip = get_best_ip()
        
        # Calcular Broadcast
        try:
            parts = self.my_ip.split('.')
            self.broadcast_addr = f"{parts[0]}.{parts[1]}.{parts[2]}.255"
        except:
            self.broadcast_addr = "255.255.255.255"

        print(f"--> Mi IP: {self.my_ip}")

        try:
            self.key_manager = KeyManager(f"{name}_identity")
        except Exception as e:
            print(f"❌ Error crypto: {e}")
            sys.exit(1)

        self.sessions = {}        
        self.peers = {}           
        self.peer_counter = 0     
        self.target_ip = None     
        self.pending_requests = {} 

        self.protocol = ChatProtocol(self.on_packet)
        self.transport = None
        
        # --- CARGAR SESIONES GUARDADAS ---
        self.load_sessions_from_disk()

    def load_sessions_from_disk(self):
        """Lee el archivo JSON y restaura las claves antiguas"""
        if not os.path.exists(SESSION_FILE):
            return

        try:
            with open(SESSION_FILE, 'r') as f:
                saved_data = json.load(f)
            
            count = 0
            for ip, hex_key in saved_data.items():
                # Recreamos la sesión manualmente
                session = SessionCrypto(self.key_manager.static_private)
                try:
                    session.load_secret(hex_key) # Usamos la función que añadiste a crypto.py
                    self.sessions[ip] = session
                    count += 1
                except:
                    print(f"⚠️ Clave corrupta para {ip}, ignorada.")
            
            if count > 0:
                print(f"💾 {count} sesiones recuperadas del disco.")
        except Exception as e:
            print(f"⚠️ Error cargando sesiones: {e}")

    def save_sessions_to_disk(self):
        """Guarda todas las sesiones activas a disco"""
        data_to_save = {}
        for ip, session in self.sessions.items():
            key_hex = session.export_secret() # Usamos la función que añadiste
            if key_hex:
                data_to_save[ip] = key_hex
        
        try:
            with open(SESSION_FILE, 'w') as f:
                json.dump(data_to_save, f)
            # print("💾 Sesiones guardadas.")
        except Exception as e:
            print(f"❌ Error guardando sesiones: {e}")

    async def start(self):
        print(f"--- CHAT INICIADO EN PUERTO {PORT} ---")
        self.transport, _ = await self.loop.create_datagram_endpoint(
            lambda: self.protocol, 
            local_addr=("0.0.0.0", PORT),
            allow_broadcast=True
        )
        self.loop.create_task(self.beacon_loop())

    async def beacon_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            sock.bind((self.my_ip, 0))
        except: pass

        msg = f"DISCOVERY:{self.name}".encode('utf-8')

        while True:
            try:
                sock.sendto(msg, (self.broadcast_addr, PORT))
            except: pass
            await asyncio.sleep(3)

    def show_peers(self):
        print("\n" + "="*30)
        print(" 👥  CONTACTOS DISPONIBLES")
        print("="*30)
        
        for pid, d in self.peers.items():
            status = ""
            # Si tenemos sesión guardada, mostramos un candado
            if d['ip'] in self.sessions:
                status = " [🔐 Clave Guardada]"
            print(f"   [{pid}]  {d['name']:<15} {status}")
        
        if self.pending_requests:
            print("-" * 30)
            print(" 🔔 SOLICITUDES PENDIENTES:")
            for ip in self.pending_requests:
                name = "Desconocido"
                pid_str = "?"
                for pid, d in self.peers.items():
                    if d['ip'] == ip: 
                        name = d['name']
                        pid_str = str(pid)
                print(f"   [ID: {pid_str}] {name} quiere conectar. (/accept {pid_str})")
        print("="*30)

    def disconnect_current(self):
        if self.target_ip:
            print(f"\n🔌 Sales del chat con {self.target_ip} (pero recordamos la clave).")
            self.target_ip = None
        self.show_peers()
        print("(Lobby) > ", end="", flush=True)

    def accept_connection(self, peer_id):
        if peer_id not in self.peers:
            print("❌ ID incorrecto.")
            return

        ip = self.peers[peer_id]['ip']
        name = self.peers[peer_id]['name']

        if ip not in self.pending_requests:
            print(f"⚠️ No hay solicitud pendiente de {name}.")
            return
        
        handshake_payload = self.pending_requests[ip]
        
        print(f"✅ Aceptando y guardando claves de {name}...")
        session = SessionCrypto(self.key_manager.static_private)
        self.sessions[ip] = session
        
        try:
            session.perform_handshake(handshake_payload, is_initiator=True)
            my_key = session.get_ephemeral_public_bytes()
            for _ in range(3):
                self.protocol.send_packet(ip, PORT, MSG_HELLO, 0, my_key)
            
            self.target_ip = ip
            del self.pending_requests[ip]
            
            # --- GUARDAR EN DISCO AL ACEPTAR ---
            self.save_sessions_to_disk()
            
            print(f"\n✨ CONECTADO Y GUARDADO.")
            print("Tú > ", end="", flush=True)

        except Exception as e:
            print(f"❌ Error al aceptar: {e}")

    def on_packet(self, packet, addr):
        ip = addr[0]
        if ip == self.my_ip: return 

        if packet.msg_type == MSG_DISCOVERY:
            nombre = packet.payload
            if ip not in [p['ip'] for p in self.peers.values()]:
                 pid = self.peer_counter
                 self.peers[pid] = {'ip': ip, 'port': PORT, 'name': nombre}
                 self.peer_counter += 1
                 if self.target_ip is None:
                     print(f"\n🔭 Nuevo contacto: [{pid}] {nombre}")
                     print("(Lobby) > ", end="", flush=True)
            return

        if packet.msg_type == MSG_HELLO:
            # Si ya tenemos sesión, simplemente ignoramos el handshake repetido
            # O actualizamos si queremos renegociar. 
            # Por ahora, si tenemos sesión, asumimos que está OK.
            if ip in self.sessions:
                try:
                    self.sessions[ip].perform_handshake(packet.payload, is_initiator=True)
                    self.save_sessions_to_disk() # Actualizar si cambiaron
                except: pass
                return

            if ip not in self.pending_requests:
                self.pending_requests[ip] = packet.payload
                name = ip
                pid_found = "?"
                for pid, d in self.peers.items():
                    if d['ip'] == ip: 
                        name = d['name']
                        pid_found = pid
                
                print(f"\n🔔 {name} quiere conectar (Claves nuevas).")
                print(f"   Escribe '/accept {pid_found}'")
                prompt = "Tú > " if self.target_ip else "(Lobby) > "
                print(prompt, end="", flush=True)

        elif packet.msg_type == MSG_DATA:
            if ip in self.sessions:
                try:
                    msg = self.sessions[ip].decrypt(packet.payload)
                    name = ip
                    for p in self.peers.values():
                        if p['ip'] == ip: name = p['name']
                    
                    sys.stdout.write("\r\033[K")
                    print(f"[{name}]: {msg}")
                    
                    if self.target_ip == ip:
                        print("Tú > ", end="", flush=True)
                    else:
                        print(f"(Mensaje de {name})")
                        print("(Lobby) > ", end="", flush=True)
                except: 
                    # Si falla desencriptar, quizás la clave vieja no sirve.
                    # Borramos la sesión para forzar reconexión
                    print(f"\n⚠️ La clave guardada con {ip} ya no sirve. Bórrala y reconecta.")
            else:
                # Si nos hablan y no tenemos clave, pedimos conectar
                print(f"\n⚠️ Mensaje ilegible de {ip}. Pide conectar de nuevo.")
                self.connect_manual(ip)

    def connect_manual(self, ip_target):
        # --- VERIFICACIÓN DE CLAVES GUARDADAS ---
        if ip_target in self.sessions:
            print(f"✅ ¡Clave encontrada! Conectando sin pedir permiso...")
            self.target_ip = ip_target
            # Enviamos un mensaje vacío o de saludo para confirmar (opcional)
            print("Chat restaurado. Escribe.")
            return

        # Si no hay clave, hacemos el protocolo normal
        print(f"--> Enviando solicitud nueva a {ip_target}...")
        session = SessionCrypto(self.key_manager.static_private)
        self.sessions[ip_target] = session
        my_key = session.get_ephemeral_public_bytes()
        for _ in range(3):
            self.protocol.send_packet(ip_target, PORT, MSG_HELLO, 0, my_key)
        
        # Al iniciar nosotros, guardamos la sesión temporalmente, 
        # pero se confirmará (y guardará en disco) cuando él responda HELLO
        self.target_ip = ip_target
        print("⏳ Solicitud enviada...")

    def send_chat(self, text):
        if self.target_ip and self.target_ip in self.sessions:
            try:
                enc = self.sessions[self.target_ip].encrypt(text)
                self.protocol.send_packet(self.target_ip, PORT, MSG_DATA, 1, enc)
            except: pass
        else:
            print("⛔ No conectado.")

async def main():
    if len(sys.argv) > 1: name = sys.argv[1]
    else: name = input("Tu nombre: ")
    
    client = ChatClient(name)
    await client.start()

    input_queue = queue.Queue()
    def kbd():
        while True:
            try:
                l = sys.stdin.readline()
                if l: input_queue.put(l.strip())
            except: break
    threading.Thread(target=kbd, daemon=True).start()

    print("\n--- SISTEMA CON MEMORIA ---")
    client.show_peers()
    print("(Lobby) > ", end="", flush=True)

    while True:
        while not input_queue.empty():
            msg = input_queue.get_nowait()
            
            if msg == "/quit": 
                client.save_sessions_to_disk() # Asegurar guardado al salir
                return
            elif msg == "/leave": client.disconnect_current()
            
            elif msg.startswith("/connect"):
                parts = msg.split()
                if len(parts) > 1 and parts[1].isdigit():
                    pid = int(parts[1])
                    if pid in client.peers:
                        client.connect_manual(client.peers[pid]['ip'])
                    else: print("❌ ID incorrecto")
                else: print("⚠️ Uso: /connect <ID>")

            elif msg.startswith("/accept"):
                parts = msg.split()
                if len(parts) > 1 and parts[1].isdigit():
                    client.accept_connection(int(parts[1]))
                else: print("⚠️ Uso: /accept <ID>")

            elif msg == "/list":
                 client.show_peers()
                 prompt = "Tú > " if client.target_ip else "(Lobby) > "
                 print(prompt, end="", flush=True)

            else:
                if client.target_ip:
                    client.send_chat(msg)
                    print("Tú > ", end="", flush=True)
                else:
                    if msg.strip():
                        print("⛔ Estás en Lobby.")
                        print("(Lobby) > ", end="", flush=True)
        
        await asyncio.sleep(0.1)

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt: pass
