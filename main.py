import asyncio
import sys
import socket
import threading
import queue
import json
import os

# Importamos tus módulos
from crypto import KeyManager, SessionCrypto
from protocol import ChatProtocol, MSG_HELLO, MSG_DATA, MSG_DISCOVERY

# Configuración
PORT = 8888 
SESSION_FILE = "sessions.json"

def get_best_ip():
    """Obtiene la IP local de salida (WiFi, Ethernet o VPN)"""
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
        
        # Calcular dirección de Broadcast
        try:
            parts = self.my_ip.split('.')
            self.broadcast_addr = f"{parts[0]}.{parts[1]}.{parts[2]}.255"
        except:
            self.broadcast_addr = "255.255.255.255"

        print(f"--> Mi IP: {self.my_ip}")
        print(f"--> Broadcast Target: {self.broadcast_addr}")

        # Cargar Identidad (DNIe / X25519)
        try:
            self.key_manager = KeyManager(f"{name}_identity")
        except Exception as e:
            print(f"❌ Error cargando crypto.py: {e}")
            sys.exit(1)

        self.sessions = {}        
        self.peers = {}           
        self.peer_counter = 0     
        self.target_ip = None     
        self.pending_requests = {} 

        self.protocol = ChatProtocol(self.on_packet)
        self.transport = None
        
        # Cargar sesiones guardadas al iniciar
        self.load_sessions_from_disk()

    # --- PERSISTENCIA (GUARDAR Y CARGAR) ---
    def load_sessions_from_disk(self):
        if not os.path.exists(SESSION_FILE):
            return

        try:
            with open(SESSION_FILE, 'r') as f:
                saved_data = json.load(f)
            
            count = 0
            for ip, hex_key in saved_data.items():
                # Reconstruimos la sesión con la clave guardada
                session = SessionCrypto(self.key_manager.static_private)
                try:
                    session.load_secret(hex_key)
                    self.sessions[ip] = session
                    count += 1
                except Exception:
                    pass # Ignoramos claves corruptas
            
            if count > 0:
                print(f"💾 {count} sesiones recuperadas del disco.")
        except Exception as e:
            print(f"⚠️ Error leyendo sessions.json: {e}")

    def save_sessions_to_disk(self):
        data_to_save = {}
        for ip, session in self.sessions.items():
            key_hex = session.export_secret()
            if key_hex:
                data_to_save[ip] = key_hex
        
        try:
            with open(SESSION_FILE, 'w') as f:
                json.dump(data_to_save, f, indent=4)
        except Exception as e:
            print(f"❌ Error guardando sesiones: {e}")

    # --- RED Y DISCOVERY ---
    async def start(self):
        print(f"--- CHAT INICIADO EN PUERTO {PORT} ---")
        self.transport, _ = await self.loop.create_datagram_endpoint(
            lambda: self.protocol, 
            local_addr=("0.0.0.0", PORT),
            allow_broadcast=True
        )
        self.loop.create_task(self.beacon_loop())

    async def beacon_loop(self):
        """Envía señal de vida cada 3 segundos"""
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

    # --- INTERFAZ DE USUARIO ---
    def show_peers(self):
        print("\n" + "="*30)
        print(" 👥  CONTACTOS DISPONIBLES")
        print("="*30)
        
        for pid, d in self.peers.items():
            status = ""
            if d['ip'] in self.sessions:
                status = " [🔐 Guardado]"
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
            print(f"\n🔌 Desconectado de {self.target_ip}.")
            self.target_ip = None
        self.show_peers()
        print("(Lobby) > ", end="", flush=True)

    def accept_connection(self, peer_id):
        """Acepta una solicitud pendiente"""
        if peer_id not in self.peers:
            print("❌ ID incorrecto.")
            return

        ip = self.peers[peer_id]['ip']
        name = self.peers[peer_id]['name']

        if ip not in self.pending_requests:
            print(f"⚠️ {name} no tiene solicitud pendiente.")
            return
        
        handshake_payload = self.pending_requests[ip]
        
        print(f"✅ Aceptando a {name}...")
        session = SessionCrypto(self.key_manager.static_private)
        self.sessions[ip] = session
        
        try:
            session.perform_handshake(handshake_payload, is_initiator=True)
            my_key = session.get_ephemeral_public_bytes()
            for _ in range(3):
                self.protocol.send_packet(ip, PORT, MSG_HELLO, 0, my_key)
            
            self.target_ip = ip
            del self.pending_requests[ip]
            
            # GUARDAR AL ACEPTAR
            self.save_sessions_to_disk()
            
            print(f"\n✨ CONEXIÓN ESTABLECIDA.")
            print("Tú > ", end="", flush=True)

        except Exception as e:
            print(f"❌ Error al aceptar: {e}")

    # --- LÓGICA DE PAQUETES (Aquí está la magia) ---
    def on_packet(self, packet, addr):
        ip = addr[0]
        if ip == self.my_ip: return 

        # 1. DISCOVERY
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

        # 2. HANDSHAKE (HELLO)
        if packet.msg_type == MSG_HELLO:
            # Si ya tenemos sesión, asumimos renegociación silenciosa
            if ip in self.sessions:
                try:
                    self.sessions[ip].perform_handshake(packet.payload, is_initiator=True)
                    self.save_sessions_to_disk()
                except: pass
                return

            if ip not in self.pending_requests:
                self.pending_requests[ip] = packet.payload
                # Avisar al usuario
                name = ip
                pid_found = "?"
                for pid, d in self.peers.items():
                    if d['ip'] == ip: 
                        name = d['name']
                        pid_found = pid
                
                print(f"\n🔔 ¡SOLICITUD DE CHAT de {name}!")
                print(f"   Escribe '/accept {pid_found}'")
                prompt = "Tú > " if self.target_ip else "(Lobby) > "
                print(prompt, end="", flush=True)

        # 3. MENSAJES DE CHAT (DATA)
        elif packet.msg_type == MSG_DATA:
            if ip in self.sessions:
                try:
                    msg = self.sessions[ip].decrypt(packet.payload)
                    
                    # Mostrar mensaje bonito
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

                except Exception: 
                    # --- AQUÍ ESTÁ EL ARREGLO DE AUTO-RECUPERACIÓN ---
                    print(f"\n♻️ La clave antigua con {ip} no funciona. Renegociando...")
                    
                    # 1. Borramos la clave mala de memoria
                    del self.sessions[ip]
                    
                    # 2. Guardamos el cambio (se borra del json)
                    self.save_sessions_to_disk()
                    
                    # 3. Pedimos conectar de nuevo automáticamente
                    self.connect_manual(ip)
            else:
                # Si llega mensaje sin sesión, pedimos conectar
                print(f"\n⚠️ Mensaje ilegible de {ip}. Reconectando...")
                self.connect_manual(ip)

    def connect_manual(self, ip_target):
        # Si tenemos clave guardada, la usamos directo
        if ip_target in self.sessions:
            print(f"✅ Usando clave guardada con {ip_target}...")
            self.target_ip = ip_target
            print("Chat restaurado. Escribe.")
            return

        # Si no, protocolo completo
        print(f"--> Enviando solicitud a {ip_target}...")
        session = SessionCrypto(self.key_manager.static_private)
        self.sessions[ip_target] = session
        my_key = session.get_ephemeral_public_bytes()
        for _ in range(3):
            self.protocol.send_packet(ip_target, PORT, MSG_HELLO, 0, my_key)
        
        self.target_ip = ip_target
        print("⏳ Esperando que acepte...")

    def send_chat(self, text):
        if self.target_ip and self.target_ip in self.sessions:
            try:
                enc = self.sessions[self.target_ip].encrypt(text)
                self.protocol.send_packet(self.target_ip, PORT, MSG_DATA, 1, enc)
            except: pass
        else:
            print("⛔ No conectado.")

# --- BUCLE PRINCIPAL ---
async def main():
    if len(sys.argv) > 1:
        name = sys.argv[1]
    else:
        name = input("Tu nombre: ")
    
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

    print("\n--- SISTEMA LISTO ---")
    client.show_peers()
    print("(Lobby) > ", end="", flush=True)

    while True:
        while not input_queue.empty():
            msg = input_queue.get_nowait()
            
            if msg == "/quit": 
                client.save_sessions_to_disk()
                return
            elif msg == "/leave": 
                client.disconnect_current()
            
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
                        print("⛔ Lobby: Usa /connect <ID>")
                        print("(Lobby) > ", end="", flush=True)
        
        await asyncio.sleep(0.1)

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt: pass