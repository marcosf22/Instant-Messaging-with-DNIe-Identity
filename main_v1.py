import asyncio
import sys
import socket
import threading
import queue

from crypto import KeyManager, SessionCrypto
from protocol import ChatProtocol, MSG_HELLO, MSG_DATA, MSG_DISCOVERY

PORT = 8888 

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
        
        # --- NUEVO: LISTA DE SOLICITUDES PENDIENTES ---
        # Guardaremos aquí la IP y el Payload (clave pública del otro) esperando a ser aceptada
        self.pending_requests = {} 

        self.protocol = ChatProtocol(self.on_packet)
        self.transport = None

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
        
        # Mostrar peers normales
        for pid, d in self.peers.items():
            print(f"   [{pid}]  {d['name']:<15}")
        
        # Mostrar solicitudes pendientes
        if self.pending_requests:
            print("-" * 30)
            print(" 🔔 SOLICITUDES PENDIENTES:")
            for ip in self.pending_requests:
                # Buscamos si tiene nombre en la lista de peers
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

    # --- NUEVA LÓGICA DE ACEPTAR ---
    def accept_connection(self, peer_id):
        if peer_id not in self.peers:
            print("❌ ID de usuario no encontrado.")
            return

        ip = self.peers[peer_id]['ip']
        name = self.peers[peer_id]['name']

        # Verificamos si realmente había pedido entrar
        if ip not in self.pending_requests:
            print(f"⚠️ {name} no te ha enviado solicitud (o ya caducó).")
            print("   Usa /connect para invitarle tú a él.")
            return
        
        # Recuperamos el paquete de handshake que guardamos en espera
        handshake_payload = self.pending_requests[ip]
        
        print(f"✅ Aceptando a {name}...")
        
        # Iniciamos la criptografía ahora
        session = SessionCrypto(self.key_manager.static_private)
        self.sessions[ip] = session
        
        try:
            # Procesamos su clave
            session.perform_handshake(handshake_payload, is_initiator=True)
            
            # Le respondemos con nuestra clave
            my_key = session.get_ephemeral_public_bytes()
            # Enviamos 3 veces por seguridad UDP
            for _ in range(3):
                self.protocol.send_packet(ip, PORT, MSG_HELLO, 0, my_key)
            
            # Conectamos y limpiamos la lista de pendientes
            self.target_ip = ip
            del self.pending_requests[ip]
            
            print(f"\n✨ CONEXIÓN ESTABLECIDA CON {name}")
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

        # --- MODIFICACIÓN CLAVE: HANDSHAKE ---
        if packet.msg_type == MSG_HELLO:
            # Si YA estamos conectados con él, ignoramos o actualizamos
            if ip in self.sessions:
                try:
                    self.sessions[ip].perform_handshake(packet.payload, is_initiator=True)
                except: pass
                return

            # Si NO estamos conectados, es una SOLICITUD NUEVA
            if ip not in self.pending_requests:
                # Guardamos su clave en la sala de espera
                self.pending_requests[ip] = packet.payload
                
                # Buscamos su nombre para avisar bonito
                name = ip
                pid_found = "?"
                for pid, d in self.peers.items():
                    if d['ip'] == ip: 
                        name = d['name']
                        pid_found = pid
                
                print(f"\n🔔 ¡SOLICITUD DE CHAT RECIBIDA!")
                print(f"   De: {name} [ID: {pid_found}]")
                print(f"   Escribe '/accept {pid_found}' para hablar con él.")
                
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
                        print(f"(Mensaje de {name} - No estás conectado a él)")
                        print("(Lobby) > ", end="", flush=True)
                except: pass

    def connect_manual(self, ip_target):
        print(f"--> Enviando invitación a {ip_target}...")
        session = SessionCrypto(self.key_manager.static_private)
        self.sessions[ip_target] = session
        my_key = session.get_ephemeral_public_bytes()
        for _ in range(3):
            self.protocol.send_packet(ip_target, PORT, MSG_HELLO, 0, my_key)
        self.target_ip = ip_target
        print("⏳ Invitación enviada. Esperando a que acepte...")

    def send_chat(self, text):
        if self.target_ip and self.target_ip in self.sessions:
            try:
                enc = self.sessions[self.target_ip].encrypt(text)
                self.protocol.send_packet(self.target_ip, PORT, MSG_DATA, 1, enc)
            except: pass
        else:
            print("⛔ No estás conectado. Usa /connect o /accept")

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

    print("\n--- SISTEMA LISTO ---")
    client.show_peers()
    print("(Lobby) > ", end="", flush=True)

    while True:
        while not input_queue.empty():
            msg = input_queue.get_nowait()
            
            if msg == "/quit": return
            elif msg == "/leave": client.disconnect_current()
            
            # --- COMANDO CONNECT (Para iniciar tú) ---
            elif msg.startswith("/connect"):
                parts = msg.split()
                if len(parts) > 1 and parts[1].isdigit():
                    pid = int(parts[1])
                    if pid in client.peers:
                        client.connect_manual(client.peers[pid]['ip'])
                    else: print("❌ ID incorrecto")
                else: print("⚠️ Uso: /connect <ID>")

            # --- NUEVO COMANDO ACCEPT (Para responder) ---
            elif msg.startswith("/accept"):
                parts = msg.split()
                if len(parts) > 1 and parts[1].isdigit():
                    client.accept_connection(int(parts[1]))
                else:
                    print("⚠️ Uso: /accept <ID>")

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
                        print("⛔ Lobby: Usa /connect <ID> o /accept <ID>")
                        print("(Lobby) > ", end="", flush=True)
        
        await asyncio.sleep(0.1)

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt: pass
