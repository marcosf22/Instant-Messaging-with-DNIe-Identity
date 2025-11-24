import asyncio
import sys
import socket
import threading
import queue

# Importamos tus módulos (asegúrate de que existen)
from crypto import KeyManager, SessionCrypto
from protocol import ChatProtocol, MSG_HELLO, MSG_DATA, MSG_DISCOVERY

# Configuración
PORT = 8888 

def get_best_ip():
    """Obtiene la IP local / ZeroTier"""
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
        
        # Red
        self.my_ip = get_best_ip()
        try:
            parts = self.my_ip.split('.')
            self.broadcast_addr = f"{parts[0]}.{parts[1]}.{parts[2]}.255"
        except:
            self.broadcast_addr = "255.255.255.255"

        print(f"--> Mi IP: {self.my_ip}")
        print(f"--> Broadcast: {self.broadcast_addr}")

        # Criptografía
        try:
            self.key_manager = KeyManager(f"{name}_identity")
        except Exception as e:
            print(f"❌ Error crypto: {e}")
            sys.exit(1)

        self.sessions = {}        
        self.peers = {}           
        self.peer_counter = 0     
        self.target_ip = None     # Si es None, estamos en el "Lobby"
        
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
        """Muestra la lista de contactos de forma bonita"""
        print("\n" + "="*30)
        print(" 👥  CONTACTOS DISPONIBLES")
        print("="*30)
        if not self.peers:
            print("   (Buscando... espera unos segundos)")
        
        for pid, d in self.peers.items():
            print(f"   [{pid}]  {d['name']:<15}  ({d['ip']})")
        print("="*30)
        print("👉 Usa '/connect <ID>' para entrar al chat.")

    def disconnect_current(self):
        """Sale del chat actual y vuelve al lobby"""
        if self.target_ip:
            print(f"\n🔌 Desconectado de {self.target_ip}.")
            self.target_ip = None
        
        # Siempre mostramos la lista al salir
        self.show_peers()
        print("(Lobby) > ", end="", flush=True)

    def on_packet(self, packet, addr):
        ip = addr[0]
        if ip == self.my_ip: return 

        # --- CASO 1: Discovery ---
        if packet.msg_type == MSG_DISCOVERY:
            nombre = packet.payload
            
            if ip not in [p['ip'] for p in self.peers.values()]:
                 pid = self.peer_counter
                 self.peers[pid] = {'ip': ip, 'port': PORT, 'name': nombre}
                 self.peer_counter += 1
                 
                 # Si estamos en el lobby, avisamos visualmente
                 if self.target_ip is None:
                     print(f"\n🔭 Nuevo contacto: [{pid}] {nombre}")
                     print("(Lobby) > ", end="", flush=True)
            return

        # --- CASO 2: Handshake ---
        if packet.msg_type == MSG_HELLO:
            if ip not in self.sessions:
                # Solo avisamos si estamos en el lobby
                if self.target_ip is None:
                    print(f"\n[!] {ip} quiere conectar contigo.")
                
                session = SessionCrypto(self.key_manager.static_private)
                self.sessions[ip] = session
                try:
                    session.perform_handshake(packet.payload, is_initiator=True)
                    my_key = session.get_ephemeral_public_bytes()
                    self.protocol.send_packet(ip, PORT, MSG_HELLO, 0, my_key)
                except: pass
            else:
                try:
                    self.sessions[ip].perform_handshake(packet.payload, is_initiator=True)
                    # Si alguien nos conecta y nosotros estábamos en el lobby, entramos al chat
                    if self.target_ip != ip:
                         # Opcional: Auto-conectar si nos hablan
                         # self.target_ip = ip 
                         # print(f"\n✅ Conectado con {ip}")
                         pass
                except: pass

        # --- CASO 3: Mensajes ---
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
            else:
                # Si llega mensaje sin sesión, intentamos reconectar
                self.connect_manual(ip)

    def connect_manual(self, ip_target):
        print(f"--> Conectando a {ip_target}...")
        session = SessionCrypto(self.key_manager.static_private)
        self.sessions[ip_target] = session
        my_key = session.get_ephemeral_public_bytes()
        for _ in range(3):
            self.protocol.send_packet(ip_target, PORT, MSG_HELLO, 0, my_key)
        self.target_ip = ip_target
        print("✅ Chat listo. Escribe para hablar.")

    def send_chat(self, text):
        if self.target_ip:
            if self.target_ip in self.sessions:
                try:
                    enc = self.sessions[self.target_ip].encrypt(text)
                    self.protocol.send_packet(self.target_ip, PORT, MSG_DATA, 1, enc)
                except: pass
        else:
            print("⛔ No estás conectado a nadie. Usa /connect <ID>")

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
    client.show_peers() # Mostrar lista al inicio
    print("(Lobby) > ", end="", flush=True)

    while True:
        while not input_queue.empty():
            msg = input_queue.get_nowait()
            
            # COMANDOS
            if msg == "/quit": 
                return
            
            elif msg == "/leave":
                client.disconnect_current()
            
            elif msg.startswith("/connect"):
                parts = msg.split()
                if len(parts) > 1:
                    target = parts[1]
                    if '.' in target: 
                        client.connect_manual(target)
                    elif target.isdigit() and int(target) in client.peers:
                        client.connect_manual(client.peers[int(target)]['ip'])
                    else:
                        print("❌ ID no válido.")
                else:
                    print("⚠️ Uso: /connect <ID>")
            
            elif msg == "/list":
                 client.show_peers()
                 prompt = "Tú > " if client.target_ip else "(Lobby) > "
                 print(prompt, end="", flush=True)

            # CHAT NORMAL
            else:
                if client.target_ip:
                    client.send_chat(msg)
                    print("Tú > ", end="", flush=True)
                else:
                    if msg.strip(): # Si no es una línea vacía
                        print("⛔ Error: Estás en el Lobby. Usa '/connect <ID>' o '/list'")
                        print("(Lobby) > ", end="", flush=True)
        
        await asyncio.sleep(0.1)

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt: pass
