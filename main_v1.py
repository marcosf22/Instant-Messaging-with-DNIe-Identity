import asyncio
import sys
import socket
import threading
import queue

# Importamos tu archivo de criptografía (Asumiendo que crypto.py existe en la carpeta)
from crypto import KeyManager, SessionCrypto
# Importamos el protocolo modificado
from protocol import ChatProtocol, MSG_HELLO, MSG_DATA, MSG_DISCOVERY

# Configuración
PORT = 8888 

def get_best_ip():
    """
    Obtiene la IP que tu ordenador usa para salir al mundo.
    Funciona tanto para LAN (WiFi) como para VPN si es la ruta por defecto.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Conectamos a una IP pública (Google DNS) para ver qué ruta elige el OS
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
        
        # 1. Configuración de Red
        self.my_ip = get_best_ip()
        
        # Calculamos Broadcast (Asumiendo máscara /24 estándar)
        # Ej: 192.168.1.33 -> 192.168.1.255
        try:
            parts = self.my_ip.split('.')
            self.broadcast_addr = f"{parts[0]}.{parts[1]}.{parts[2]}.255"
        except:
            self.broadcast_addr = "255.255.255.255"

        print(f"--> Mi IP: {self.my_ip}")
        print(f"--> Broadcast Target: {self.broadcast_addr}")

        # 2. Criptografía
        try:
            self.key_manager = KeyManager(f"{name}_identity")
        except Exception as e:
            print(f"❌ Error cargando crypto.py: {e}")
            sys.exit(1)

        self.sessions = {}        
        self.peers = {}           
        self.peer_counter = 0     
        self.target_ip = None     
        
        self.protocol = ChatProtocol(self.on_packet)
        self.transport = None

    async def start(self):
        print(f"--- CHAT INICIADO EN PUERTO {PORT} ---")
        
        # Bind a 0.0.0.0 para escuchar por TODAS las interfaces (WiFi, Cable, ZT)
        self.transport, _ = await self.loop.create_datagram_endpoint(
            lambda: self.protocol, 
            local_addr=("0.0.0.0", PORT),
            allow_broadcast=True
        )
        
        # Iniciamos el radar
        self.loop.create_task(self.beacon_loop())

    async def beacon_loop(self):
        """Envía 'DISCOVERY:Nombre' cada 3 segundos"""
        print("--- 📡 Radar Activo ---")
        
        # Socket independiente para enviar Broadcast Raw
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        # Atamos a la IP local para salir por la interfaz correcta
        try:
            sock.bind((self.my_ip, 0))
        except: pass

        msg = f"DISCOVERY:{self.name}".encode('utf-8')

        while True:
            try:
                sock.sendto(msg, (self.broadcast_addr, PORT))
            except Exception: pass
            
            await asyncio.sleep(3)

    def on_packet(self, packet, addr):
        ip = addr[0]
        if ip == self.my_ip: return 

        # --- CASO 1: Discovery (Texto Plano) ---
        if packet.msg_type == MSG_DISCOVERY:
            nombre_compañero = packet.payload # Viene del decode en protocol.py
            
            # Si no lo tenemos en la lista, lo añadimos
            if ip not in [p['ip'] for p in self.peers.values()]:
                 pid = self.peer_counter
                 self.peers[pid] = {'ip': ip, 'port': PORT, 'name': nombre_compañero}
                 self.peer_counter += 1
                 print(f"\n🔭 ¡COMPAÑERO ENCONTRADO! [{pid}] {nombre_compañero} ({ip})")
                 print("Comando > ", end="", flush=True)
            return

        # --- CASO 2: Handshake (Binario) ---
        if packet.msg_type == MSG_HELLO:
            if ip not in self.sessions:
                print(f"\n[!] Solicitud de conexión de {ip}")
                session = SessionCrypto(self.key_manager.static_private)
                self.sessions[ip] = session
                try:
                    session.perform_handshake(packet.payload, is_initiator=True)
                    # Respondemos una sola vez
                    my_key = session.get_ephemeral_public_bytes()
                    self.protocol.send_packet(ip, PORT, MSG_HELLO, 0, my_key)
                except: pass
            else:
                # Ya somos iniciadores, solo procesamos la respuesta
                try:
                    self.sessions[ip].perform_handshake(packet.payload, is_initiator=True)
                    if self.target_ip != ip:
                        self.target_ip = ip
                        print(f"\n✅ CONECTADO CON {ip}")
                        print("Tú > ", end="", flush=True)
                except: pass

        # --- CASO 3: Datos (Chat) ---
        elif packet.msg_type == MSG_DATA:
            if ip in self.sessions:
                try:
                    msg = self.sessions[ip].decrypt(packet.payload)
                    name = ip
                    for p in self.peers.values():
                        if p['ip'] == ip: name = p['name']
                    
                    sys.stdout.write("\r\033[K")
                    print(f"[{name}]: {msg}")
                    print("Tú > ", end="", flush=True)
                except: 
                    print("\n💀 Error desencriptando (clave incorrecta).")
            else:
                print(f"\n⚠️ Mensaje de {ip} sin sesión. Intentando reconectar...")
                self.connect_manual(ip)

    def connect_manual(self, ip_target):
        print(f"--> Conectando a {ip_target}...")
        session = SessionCrypto(self.key_manager.static_private)
        self.sessions[ip_target] = session
        my_key = session.get_ephemeral_public_bytes()
        # Enviar varias veces por si UDP falla
        for _ in range(3):
            self.protocol.send_packet(ip_target, PORT, MSG_HELLO, 0, my_key)
        self.target_ip = ip_target

    def send_chat(self, text):
        if self.target_ip and self.target_ip in self.sessions:
            try:
                enc = self.sessions[self.target_ip].encrypt(text)
                self.protocol.send_packet(self.target_ip, PORT, MSG_DATA, 1, enc)
            except: pass

async def main():
    if len(sys.argv) > 1:
        name = sys.argv[1]
    else:
        name = input("Introduce tu nombre: ")
    
    client = ChatClient(name)
    await client.start()

    # Input Thread no bloqueante
    input_queue = queue.Queue()
    def kbd():
        while True:
            try:
                l = sys.stdin.readline()
                if l: input_queue.put(l.strip())
            except: break
    threading.Thread(target=kbd, daemon=True).start()

    print("\n--- SISTEMA LISTO ---")
    print("Comando > ", end="", flush=True)

    while True:
        while not input_queue.empty():
            msg = input_queue.get_nowait()
            if msg == "/quit": return
            
            if msg.startswith("/connect"):
                parts = msg.split()
                if len(parts) > 1:
                    target = parts[1]
                    if '.' in target: 
                        client.connect_manual(target)
                    elif target.isdigit() and int(target) in client.peers:
                        client.connect_manual(client.peers[int(target)]['ip'])
            
            elif msg == "/list":
                 print("Usuarios detectados:")
                 for pid, d in client.peers.items():
                     print(f"[{pid}] {d['name']} - {d['ip']}")
                 print("Comando > ", end="", flush=True)
            else:
                client.send_chat(msg)
                print("Tú > ", end="", flush=True)
        
        await asyncio.sleep(0.1)

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt: pass
