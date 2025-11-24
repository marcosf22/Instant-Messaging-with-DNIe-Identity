import asyncio
import os
import sys
import socket
import threading
import queue
import traceback

# Módulos de cripto y protocolo (asegúrate de que crypto.py y protocol.py siguen ahí)
from crypto import KeyManager, SessionCrypto
from protocol import ChatProtocol, MSG_HELLO, MSG_DATA

# Configuración
PORT = 8888 

def get_local_ip():
    """
    Truco maestro: Conectamos un socket UDP a Google (8.8.8.8).
    No se envían datos, pero el Sistema Operativo nos dice automáticamente
    qué interfaz e IP local está usando para salir.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # No te preocupes, esto no conecta realmente ni gasta datos
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
        
        # 1. OBTENER IP LOCAL (WiFi/Ethernet)
        self.my_ip = get_local_ip()
        
        # 2. CALCULAR DIRECCIÓN DE BROADCAST
        # Asumimos una red doméstica estándar (/24).
        # Si tu IP es 192.168.1.33 -> Broadcast es 192.168.1.255
        try:
            parts = self.my_ip.split('.')
            self.broadcast_addr = f"{parts[0]}.{parts[1]}.{parts[2]}.255"
        except:
            self.broadcast_addr = "255.255.255.255"

        print(f"--> Tu IP Local: {self.my_ip}")
        print(f"--> Objetivo Broadcast: {self.broadcast_addr}")

        try:
            self.key_manager = KeyManager(f"{name}_identity")
        except: sys.exit(1)

        self.sessions = {}        
        self.peers = {}           
        self.peer_counter = 0     
        self.target_ip = None     
        
        self.protocol = ChatProtocol(self.on_packet)
        self.transport = None

    async def start(self):
        print(f"--- INICIANDO EN PUERTO {PORT} ---")
        
        # Escuchar en 0.0.0.0 permite recibir de cualquiera en la WiFi
        self.transport, _ = await self.loop.create_datagram_endpoint(
            lambda: self.protocol, 
            local_addr=("0.0.0.0", PORT),
            allow_broadcast=True
        )
        
        # Iniciamos el radar de descubrimiento
        self.loop.create_task(self.beacon_loop())

    async def beacon_loop(self):
        """Envía una señal cada 3 segundos a toda la WiFi"""
        print("--- 📡 Radar Activo (Buscando en LAN) ---")
        
        # Socket especial para enviar Broadcast
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        # Atamos a nuestra IP local para asegurar que sale por la interfaz correcta
        try:
            sock.bind((self.my_ip, 0))
        except: pass

        msg = f"DISCOVERY:{self.name}".encode()

        while True:
            try:
                # Enviar a la dirección de broadcast calculada (ej: 192.168.1.255)
                sock.sendto(msg, (self.broadcast_addr, PORT))
            except Exception: pass
            
            await asyncio.sleep(3)

    def on_packet(self, packet, addr):
        ip = addr[0]
        if ip == self.my_ip: return 

        # --- DETECCIÓN DE COMPAÑEROS (DISCOVERY) ---
        # Si recibimos algo de alguien nuevo, lo apuntamos
        if ip not in [p['ip'] for p in self.peers.values()]:
             pid = self.peer_counter
             self.peers[pid] = {'ip': ip, 'port': PORT, 'name': f"Usuario_{ip.split('.')[-1]}"}
             self.peer_counter += 1
             print(f"\n🔭 ¡NUEVO VECINO! [{pid}] IP: {ip}")
             print("Comando > ", end="", flush=True)

        # --- LÓGICA DE MENSAJES ---
        if packet.msg_type == MSG_HELLO:
            # Lógica corregida anti-bucle
            if ip not in self.sessions:
                print(f"\n[!] Conexión entrante de {ip}")
                session = SessionCrypto(self.key_manager.static_private)
                self.sessions[ip] = session
                try:
                    session.perform_handshake(packet.payload, is_initiator=True)
                    # Respondemos una sola vez
                    print(f"    -> Respondiendo saludo...")
                    my_key = session.get_ephemeral_public_bytes()
                    self.protocol.send_packet(ip, PORT, MSG_HELLO, 0, my_key)
                except: pass
            else:
                # Si ya tenemos sesión, solo procesamos (somos el iniciador recibiendo respuesta)
                try:
                    self.sessions[ip].perform_handshake(packet.payload, is_initiator=True)
                    if self.target_ip != ip:
                        self.target_ip = ip
                        print(f"\n✅ CONEXIÓN LOCAL ESTABLECIDA CON {ip}")
                        print("Tú > ", end="", flush=True)
                except: pass

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
                    print("\n💀 Error desencriptando.")
            else:
                # Recuperación automática si perdimos el handshake
                print(f"\n⚠️ Sesión perdida con {ip}. Reconectando...")
                self.connect_manual(ip)

    def connect_manual(self, ip_target):
        print(f"--> Conectando a {ip_target}...")
        session = SessionCrypto(self.key_manager.static_private)
        self.sessions[ip_target] = session
        my_key = session.get_ephemeral_public_bytes()
        # En WiFi UDP es más fiable, enviamos 3 veces rápido
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
    name = sys.argv[1] if len(sys.argv) > 1 else input("Tu nombre: ")
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

    print("\n--- CHAT LAN LISTO ---")
    print("Comando > ", end="", flush=True)

    while True:
        while not input_queue.empty():
            msg = input_queue.get_nowait()
            if msg == "/quit": return
            
            if msg.startswith("/connect"):
                parts = msg.split()
                if len(parts) > 1:
                    target = parts[1]
                    # Soporte para conectar por ID o IP
                    if '.' in target: client.connect_manual(target)
                    elif target.isdigit() and int(target) in client.peers:
                        client.connect_manual(client.peers[int(target)]['ip'])
            
            elif msg == "/list":
                 for pid, d in client.peers.items():
                     print(f"[{pid}] {d['ip']}")
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
