import asyncio
import sys
import socket
import threading
import queue
import time

# Tus módulos
from discovery import DiscoveryManager
from crypto import KeyManager, SessionCrypto
from protocol import ChatProtocol, MSG_HELLO, MSG_DATA

# Configuración
PORT = 8888 

def get_lan_ip():
    """Obtiene la IP real de la red local (WiFi/Ethernet)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

class ChatClient:
    def __init__(self, name):
        self.name = name
        self.loop = asyncio.get_running_loop()
        self.my_ip = get_lan_ip()
        
        self.key_manager = KeyManager(f"{name}_identity.json")
        self.sessions = {}        
        self.peers = {}           
        self.peer_counter = 0     
        self.target_ip = None     
        
        self.protocol = ChatProtocol(self.on_packet)
        self.discovery = DiscoveryManager(name, self.on_discovery)
        self.transport = None

    async def start(self):
        print(f"--- INICIANDO EN {self.my_ip}:{PORT} ---")
        
        # CORRECCIÓN 1: BIND A LA IP ESPECÍFICA (NO 0.0.0.0)
        # Esto ayuda a que Windows no se confunda de tarjeta de red
        try:
            self.transport, _ = await self.loop.create_datagram_endpoint(
                lambda: self.protocol, local_addr=(self.my_ip, PORT)
            )
        except Exception as e:
            print(f"Error crítico puerto {PORT}: {e}")
            return

        print("--- Buscando usuarios... ---")
        await self.discovery.start()

    def on_discovery(self, action, name, info):
        if action == "ADD" and info and info.addresses:
            ip = socket.inet_ntoa(info.addresses[0])
            if name == self.name: return

            # Chequear duplicados
            for p in self.peers.values():
                if p['ip'] == ip: return
            
            pid = self.peer_counter
            # Guardamos SIEMPRE el puerto oficial (PORT), ignoramos el aleatorio
            self.peers[pid] = {'ip': ip, 'port': PORT, 'name': name}
            self.peer_counter += 1
            
            print(f"\n[+] USUARIO ENCONTRADO: [{pid}] {name} ({ip})")
            if self.target_ip is None:
                print("--> Escribe '/connect <id>' para empezar.")
                print("Comando > ", end="", flush=True)

    def connect_by_id(self, pid):
        if pid not in self.peers:
            print(f"Error ID {pid}")
            return

        peer = self.peers[pid]
        ip = peer['ip']
        print(f"--> Iniciando Handshake con {peer['name']} ({ip})...")
        
        session = SessionCrypto(self.key_manager.static_private)
        self.sessions[ip] = session
        my_key = session.get_ephemeral_public_bytes()
        
        # Enviamos 3 veces por si acaso (UDP es inseguro)
        for _ in range(3):
            self.protocol.send_packet(ip, PORT, MSG_HELLO, 0, my_key)
        
        self.target_ip = ip
        print("--> Handshake enviado (x3). Esperando...")

    def on_packet(self, packet, addr):
        # CORRECCIÓN 2: Ignoramos el puerto de origen (addr[1])
        # Asumimos que el otro SIEMPRE escucha en PORT (8888)
        ip = addr[0] 
        
        if packet.msg_type == MSG_HELLO:
            # Si no teníamos sesión o el handshake no estaba completo
            is_new = ip not in self.sessions
            
            if is_new:
                print(f"\n[!] Handshake recibido de {ip}.")
                session = SessionCrypto(self.key_manager.static_private)
                self.sessions[ip] = session
            
            # RESPONDEMOS SIEMPRE (ACK)
            # Para asegurar que el otro recibe nuestra clave aunque se pierda un paquete
            session = self.sessions[ip]
            my_key = session.get_ephemeral_public_bytes()
            self.protocol.send_packet(ip, PORT, MSG_HELLO, 0, my_key)

            try:
                # Procesamos la clave del otro
                self.sessions[ip].perform_handshake(packet.payload, is_initiator=True)
                
                # Solo avisamos si es la primera vez que completamos
                if is_new or self.target_ip != ip:
                    print(f"✅ CONEXIÓN ESTABLECIDA CON {ip}")
                    if self.target_ip is None: self.target_ip = ip
                    print("Tú > ", end="", flush=True)
                    
            except Exception as e:
                pass # Ignoramos errores de handshake repetidos

        elif packet.msg_type == MSG_DATA:
            if ip in self.sessions:
                try:
                    msg = self.sessions[ip].decrypt(packet.payload)
                    name = ip
                    for p in self.peers.values():
                        if p['ip'] == ip: name = p['name']
                    
                    # Borrar línea actual para que no se rompa el prompt
                    sys.stdout.write("\r\033[K")
                    print(f"[{name}]: {msg}")
                    print("Tú > ", end="", flush=True)
                except: pass

    def send_chat(self, text):
        if not self.target_ip: return
        if self.target_ip not in self.sessions:
            print("⚠ Esperando handshake...")
            return

        try:
            session = self.sessions[self.target_ip]
            encrypted = session.encrypt(text)
            self.protocol.send_packet(self.target_ip, PORT, MSG_DATA, 1, encrypted)
        except Exception as e:
            print(f"Error: {e}")

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

    print("\n--- SISTEMA LISTO ---")
    print("Comando > ", end="", flush=True)

    while True:
        while not input_queue.empty():
            msg = input_queue.get_nowait()
            if msg == "/quit": return

            if msg.startswith("/connect"):
                try:
                    client.connect_by_id(int(msg.split()[1]))
                except: print("Error comando")
            elif msg == "/list":
                 # Mostrar lista
                 for pid, d in client.peers.items():
                     print(f"[{pid}] {d['name']}")
                 print("Comando > ", end="", flush=True)
            else:
                if client.target_ip:
                    client.send_chat(msg)
                    print("Tú > ", end="", flush=True)
                else:
                    print("Usa /connect <id>")
                    print("Comando > ", end="", flush=True)
        
        await asyncio.sleep(0.1)

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt: pass
