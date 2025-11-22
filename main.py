import asyncio
import sys
import socket
import threading
import queue
import traceback # Importante para ver el error real

# Tus módulos
from discovery import DiscoveryManager
from crypto import KeyManager, SessionCrypto
from protocol import ChatProtocol, MSG_HELLO, MSG_DATA

# Configuración
PORT = 8888 

def get_lan_ip():
    # 1. Detectar sistema y buscar el programa zerotier-cli
    sistema = platform.system()
    zt_binary = "zerotier-cli" # Default Linux/Mac
    
    if sistema == "Windows":
        # Rutas comunes en Windows
        rutas_posibles = [
            r"C:\Program Files (x86)\ZeroTier\One\zerotier-cli.bat",
            r"C:\Program Files\ZeroTier\One\zerotier-cli.bat"
        ]
        zt_binary = None
        for ruta in rutas_posibles:
            if os.path.exists(ruta):
                zt_binary = ruta
                break
        
        if not zt_binary:
            print("\n[ERROR] No se encontró ZeroTier en las rutas estándar.")
            return

    # 2. Ejecutar comando para pedir la info
    try:
        # Usamos -j para obtener JSON limpio
        resultado = subprocess.check_output([zt_binary, "-j", "listnetworks"], text=True)
        datos = json.loads(resultado)
    except Exception as e:
        print(f"\n[ERROR] No se pudo ejecutar ZeroTier: {e}")
        print("Intenta ejecutar este script como Administrador (o con sudo).")
        return

    # 3. Filtrar y mostrar solo lo importante
    redes_encontradas = 0
    
    for red in datos:
        nombre_red = red.get('name', 'Sin Nombre')
        net_id = red.get('nwid')
        estado = red.get('status')
        ips = red.get('assignedAddresses')

        if estado == 'OK' and ips:
            redes_encontradas += 1
            # Limpiamos la IP (quitamos la máscara /24, etc)
            ip_limpia = ips[0].split('/')[0]
    return ip_limpia

class ChatClient:
    def __init__(self, name):
        self.name = name
        self.loop = asyncio.get_running_loop()
        self.my_ip = get_lan_ip()
        
        print("--> Cargando identidad y DNIe...")
        try:
            self.key_manager = KeyManager(f"{name}_identity")
        except Exception as e:
            print(f"\n❌ ERROR CRÍTICO CARGANDO DNIe/CRIPTOGRAFÍA: {e}")
            print("Revisa la ruta de la DLL en crypto.py")
            sys.exit(1)

        self.sessions = {}        
        self.peers = {}           
        self.peer_counter = 0     
        self.target_ip = None     
        
        self.protocol = ChatProtocol(self.on_packet)
        self.discovery = DiscoveryManager(name, self.on_discovery)
        self.transport = None

    async def start(self):
        print(f"--- INICIANDO EN {self.my_ip}:{PORT} ---")
        
        # BIND A LA IP ESPECÍFICA
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
        
        # Aquí es donde suele fallar si el DNIe no va bien
        session = SessionCrypto(self.key_manager.static_private)
        self.sessions[ip] = session
        my_key = session.get_ephemeral_public_bytes()
        
        # Enviamos 3 veces por si acaso (UDP es inseguro)
        for _ in range(3):
            self.protocol.send_packet(ip, PORT, MSG_HELLO, 0, my_key)
        
        self.target_ip = ip
        print("--> Handshake enviado (x3). Esperando...")

    def on_packet(self, packet, addr):
        ip = addr[0] 
        
        if packet.msg_type == MSG_HELLO:
            is_new = ip not in self.sessions
            
            if is_new:
                print(f"\n[!] Handshake recibido de {ip}.")
                session = SessionCrypto(self.key_manager.static_private)
                self.sessions[ip] = session
            
            # RESPONDEMOS SIEMPRE (ACK)
            session = self.sessions[ip]
            my_key = session.get_ephemeral_public_bytes()
            self.protocol.send_packet(ip, PORT, MSG_HELLO, 0, my_key)

            try:
                self.sessions[ip].perform_handshake(packet.payload, is_initiator=True)
                
                if is_new or self.target_ip != ip:
                    print(f"✅ CONEXIÓN ESTABLECIDA CON {ip}")
                    if self.target_ip is None: self.target_ip = ip
                    print("Tú > ", end="", flush=True)
                    
            except Exception as e:
                pass 

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
            print(f"Error envio: {e}")

async def main():
    name = sys.argv[1] if len(sys.argv) > 1 else input("Tu nombre: ")
    
    try:
        client = ChatClient(name)
        await client.start()
    except Exception as e:
        print(f"Error iniciando cliente: {e}")
        return

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
                # BLOQUE DE DEBUG CORREGIDO
                try:
                    parts = msg.split()
                    if len(parts) < 2:
                        print("⚠ Falta el ID. Uso: /connect <número>")
                    else:
                        client.connect_by_id(int(parts[1]))
                except Exception as e:
                    print(f"\n❌ ERROR AL CONECTAR:")
                    print(f"Mensaje de error: {e}")
                    traceback.print_exc() # ESTO IMPRIMIRÁ EL DETALLE REAL
                    print("Comando > ", end="", flush=True)
            
            elif msg == "/list":
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
