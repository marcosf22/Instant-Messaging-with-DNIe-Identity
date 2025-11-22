import asyncio
import logging
import sys
import socket
import threading
import queue

# Importamos tus módulos existentes
from discovery import DiscoveryManager
from crypto import KeyManager, SessionCrypto
from protocol import ChatProtocol, MSG_HELLO, MSG_DATA

# Configuración
PORT = 8888 

# Configurar logs para ver claramente qué pasa
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger("Main")

# Cola para pasar mensajes del teclado al bucle asíncrono
input_queue = queue.Queue()

def get_lan_ip():
    """Detecta la IP de la red local para evitar usar localhost."""
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
    def __init__(self, display_name):
        self.display_name = display_name
        self.loop = asyncio.get_running_loop()
        
        self.key_manager = KeyManager(f"{display_name}_identity.json")
        self.sessions = {}        
        self.discovered_peers = {} # Aquí guardaremos la lista
        self.active_chat_ip = None 
        
        # Protocolo y Discovery
        self.protocol = ChatProtocol(self.on_packet_received)
        self.transport = None
        self.discovery = DiscoveryManager(display_name, self.on_peer_update)

    async def start(self):
        # 1. Asegurar que escuchamos en la IP correcta
        my_ip = get_lan_ip()
        print(f"--- INICIANDO EN IP: {my_ip} (PUERTO {PORT}) ---")
        
        try:
            self.transport, _ = await self.loop.create_datagram_endpoint(
                lambda: self.protocol,
                local_addr=('0.0.0.0', PORT)
            )
        except OSError as e:
            print(f"ERROR: El puerto {PORT} está ocupado. Cierra otros scripts de Python.")
            sys.exit(1)

        # 2. Iniciar Discovery
        print("--- BUSCANDO USUARIOS EN LA RED... ---")
        await self.discovery.start()

    async def stop(self):
        await self.discovery.stop()
        if self.transport: self.transport.close()

    # --- PARTE CLAVE: LA LISTA DE USUARIOS ---
    def on_peer_update(self, action, name, info):
        """Este método se ejecuta AUTOMÁTICAMENTE cuando discovery ve a alguien."""
        if action == "ADD" and info:
            if not info.addresses: return
            ip = socket.inet_ntoa(info.addresses[0])
            
            # Evitar añadirse a uno mismo
            if name == self.display_name: return

            # Si es nuevo, lo anunciamos y guardamos
            if ip not in self.discovered_peers:
                self.discovered_peers[ip] = {'name': name, 'port': info.port}
                
                # IMPRIMIR AVISO VISIBLE
                print(f"\n\n[★] ¡USUARIO ENCONTRADO!")
                print(f"    Nombre: {name}")
                print(f"    IP: {ip}")
                print("    (Escribe /connect para hablar con él)")
                print("Comando > ", end="", flush=True)

        elif action == "REMOVE":
            # Limpieza si se van
            ips_to_remove = [ip for ip, data in self.discovered_peers.items() if data['name'] == name]
            for ip in ips_to_remove:
                del self.discovered_peers[ip]
                print(f"\n[!] Usuario desconectado: {name}")

    # --- CONEXIÓN Y CHAT ---
    def connect_to_peer_by_index(self, index):
        try:
            ips = list(self.discovered_peers.keys())
            target_ip = ips[index]
            peer = self.discovered_peers[target_ip]
            
            print(f"--> Conectando con {peer['name']} ({target_ip})...")
            
            # Iniciar sesión criptográfica
            session = SessionCrypto(self.key_manager.static_private)
            self.sessions[target_ip] = session
            
            # Enviar Handshake (HELLO)
            my_key = session.get_ephemeral_public_bytes()
            self.protocol.send_packet(target_ip, peer['port'], MSG_HELLO, 0, my_key)
            
            self.active_chat_ip = target_ip
            print("--> Handshake enviado. Esperando respuesta...")
            
        except IndexError:
            print("Error: Número de usuario incorrecto.")

    def on_packet_received(self, packet, addr):
        ip, port = addr
        
        if packet.msg_type == MSG_HELLO:
            # Recibimos solicitud de chat
            if ip not in self.sessions:
                print(f"\n[!] Solicitud de chat recibida de {ip}. Aceptando...")
                session = SessionCrypto(self.key_manager.static_private)
                self.sessions[ip] = session
                # Responder con nuestra clave
                my_key = session.get_ephemeral_public_bytes()
                self.protocol.send_packet(ip, PORT, MSG_HELLO, 0, my_key)
            
            try:
                self.sessions[ip].perform_handshake(packet.payload, is_initiator=True)
                print(f"✅ ¡CONEXIÓN SEGURA LISTA CON {ip}!")
                if not self.active_chat_ip:
                    self.active_chat_ip = ip
                    print("--> Ya puedes escribir mensajes.")
            except Exception as e:
                print(f"Error Handshake: {e}")

        elif packet.msg_type == MSG_DATA:
            if ip in self.sessions:
                try:
                    msg = self.sessions[ip].decrypt(packet.payload)
                    name = self.discovered_peers.get(ip, {}).get('name', ip)
                    print(f"\n[{name}]: {msg}")
                    print("Tú > ", end="", flush=True)
                except: pass

    def send_msg(self, text):
        if self.active_chat_ip and self.active_chat_ip in self.sessions:
            session = self.sessions[self.active_chat_ip]
            encrypted = session.encrypt(text)
            port = self.discovered_peers[self.active_chat_ip]['port']
            self.protocol.send_packet(self.active_chat_ip, port, MSG_DATA, 1, encrypted)
        else:
            print("Error: No estás conectado con nadie.")

# --- HILO PARA LEER EL TECLADO SIN BLOQUEAR ---
def keyboard_thread_loop(loop):
    """Lee del teclado y manda la info al hilo principal."""
    while True:
        try:
            msg = sys.stdin.readline()
            if msg:
                # Enviamos el texto al bucle asíncrono principal de forma segura
                asyncio.run_coroutine_threadsafe(handle_user_input(msg.strip()), loop)
        except:
            break

async def handle_user_input(msg):
    """Procesa los comandos en el hilo principal."""
    global client
    
    if msg == "/quit":
        await client.stop()
        asyncio.get_event_loop().stop()
        
    elif msg == "/list":
        print("\n--- USUARIOS DISPONIBLES ---")
        if not client.discovered_peers:
            print("(Lista vacía. Esperando discovery...)")
        else:
            ips = list(client.discovered_peers.keys())
            for i, ip in enumerate(ips):
                peer = client.discovered_peers[ip]
                print(f" [{i}] {peer['name']} - IP: {ip}")
        print("----------------------------")
        print("Comando > ", end="", flush=True)

    elif msg.startswith("/connect"):
        # Intentar conectar por número (ej: /connect 0)
        parts = msg.split()
        if len(parts) > 1 and parts[1].isdigit():
            client.connect_to_peer_by_index(int(parts[1]))
        else:
            print("Uso: /connect <NUMERO DE LISTA>")
            print("Ejemplo: /connect 0")

    elif client.active_chat_ip:
        client.send_msg(msg)
        print("Tú > ", end="", flush=True)
    else:
        print("Comando desconocido o no estás conectado. Usa /list")
        print("Comando > ", end="", flush=True)

# --- ARRANQUE ---
client = None

async def main():
    global client
    if len(sys.argv) > 1:
        name = sys.argv[1]
    else:
        name = input("Tu nombre de usuario: ")

    client = ChatClient(name)
    await client.start()
    
    print("\n--- SISTEMA LISTO ---")
    print("Espera a que aparezcan usuarios automáticamente.")
    print("Comandos: /list, /connect <n>, /quit")
    print("Comando > ", end="", flush=True)

    # Ejecutamos un "while True" asíncrono para mantener el programa vivo
    # El input se maneja por el hilo separado
    while True:
        await asyncio.sleep(1)

if __name__ == "__main__":
    # FIX WINDOWS
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Arrancar el hilo del teclado
    t = threading.Thread(target=keyboard_thread_loop, args=(loop,), daemon=True)
    t.start()

    try:
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        pass
