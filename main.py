import asyncio
import logging
import sys
import socket

# Importamos nuestros módulos
from discovery import DiscoveryManager
from crypto import KeyManager, SessionCrypto
from protocol import ChatProtocol, Packet, MSG_HELLO, MSG_DATA

# Configuración
PORT = 8888 

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
# Reducimos el ruido del log para que no moleste en el menú
logging.getLogger("Discovery").setLevel(logging.WARNING)
logging.getLogger("Protocol").setLevel(logging.WARNING)
logger = logging.getLogger("Main")

class ChatClient:
    def __init__(self, display_name):
        self.display_name = display_name
        self.loop = asyncio.get_running_loop()
        
        # Criptografía
        self.key_manager = KeyManager(f"{display_name}_identity.json")
        
        # Estado del chat
        self.sessions = {}        # {ip: SessionCrypto} (Sesiones activas/handshake hecho)
        self.discovered_peers = {} # {ip: {'name': str, 'port': int}} (Lista de gente vista en red)
        self.active_chat_ip = None # IP del usuario con el que hablamos AHORA
        
        # Red y Discovery
        self.protocol = ChatProtocol(self.on_packet_received)
        self.transport = None
        self.discovery = DiscoveryManager(display_name, self.on_peer_update)

    async def start(self):
        print(f"--- CLIENTE INICIADO: {self.display_name} ---")
        
        self.transport, _ = await self.loop.create_datagram_endpoint(
            lambda: self.protocol,
            local_addr=('0.0.0.0', PORT)
        )
        await self.discovery.start()

    async def stop(self):
        await self.discovery.stop()
        if self.transport:
            self.transport.close()

    def on_peer_update(self, action, name, info):
        # DEBUG: Imprimir TODO lo que llega sin filtros
        print(f"\n[DEBUG] Discovery evento: {action} -> {name}")
        
        if action == "ADD" and info:
            if not info.addresses: return
            ip = socket.inet_ntoa(info.addresses[0])
            
            print(f"[DEBUG] IP detectada: {ip}. Mi nombre: {self.display_name} vs Otro: {name}")

            # Aquí estaba el filtro silencioso
            if name.startswith(self.display_name): 
                print("[DEBUG] IGNORADO: Se llama igual que yo.")
                return

            self.discovered_peers[ip] = {'name': name, 'port': info.port}
            print(f"[EXITO] Añadido a la lista. Total peers: {len(self.discovered_peers)}")
            
            if self.active_chat_ip is None:
                print(f"\n[!] Nuevo usuario: {name}. Escribe /list.")
                print("Comando > ", end="", flush=True)

    # --- GESTIÓN DE CONEXIÓN (HANDSHAKE) ---
    def connect_to_peer(self, ip):
        """Inicia el handshake manual con una IP específica."""
        if ip not in self.discovered_peers:
            print("Error: Esa IP no está en la lista de descubiertos.")
            return

        target_info = self.discovered_peers[ip]
        print(f"--> Iniciando Handshake con {target_info['name']} ({ip})...")
        
        # Crear sesión
        session = SessionCrypto(self.key_manager.static_private)
        self.sessions[ip] = session
        
        # Enviar HELLO
        my_ephemeral = session.get_ephemeral_public_bytes()
        self.protocol.send_packet(ip, target_info['port'], MSG_HELLO, 0, my_ephemeral)
        
        # Establecer como chat activo
        self.active_chat_ip = ip
        print(f"--> Esperando respuesta... Ya puedes escribir, pero el mensaje se enviará tras completar el handshake.")

    def on_packet_received(self, packet, addr):
        ip, port = addr
        
        if packet.msg_type == MSG_HELLO:
            self.handle_handshake_packet(ip, packet)
        elif packet.msg_type == MSG_DATA:
            self.handle_data_packet(ip, packet)

    def handle_handshake_packet(self, ip, packet):
        peer_ephemeral = packet.payload
        
        # Si alguien nos habla y no tenemos sesión, la creamos (Responder)
        if ip not in self.sessions:
            # Intentamos adivinar el nombre si lo tenemos en discovery
            name = self.discovered_peers.get(ip, {}).get('name', 'Desconocido')
            print(f"\n[!] {name} ({ip}) quiere hablar contigo. Aceptando conexión...")
            
            session = SessionCrypto(self.key_manager.static_private)
            self.sessions[ip] = session
            
            # Respondemos con nuestra clave
            my_ephemeral = session.get_ephemeral_public_bytes()
            self.protocol.send_packet(ip, PORT, MSG_HELLO, 0, my_ephemeral)
        
        # Completar handshake
        try:
            self.sessions[ip].perform_handshake(peer_ephemeral, is_initiator=True)
            print(f"✅ CONEXIÓN SEGURA ESTABLECIDA CON {ip}")
            
            # Si no estábamos hablando con nadie, cambiamos el foco a este usuario
            if self.active_chat_ip is None:
                print(f"--> Entrando en chat con {ip}. Escribe para hablar.")
                self.active_chat_ip = ip
                print("Tú > ", end="", flush=True)
                
        except Exception as e:
            print(f"Error en handshake: {e}")

    # --- GESTIÓN DE MENSAJES (CHAT) ---
    def handle_data_packet(self, ip, packet):
        """Recibir mensaje."""
        if ip not in self.sessions: return
        
        try:
            plaintext = self.sessions[ip].decrypt(packet.payload)
            name = self.discovered_peers.get(ip, {}).get('name', ip)
            
            # Mostrar mensaje
            print(f"\n[{name}]: {plaintext}")
            
            # Restaurar el prompt
            if self.active_chat_ip:
                print("Tú > ", end="", flush=True)
            else:
                print("Comando > ", end="", flush=True)
                
        except Exception as e:
            print(f"Error desencriptando: {e}")

    def send_current_chat_message(self, message):
        """Enviar mensaje SOLO al usuario activo."""
        if not self.active_chat_ip:
            print("⚠ No estás conectado con nadie. Usa /list y /connect.")
            return

        if self.active_chat_ip not in self.sessions:
            print("⚠ El Handshake no ha terminado aún. Espera un segundo.")
            return

        try:
            session = self.sessions[self.active_chat_ip]
            encrypted = session.encrypt(message)
            # Enviar DATA
            # Asumimos puerto 8888 o el que tenga guardado discovery
            port = self.discovered_peers.get(self.active_chat_ip, {}).get('port', PORT)
            self.protocol.send_packet(self.active_chat_ip, port, MSG_DATA, 1, encrypted)
        except Exception as e:
            print(f"Error enviando: {e}")

# --- INTERFAZ DE COMANDOS ---
async def input_loop(client):
    """
    Bucle principal que gestiona la entrada del teclado.
    Tiene dos modos: 'MENÚ' y 'CHAT'.
    """
    loop = asyncio.get_event_loop()
    
    print("\n--- SISTEMA LISTO ---")
    print("Comandos disponibles:")
    print("  /list           -> Ver usuarios en la red")
    print("  /connect <INDICE> -> Conectar con un usuario")
    print("  /quit           -> Salir del programa")
    print("---------------------\n")

    while True:
        # El prompt cambia según si estamos en chat o en menú
        if client.active_chat_ip:
            prompt = "Tú > "
        else:
            prompt = "Comando > "
            
        print(prompt, end="", flush=True)
        
        # Lectura no bloqueante
        msg = await loop.run_in_executor(None, sys.stdin.readline)
        msg = msg.strip()
        
        if not msg: continue

        # --- COMANDOS GLOBALES ---
        if msg == "/quit":
            break
        
        # --- ESTADO: CHATEANDO ---
        if client.active_chat_ip:
            if msg == "/exit":
                print(f"Saliste del chat con {client.active_chat_ip}")
                client.active_chat_ip = None
            else:
                client.send_current_chat_message(msg)
        
        # --- ESTADO: MENÚ ---
        else:
            if msg == "/list":
                print("\n--- USUARIOS DISPONIBLES ---")
                peers = list(client.discovered_peers.values())
                ip_list = list(client.discovered_peers.keys())
                
                if not peers:
                    print(" (Nadie encontrado aún. Asegúrate que Discovery funciona)")
                else:
                    for idx, p in enumerate(peers):
                        # Mostramos: [0] Alice (192.168.1.35)
                        print(f" [{idx}] {p['name']} ({ip_list[idx]})")
                print("----------------------------")

            elif msg.startswith("/connect"):
                try:
                    # Parsear el índice: /connect 0
                    parts = msg.split(" ")
                    if len(parts) < 2:
                        print("Uso: /connect <NUMERO_DE_LISTA>")
                        continue
                        
                    idx = int(parts[1])
                    ip_list = list(client.discovered_peers.keys())
                    
                    if 0 <= idx < len(ip_list):
                        target_ip = ip_list[idx]
                        client.connect_to_peer(target_ip)
                    else:
                        print("Número inválido.")
                except ValueError:
                    print("Introduce un número válido.")
            else:
                print("Comando no reconocido. Usa /list o /connect")

async def main():
    if len(sys.argv) > 1:
        name = sys.argv[1]
    else:
        name = input("Tu nombre de usuario: ")

    client = ChatClient(name)
    try:
        await client.start()
        await input_loop(client)
    finally:
        await client.stop()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
