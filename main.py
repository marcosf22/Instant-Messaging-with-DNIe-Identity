import asyncio
import logging
import sys
import socket
import threading

# Importamos nuestros módulos
from discovery import DiscoveryManager
from crypto import KeyManager, SessionCrypto
from protocol import ChatProtocol, Packet, MSG_HELLO, MSG_DATA

# Configuración
PORT = 8888 

# Configuración de logs (Menos ruido para ver mejor el menú)
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logging.getLogger("Discovery").setLevel(logging.WARNING)
logging.getLogger("Protocol").setLevel(logging.WARNING)
logger = logging.getLogger("Main")

class ChatClient:
    def __init__(self, display_name):
        self.display_name = display_name
        self.loop = asyncio.get_running_loop()
        
        # Criptografía
        self.key_manager = KeyManager(f"{display_name}_identity.json")
        
        # Estado
        self.sessions = {}        
        self.discovered_peers = {} # {ip: {'name': str, 'port': int}}
        self.active_chat_ip = None 
        self.input_queue = asyncio.Queue() # Cola para recibir texto del teclado
        
        # Red y Discovery
        self.protocol = ChatProtocol(self.on_packet_received)
        self.transport = None
        self.discovery = DiscoveryManager(display_name, self.on_peer_update)

    async def start(self):
        print(f"--- CLIENTE INICIADO: {self.display_name} ---")
        print(f"--- Escuchando en puerto {PORT} ---")
        
        self.transport, _ = await self.loop.create_datagram_endpoint(
            lambda: self.protocol,
            local_addr=('0.0.0.0', PORT)
        )
        await self.discovery.start()
        
        # Arrancar el hilo que escucha el teclado
        threading.Thread(target=self._keyboard_listener, daemon=True).start()

    def _keyboard_listener(self):
        """Hilo separado que lee del teclado y lo mete en la cola asíncrona."""
        while True:
            try:
                msg = sys.stdin.readline()
                if msg:
                    # Usamos call_soon_threadsafe para meter datos en el loop principal
                    self.loop.call_soon_threadsafe(self.input_queue.put_nowait, msg.strip())
            except:
                break

    async def stop(self):
        await self.discovery.stop()
        if self.transport:
            self.transport.close()

    # --- DISCOVERY ---
    def on_peer_update(self, action, name, info):
        if action == "ADD" and info:
            if not info.addresses: return
            ip = socket.inet_ntoa(info.addresses[0])
            
            # Filtro de identidad
            if name == self.display_name or name.startswith(self.display_name):
                return

            # Guardar peer
            self.discovered_peers[ip] = {'name': name, 'port': info.port}
            
            # Avisar solo si estamos en el menú principal
            if self.active_chat_ip is None:
                # Borramos línea actual para que el aviso no rompa el prompt
                sys.stdout.write("\r\033[K") 
                print(f"[!] NUEVO USUARIO: {name} ({ip}). Usa /list para ver.")
                sys.stdout.write("Comando > ")
                sys.stdout.flush()

    # --- CONEXIÓN ---
    def connect_to_peer(self, ip):
        if ip not in self.discovered_peers:
            print("Error: IP desconocida.")
            return

        target_info = self.discovered_peers[ip]
        print(f"--> Conectando con {target_info['name']}...")
        
        session = SessionCrypto(self.key_manager.static_private)
        self.sessions[ip] = session
        
        # Enviar HELLO
        my_ephemeral = session.get_ephemeral_public_bytes()
        self.protocol.send_packet(ip, target_info['port'], MSG_HELLO, 0, my_ephemeral)
        
        self.active_chat_ip = ip
        print(f"--> Handshake enviado. Esperando respuesta...")

    # --- RED (RECEPCIÓN) ---
    def on_packet_received(self, packet, addr):
        ip, port = addr
        
        if packet.msg_type == MSG_HELLO:
            # ALGUIEN NOS SALUDA (HANDSHAKE)
            peer_ephemeral = packet.payload
            
            # Si es nuevo, creamos sesión
            if ip not in self.sessions:
                name = self.discovered_peers.get(ip, {}).get('name', 'Desconocido')
                sys.stdout.write("\r\033[K")
                print(f"\n[!] Solicitud de chat de {name} ({ip}). Aceptando...")
                
                session = SessionCrypto(self.key_manager.static_private)
                self.sessions[ip] = session
                
                # Responder con nuestra clave
                my_ephemeral = session.get_ephemeral_public_bytes()
                self.protocol.send_packet(ip, PORT, MSG_HELLO, 0, my_ephemeral)
            
            # Completar handshake
            try:
                self.sessions[ip].perform_handshake(peer_ephemeral, is_initiator=True)
                sys.stdout.write("\r\033[K")
                print(f"✅ CONEXIÓN SEGURA CON {ip}")
                
                if self.active_chat_ip is None:
                    self.active_chat_ip = ip
                    print(f"--> Chat activo con {ip}. ¡Escribe!")
                    print("Tú > ", end="", flush=True)
                else:
                    print("Comando > ", end="", flush=True)
            except Exception as e:
                print(f"Error Handshake: {e}")

        elif packet.msg_type == MSG_DATA:
            # MENSAJE DE TEXTO
            if ip in self.sessions:
                try:
                    msg = self.sessions[ip].decrypt(packet.payload)
                    name = self.discovered_peers.get(ip, {}).get('name', ip)
                    sys.stdout.write("\r\033[K")
                    print(f"\n[{name}]: {msg}")
                    if self.active_chat_ip:
                        print("Tú > ", end="", flush=True)
                    else:
                        print("Comando > ", end="", flush=True)
                except:
                    pass

    # --- RED (ENVÍO) ---
    def send_msg(self, text):
        if not self.active_chat_ip: return
        try:
            session = self.sessions[self.active_chat_ip]
            encrypted = session.encrypt(text)
            # Usamos el puerto guardado o el por defecto
            port = self.discovered_peers.get(self.active_chat_ip, {}).get('port', PORT)
            self.protocol.send_packet(self.active_chat_ip, port, MSG_DATA, 1, encrypted)
        except Exception as e:
            print(f"Error enviando: {e}")

async def main():
    # NOMBRE DE USUARIO
    if len(sys.argv) > 1:
        name = sys.argv[1]
    else:
        # Usar input normal aquí está bien porque aún no arrancamos el loop
        name = input("Tu nombre: ")

    client = ChatClient(name)
    await client.start()

    print("\n--- CHAT SEGURO LISTO ---")
    print(" /list              -> Ver usuarios")
    print(" /connect <Nº>      -> Hablar con alguien")
    print(" /exit              -> Salir del chat actual")
    print(" /quit              -> Cerrar programa")
    print("-------------------------\n")

    # BUCLE PRINCIPAL DE LA INTERFAZ
    print("Comando > ", end="", flush=True)
    
    while True:
        # Esperamos a que el hilo del teclado meta algo en la cola
        msg = await client.input_queue.get()
        
        if msg == "/quit":
            break
        
        # MODO CHAT
        if client.active_chat_ip:
            if msg == "/exit":
                print(f"Desconectado de {client.active_chat_ip}")
                client.active_chat_ip = None
                print("Comando > ", end="", flush=True)
            else:
                client.send_msg(msg)
                print("Tú > ", end="", flush=True)
        
        # MODO MENÚ
        else:
            if msg == "/list":
                peers = list(client.discovered_peers.values())
                ips = list(client.discovered_peers.keys())
                print("\n--- USUARIOS ---")
                for i, p in enumerate(peers):
                    print(f" [{i}] {p['name']} ({ips[i]})")
                print("----------------")
                print("Comando > ", end="", flush=True)
            
            elif msg.startswith("/connect"):
                parts = msg.split()
                if len(parts) > 1 and parts[1].isdigit():
                    idx = int(parts[1])
                    ips = list(client.discovered_peers.keys())
                    if 0 <= idx < len(ips):
                        client.connect_to_peer(ips[idx])
                    else:
                        print("Índice incorrecto.")
                        print("Comando > ", end="", flush=True)
                else:
                    print("Uso: /connect <NUMERO>")
                    print("Comando > ", end="", flush=True)
            else:
                print("Comando desconocido.")
                print("Comando > ", end="", flush=True)

    await client.stop()

if __name__ == "__main__":
    # FIX PARA WINDOWS (La clave del éxito)
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
