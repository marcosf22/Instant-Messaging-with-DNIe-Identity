import asyncio
import sys
import socket
import threading
import queue

# Tus módulos (asegúrate de que se llaman así)
from discovery import DiscoveryManager
from crypto import KeyManager, SessionCrypto
from protocol import ChatProtocol, MSG_HELLO, MSG_DATA

# Configuración
PORT = 8888 

class ChatClient:
    def __init__(self, name):
        self.name = name
        self.loop = asyncio.get_running_loop()
        
        # Identidad y Cifrado
        self.key_manager = KeyManager(f"{name}_identity.json")
        self.sessions = {}        # Sesiones cifradas activas
        self.peers = {}           # Lista de usuarios encontrados {index: {ip, port, name}}
        self.peer_counter = 0     # Para asignar ID 0, 1, 2...
        self.target_ip = None     # A QUIÉN enviamos los mensajes
        
        # Red
        self.protocol = ChatProtocol(self.on_packet)
        self.discovery = DiscoveryManager(name, self.on_discovery)
        self.transport = None

    async def start(self):
        # Abrir puerto
        try:
            self.transport, _ = await self.loop.create_datagram_endpoint(
                lambda: self.protocol, local_addr=('0.0.0.0', PORT)
            )
        except Exception as e:
            print(f"Error abriendo puerto {PORT}: {e}")
            return

        # Iniciar Discovery
        print(f"--- Cliente '{self.name}' iniciado en puerto {PORT} ---")
        print("--- Buscando usuarios... (Espera a que aparezcan) ---")
        await self.discovery.start()

    # --- LÓGICA: DESCUBRIMIENTO ---
    def on_discovery(self, action, name, info):
        """Se ejecuta solo cuando Discovery encuentra a alguien."""
        if action == "ADD" and info and info.addresses:
            ip = socket.inet_ntoa(info.addresses[0])
            
            # Ignorarnos a nosotros mismos
            if name == self.name: return

            # Comprobar si ya lo tenemos por IP
            known = False
            for p in self.peers.values():
                if p['ip'] == ip: known = True
            
            if not known:
                # Añadir a la lista con un ID numérico simple
                pid = self.peer_counter
                self.peers[pid] = {'ip': ip, 'port': info.port, 'name': name}
                self.peer_counter += 1
                
                # AVISO VISIBLE
                print(f"\n[+] USUARIO ENCONTRADO: [{pid}] {name} ({ip})")
                # Si no estamos chateando, recordamos cómo conectar
                if self.target_ip is None:
                    print("--> Escribe '/connect <id>' para hablar con él.")
                    print("Comando > ", end="", flush=True)

    # --- LÓGICA: CONEXIÓN MANUAL ---
    def connect_by_id(self, pid):
        if pid not in self.peers:
            print(f"Error: No existe el usuario con ID {pid}")
            return

        peer = self.peers[pid]
        ip = peer['ip']
        print(f"--> Iniciando Handshake con {peer['name']} ({ip})...")
        
        # Crear sesión
        session = SessionCrypto(self.key_manager.static_private)
        self.sessions[ip] = session
        
        # Enviar HELLO
        my_key = session.get_ephemeral_public_bytes()
        self.protocol.send_packet(ip, peer['port'], MSG_HELLO, 0, my_key)
        
        # FIJAR OBJETIVO (A partir de ahora mandamos solo a él)
        self.target_ip = ip
        print("--> Handshake enviado. Esperando confirmación...")

    # --- LÓGICA: RED ---
    def on_packet(self, packet, addr):
        ip, port = addr
        
        # 1. HANDSHAKE
        if packet.msg_type == MSG_HELLO:
            if ip not in self.sessions:
                # Alguien nuevo nos habla
                session = SessionCrypto(self.key_manager.static_private)
                self.sessions[ip] = session
                my_key = session.get_ephemeral_public_bytes()
                self.protocol.send_packet(ip, PORT, MSG_HELLO, 0, my_key)
            
            try:
                self.sessions[ip].perform_handshake(packet.payload, is_initiator=True)
                print(f"\n✅ CONEXIÓN SEGURA LISTA CON {ip}")
                
                # Si no habíamos elegido a nadie, fijamos este automáticamente
                if self.target_ip is None:
                    self.target_ip = ip
                    print(f"--> Chat fijado con {ip}. ¡Escribe!")
                    print("Tú > ", end="", flush=True)
                elif self.target_ip == ip:
                    print("--> Ya puedes escribir.")
                    print("Tú > ", end="", flush=True)

            except Exception as e:
                print(f"Error Crypto: {e}")

        # 2. MENSAJE DE DATOS
        elif packet.msg_type == MSG_DATA:
            if ip in self.sessions:
                try:
                    msg = self.sessions[ip].decrypt(packet.payload)
                    # Buscar nombre para mostrarlo bonito
                    sender_name = ip
                    for p in self.peers.values():
                        if p['ip'] == ip: sender_name = p['name']
                    
                    print(f"\n[{sender_name}]: {msg}")
                    
                    # Volver a pintar el prompt
                    if self.target_ip:
                        print("Tú > ", end="", flush=True)
                    else:
                        print("Comando > ", end="", flush=True)
                except:
                    pass

    # --- LÓGICA: ENVIAR ---
    def send_chat(self, text):
        if not self.target_ip:
            print("⚠ Error: No has seleccionado a nadie. Usa /connect <id>")
            return
        
        if self.target_ip not in self.sessions:
            print("⚠ Error: Handshake no completado.")
            return

        try:
            # Cifrar y enviar solo al TARGET
            session = self.sessions[self.target_ip]
            encrypted = session.encrypt(text)
            
            # Buscamos el puerto destino
            dst_port = PORT
            for p in self.peers.values():
                if p['ip'] == self.target_ip: dst_port = p['port']

            self.protocol.send_packet(self.target_ip, dst_port, MSG_DATA, 1, encrypted)
        except Exception as e:
            print(f"Error enviando: {e}")

async def main():
    # Pedir nombre al arrancar
    name = sys.argv[1] if len(sys.argv) > 1 else input("Tu nombre de usuario: ")
    
    client = ChatClient(name)
    await client.start()

    # Cola para comunicar teclado -> asyncio
    input_queue = queue.Queue()

    # HILO DE TECLADO (Para no bloquear la red)
    def keyboard_listener():
        while True:
            try:
                # Esto bloquea el hilo, pero NO el programa principal
                line = sys.stdin.readline()
                if line: input_queue.put(line.strip())
            except: break
    
    threading.Thread(target=keyboard_listener, daemon=True).start()

    print("\n--- INSTRUCCIONES ---")
    print("1. Espera a ver '[+] USUARIO ENCONTRADO'")
    print("2. Escribe '/connect 0' (o el número que sea)")
    print("3. Escribe mensajes para chatear")
    print("---------------------")
    print("Comando > ", end="", flush=True)

    # BUCLE PRINCIPAL
    while True:
        try:
            # Procesar inputs del teclado si los hay
            while not input_queue.empty():
                msg = input_queue.get_nowait()
                
                if msg == "/quit":
                    print("Saliendo...")
                    return

                if msg.startswith("/connect"):
                    try:
                        pid = int(msg.split()[1])
                        client.connect_by_id(pid)
                    except:
                        print("Uso: /connect <número>")
                        print("Comando > ", end="", flush=True)
                
                elif msg == "/list":
                    print("\n--- USUARIOS ---")
                    for pid, data in client.peers.items():
                        print(f" [{pid}] {data['name']} - {data['ip']}")
                    if not client.peers: print("(Nadie encontrado aún)")
                    print("----------------")
                    print("Comando > ", end="", flush=True)

                else:
                    # Es un mensaje de chat normal
                    if client.target_ip:
                        client.send_chat(msg)
                        print("Tú > ", end="", flush=True)
                    else:
                        print("Comando desconocido o no conectado. Usa /connect <n>")
                        print("Comando > ", end="", flush=True)

            # Dejar respirar a la red
            await asyncio.sleep(0.1)
            
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
