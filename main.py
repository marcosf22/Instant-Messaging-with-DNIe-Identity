import asyncio
import logging
import sys
import os

# Importamos nuestros módulos
from discovery import DiscoveryManager
from crypto import KeyManager, SessionCrypto
from protocol import ChatProtocol, Packet, MSG_HELLO, MSG_DATA

# Configuración
# NOTA: El documento pide puerto 443. Para pruebas sin admin usamos 8888.
PORT = 8888 
# PORT = 443 # Descomentar esto para la versión final (requiere Admin/Sudo)

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("Main")

class ChatClient:
    def __init__(self, display_name):
        self.display_name = display_name
        self.loop = asyncio.get_running_loop()
        
        # 1. Criptografía: Cargar identidad (DNIe simulado)
        self.key_manager = KeyManager(f"{display_name}_identity.json")
        self.sessions = {} # Diccionario para guardar sesiones activas {ip: SessionCrypto}
        
        # 2. Protocolo: Preparar el transporte UDP
        self.protocol = ChatProtocol(self.on_packet_received)
        self.transport = None

        # 3. Discovery: Preparar el gestor mDNS
        self.discovery = DiscoveryManager(display_name, self.on_peer_update)

    async def start(self):
        """Arranca todos los servicios (Red + Discovery)."""
        print(f"--- INICIANDO CLIENTE: {self.display_name} ---")
        print(f"--- Escuchando en puerto {PORT} ---")

        # A. Iniciar servidor UDP
        self.transport, _ = await self.loop.create_datagram_endpoint(
            lambda: self.protocol,
            local_addr=('0.0.0.0', PORT)
        )

        # B. Iniciar Discovery
        await self.discovery.start()

    async def stop(self):
        await self.discovery.stop()
        if self.transport:
            self.transport.close()

    def on_peer_update(self, action, name, info):
        """Callback que salta cuando discovery encuentra a alguien."""
        if action == "ADD" and info:
            # Extraer IP y Puerto
            import socket
            ip = socket.inet_ntoa(info.addresses[0])
            port = info.port
            
            # Evitamos hablarnos a nosotros mismos (comprobando IP local)
            # En producción usaríamos UUID, aquí simplificamos.
            if name.startswith(self.display_name):
                return

            logger.info(f"Peer encontrado: {name} en {ip}:{port}")
            
            # Si no tenemos sesión con él, iniciamos Handshake
            if ip not in self.sessions:
                self.initiate_handshake(ip, port)

        elif action == "REMOVE":
            logger.info(f"Peer desconectado: {name}")

    def initiate_handshake(self, ip, port):
        """Paso 1: Crear sesión y enviar mi clave efímera (HELLO)."""
        logger.info(f"Iniciando handshake con {ip}...")
        
        # Crear nueva sesión criptográfica
        session = SessionCrypto(self.key_manager.static_private)
        self.sessions[ip] = session
        
        # Obtener mi clave pública efímera
        my_ephemeral = session.get_ephemeral_public_bytes()
        
        # Enviar paquete HELLO
        # Usamos un CID temporal (ej. 0) porque aún no negociamos IDs complejos
        self.protocol.send_packet(ip, port, MSG_HELLO, 0, my_ephemeral)

    def on_packet_received(self, packet, addr):
        ip, port = addr
        
        if packet.msg_type == MSG_HELLO:
            self.handle_handshake_packet(ip, packet)
        elif packet.msg_type == MSG_DATA:
            self.handle_data_packet(ip, packet)

    def handle_handshake_packet(self, ip, packet):
        """
        Recibimos la clave efímera del otro. 
        Calculamos las claves compartidas y completamos la conexión.
        """
        peer_ephemeral = packet.payload
        
        # Si no teníamos sesión creada (somos el Responder), la creamos ahora
        if ip not in self.sessions:
            logger.info(f"Recibido saludo de {ip}. Creando sesión (Responder)...")
            session = SessionCrypto(self.key_manager.static_private)
            self.sessions[ip] = session
            
            # Como somos el que responde, DEBEMOS enviar nuestra clave también
            my_ephemeral = session.get_ephemeral_public_bytes()
            self.protocol.send_packet(ip, port=PORT, msg_type=MSG_HELLO, cid=0, payload=my_ephemeral)
        
        # Completar el cálculo matemático (Diffie-Hellman + HKDF)
        session = self.sessions[ip]
        try:
            # NOTA: is_initiator ayuda a ordenar claves en Noise real. 
            # Aquí simplificado no afecta mucho al cálculo básico ECDH del mock.
            session.perform_handshake(peer_ephemeral, is_initiator=True)
            logger.info(f"✅ HANDSHAKE COMPLETADO CON {ip}. ¡Chat Seguro Listo!")
        except Exception as e:
            logger.error(f"Error en handshake: {e}")

    def handle_data_packet(self, ip, packet):
        """Descifrar y mostrar mensaje."""
        if ip not in self.sessions:
            logger.warning(f"Recibido DATA de {ip} sin sesión activa. Ignorando.")
            return
            
        session = self.sessions[ip]
        try:
            plaintext = session.decrypt(packet.payload)
            print(f"\n[{ip}] dice: {plaintext}")
            # Imprimimos prompt de nuevo para que quede bonito
            print("Tú > ", end="", flush=True) 
        except Exception as e:
            logger.error(f"No se pudo descifrar mensaje de {ip}: {e}")

    def send_chat_message(self, message):
        """Envía un mensaje cifrado a TODOS los peers conectados (Broadcast simple)."""
        if not self.sessions:
            print("⚠ No hay nadie conectado aún. Espera a que Discovery encuentre peers.")
            return

        for ip, session in self.sessions.items():
            try:
                encrypted_payload = session.encrypt(message)
                # Enviamos DATA
                self.protocol.send_packet(ip, PORT, MSG_DATA, 1, encrypted_payload)
            except Exception as e:
                print(f"Error enviando a {ip}: {e}")

# --- GESTIÓN DE ENTRADA DE USUARIO ASÍNCRONA ---
async def console_input_loop(client):
    """Lee del teclado sin bloquear el servidor."""
    print("\n--- Escribe un mensaje y pulsa Enter para enviar ---")
    print("--- Escribe '/quit' para salir ---\n")
    
    # Truco para input asíncrono en Windows/Linux de forma estándar
    loop = asyncio.get_event_loop()
    while True:
        print("Tú > ", end="", flush=True)
        msg = await loop.run_in_executor(None, sys.stdin.readline)
        msg = msg.strip()
        
        if msg == "/quit":
            break
            
        if msg:
            client.send_chat_message(msg)

async def main():
    # Pedimos nombre para distinguir usuarios
    if len(sys.argv) > 1:
        name = sys.argv[1]
    else:
        name = input("Introduce tu nombre de usuario: ")

    client = ChatClient(name)
    
    try:
        await client.start()
        # Ejecutamos el bucle de lectura de teclado y el cliente a la vez
        await console_input_loop(client)
    finally:
        print("Cerrando...")
        await client.stop()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass