import asyncio
import json
import os
import platform
import subprocess
import sys
import socket
import threading
import queue
import traceback

# Módulos de cripto y protocolo (se mantienen igual)
from crypto import KeyManager, SessionCrypto
from protocol import ChatProtocol, MSG_HELLO, MSG_DATA

# Configuración
PORT = 8888 
BROADCAST_PORT = 8888
MAGIC_WORD = b"ZEROTIER_CHAT_V1" # Para identificar nuestros paquetes de discovery

def get_zerotier_ip_info():
    """Devuelve la IP y la máscara (netmask) de ZeroTier"""
    sistema = platform.system()
    zt_binary = "zerotier-cli" 
    if sistema == "Windows":
        rutas = [r"C:\Program Files (x86)\ZeroTier\One\zerotier-cli.bat", r"C:\Program Files\ZeroTier\One\zerotier-cli.bat"]
        zt_binary = next((r for r in rutas if os.path.exists(r)), None)

    try:
        if zt_binary:
            res = subprocess.check_output([zt_binary, "-j", "listnetworks"], text=True)
            datos = json.loads(res)
            for red in datos:
                if red['status'] == 'OK' and red['assignedAddresses']:
                    # Devuelve algo tipo "10.144.20.5/24"
                    return red['assignedAddresses'][0] 
    except: pass
    return None

def get_broadcast_address(ip_cidr):
    """Calcula la dirección de broadcast de la red ZeroTier (ej: 10.144.255.255)"""
    try:
        import ipaddress
        net = ipaddress.IPv4Interface(ip_cidr)
        return str(net.network.broadcast_address)
    except:
        return "255.255.255.255" # Fallback

class ChatClient:
    def __init__(self, name):
        self.name = name
        self.loop = asyncio.get_running_loop()
        
        # 1. OBTENER INFO DE ZEROTIER
        zt_info = get_zerotier_ip_info()
        if zt_info:
            self.my_ip = zt_info.split('/')[0]
            self.broadcast_addr = get_broadcast_address(zt_info)
            print(f"✅ ZeroTier detectado: {self.my_ip}")
            print(f"📡 Dirección de Broadcast calculada: {self.broadcast_addr}")
        else:
            print("⚠️ NO SE DETECTÓ ZEROTIER. Usando IP local (Discovery fallará si no estáis en la misma LAN).")
            self.my_ip = socket.gethostbyname(socket.gethostname())
            self.broadcast_addr = "255.255.255.255"

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
        # Escuchar en 0.0.0.0 para recibir todo
        print(f"--- INICIANDO ESCUCHA EN PUERTO {PORT} ---")
        self.transport, _ = await self.loop.create_datagram_endpoint(
            lambda: self.protocol, local_addr=("0.0.0.0", PORT), allow_broadcast=True
        )
        
        # Iniciar el 'faro' de descubrimiento
        self.loop.create_task(self.beacon_loop())

    async def beacon_loop(self):
        """Envía un paquete 'AQUÍ ESTOY' cada 3 segundos por la interfaz de ZeroTier"""
        print("--- Iniciando baliza de descubrimiento (Beacon) ---")
        
        # Creamos un socket UDP puro para enviar el broadcast forzando la interfaz
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        # VITAL: Bind a la IP de ZeroTier para que el broadcast salga por el túnel
        try:
            sock.bind((self.my_ip, 0)) 
        except:
            print("⚠️ No pude atar el socket a la IP de ZT. El discovery podría fallar.")

        msg = MAGIC_WORD + f":{self.name}".encode()

        while True:
            try:
                # Enviamos a la dirección de broadcast de la VPN
                sock.sendto(msg, (self.broadcast_addr, PORT))
                # También enviamos a broadcast global por si acaso
                # sock.sendto(msg, ("255.255.255.255", PORT)) 
            except Exception as e:
                print(f"Error beacon: {e}")
            
            await asyncio.sleep(3) # Gritar cada 3 segundos

    def on_packet(self, packet, addr):
        ip = addr[0]
        if ip == self.my_ip: return # Ignorarnos a nosotros mismos

        # 1. INTERCEPTAR PAQUETES DE DISCOVERY (Raw bytes check)
        # Como ChatProtocol suele esperar una estructura, si falla el parseo puede ser un beacon.
        # Pero ChatProtocol probablemente procesa el header. 
        # Si usas un protocolo binario estricto, el beacon debería ser un tipo de mensaje MSG_DISCOVERY.
        # HACK RAPIDO: Verificamos si el payload crudo parece nuestro beacon.
        # (Esto depende de cómo tu protocol.py maneje datos corruptos/desconocidos).
        
        # Si tu protocol.py lanza error con datos basura, este método fallará.
        # Asumiremos que el beacon llega aquí de alguna forma o modificamos protocol.
        
        pass 
        # NOTA: Como ChatProtocol decodifica, necesitamos manejar el beacon DENTRO de protocol.py
        # o enviar el beacon usando el formato de ChatProtocol.
        # VAMOS A CAMBIAR LA ESTRATEGIA DEL BEACON:

    # --- REEMPLAZO DE ESTRATEGIA: ENVIAR BEACON CON FORMATO DE PROTOCOLO ---
    # Olvida el beacon_loop de arriba que usa socket crudo si rompe tu parser.
    # Usaremos send_packet del protocolo con un tipo especial o MSG_HELLO modificado.

    async def beacon_loop_safe(self):
        """Versión segura que usa tu protocolo para hacer broadcast"""
        # Usamos un ID ficticio o tipo especial. Asumiremos que MSG_HELLO sirve para anunciarse.
        # O mejor, enviamos un paquete que al fallar la desencriptación revele la IP.
        print("--- Discovery Activo ---")
        while True:
            # Enviamos un HELLO genérico a la dirección de broadcast
            # La clave pública va en el payload
            my_key = self.key_manager.static_public # Usamos la estática para anunciar
            
            # Necesitamos acceso al transport para enviar a broadcast manualmente
            if self.transport:
                # HACK: Usamos el socket del transport para enviar raw bytes si protocol lo permite
                # O usamos protocol.send_packet si soporta broadcast IP
                try:
                    self.protocol.send_packet(self.broadcast_addr, PORT, MSG_HELLO, 0, my_key)
                except: pass
            
            await asyncio.sleep(2)

    def on_packet(self, packet, addr):
        ip = addr[0]
        if ip == self.my_ip: return 

        if packet.msg_type == MSG_HELLO:
            # CASO 1: Es un desconocido hablándome (Soy el RESPONDER)
            if ip not in self.sessions:
                print(f"\n[!] Solicitud de conexión de {ip}")
                # Creamos la sesión
                session = SessionCrypto(self.key_manager.static_private)
                self.sessions[ip] = session
                
                # Procesamos su clave
                try:
                    session.perform_handshake(packet.payload, is_initiator=True) # True porque en este protocolo P2P ambos actúan como pares
                except Exception as e:
                    print(f"Error Crypto Handshake: {e}")
                    return

                # IMPORTANTE: Como él inició, YO DEBO RESPONDERLE para que tenga mi clave
                print(f"    -> Enviando mi clave a {ip}...")
                my_key = session.get_ephemeral_public_bytes()
                self.protocol.send_packet(ip, PORT, MSG_HELLO, 0, my_key)

            # CASO 2: Ya conozco a este tipo (Soy el INICIADOR y me responden)
            else:
                # Si ya tengo sesión, significa que YO inicié la charla y él me responde.
                # NO debo crear sesión nueva. NO debo responderle otra vez (evitar bucle infinito).
                session = self.sessions[ip]
                try:
                    # Simplemente guardo su clave y me callo.
                    session.perform_handshake(packet.payload, is_initiator=True)
                    
                    if self.target_ip != ip:
                        self.target_ip = ip
                        print(f"\n✅ ¡CONEXIÓN COMPLETADA CON {ip}!")
                        print("   Ahora ambos podéis hablar.")
                        print("Tú > ", end="", flush=True)
                except Exception as e:
                    # Si falla aquí, es posible que sea un paquete duplicado, lo ignoramos
                    pass

        elif packet.msg_type == MSG_DATA:
            if ip in self.sessions:
                try:
                    msg = self.sessions[ip].decrypt(packet.payload)
                    
                    # Buscar nombre bonito
                    name = ip
                    for p in self.peers.values():
                        if p['ip'] == ip: name = p['name']
                    
                    sys.stdout.write("\r\033[K")
                    print(f"[{name}]: {msg}")
                    print("Tú > ", end="", flush=True)
                except Exception:
                    print(f"\n💀 Error desencriptando mensaje de {ip}. Las claves no coinciden.")
            else:
                print(f"\n⚠️ Recibidos datos de {ip} sin sesión. Escribe '/connect {ip}' para arreglarlo.")

    def connect_manual(self, ip_target):
        """Conexión manual si falla el discovery"""
        print(f"--> Forzando conexión a {ip_target}...")
        session = SessionCrypto(self.key_manager.static_private)
        self.sessions[ip_target] = session
        my_key = session.get_ephemeral_public_bytes()
        
        for _ in range(5): # Enviamos 5 veces agresivamente
            self.protocol.send_packet(ip_target, PORT, MSG_HELLO, 0, my_key)
        
        self.target_ip = ip_target
        print("--> Handshake enviado.")

    def send_chat(self, text):
        if self.target_ip and self.target_ip in self.sessions:
            try:
                enc = self.sessions[self.target_ip].encrypt(text)
                self.protocol.send_packet(self.target_ip, PORT, MSG_DATA, 1, enc)
            except: pass

async def main():
    name = sys.argv[1] if len(sys.argv) > 1 else input("Nombre: ")
    client = ChatClient(name)
    
    # INICIAMOS EL BEACON SEGURO
    client.loop.create_task(client.beacon_loop_safe())
    
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
    print("Si el discovery falla, usa: /connect <IP_ZEROTIER>")
    print("Comando > ", end="", flush=True)

    while True:
        while not input_queue.empty():
            msg = input_queue.get_nowait()
            if msg == "/quit": return

            if msg.startswith("/connect"):
                parts = msg.split()
                if len(parts) == 2:
                    # Permite conectar por ID (si existe en lista) o por IP DIRECTA
                    target = parts[1]
                    if '.' in target: # Es una IP
                        client.connect_manual(target)
                    else: # Es un ID
                         try:
                             pid = int(target)
                             if pid in client.peers:
                                 client.connect_manual(client.peers[pid]['ip'])
                         except: print("ID inválido")
            
            elif msg == "/list":
                 print("Peers detectados:")
                 for pid, d in client.peers.items():
                     print(f"[{pid}] {d['ip']}")
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
