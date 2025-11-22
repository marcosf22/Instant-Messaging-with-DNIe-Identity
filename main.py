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

# Tus módulos (asegúrate de que están en la misma carpeta)
from discovery import DiscoveryManager
from crypto import KeyManager, SessionCrypto
from protocol import ChatProtocol, MSG_HELLO, MSG_DATA

# Configuración
PORT = 8888 

def get_zerotier_ip():
    """Obtiene la IP real preguntando al cliente de ZeroTier"""
    sistema = platform.system()
    zt_binary = "zerotier-cli" 
    
    if sistema == "Windows":
        rutas = [
            r"C:\Program Files (x86)\ZeroTier\One\zerotier-cli.bat",
            r"C:\Program Files\ZeroTier\One\zerotier-cli.bat"
        ]
        zt_binary = next((r for r in rutas if os.path.exists(r)), None)
        if not zt_binary:
            print("❌ ERROR: No encuentro ZeroTier instalado.")
            return None

    try:
        # Ejecutamos zerotier-cli para obtener la IP exacta de la VPN
        res = subprocess.check_output([zt_binary, "-j", "listnetworks"], text=True)
        datos = json.loads(res)
        for red in datos:
            if red['status'] == 'OK' and red['assignedAddresses']:
                # Retorna la primera IP de ZeroTier que encuentre (sin la máscara /24)
                return red['assignedAddresses'][0].split('/')[0]
    except Exception as e:
        print(f"❌ Error leyendo ZeroTier: {e}")
    
    return None

class ChatClient:
    def __init__(self, name):
        self.name = name
        self.loop = asyncio.get_running_loop()
        
        # 1. OBTENER IP DE ZEROTIER
        self.my_ip = get_zerotier_ip()
        if not self.my_ip:
            print("⚠️ NO SE DETECTÓ ZEROTIER. Usando IP local normal...")
            self.my_ip = socket.gethostbyname(socket.gethostname())
        
        # Calculamos el prefijo de la red (ej: si mi IP es 10.144.20.5 -> prefijo "10.144.")
        # Esto sirve para filtrar las IPs de los demás y coger solo la del túnel.
        self.network_prefix = ".".join(self.my_ip.split('.')[:2]) + "."

        print(f"--> Identidad: {name}")
        print(f"--> Tu IP Túnel (ZeroTier): {self.my_ip}")
        print(f"--> Filtro de seguridad: Solo aceptaré IPs que empiecen por '{self.network_prefix}'")

        try:
            self.key_manager = KeyManager(f"{name}_identity")
        except Exception as e:
            print(f"❌ ERROR CRIPTO: {e}")
            sys.exit(1)

        self.sessions = {}        
        self.peers = {}           
        self.peer_counter = 0     
        self.target_ip = None     
        
        self.protocol = ChatProtocol(self.on_packet)
        # Pasamos my_ip al discovery por si acaso la librería lo permite usar
        self.discovery = DiscoveryManager(name, self.on_discovery)
        self.transport = None

    async def start(self):
        print(f"--- INICIANDO ESCUCHA EN {self.my_ip}:{PORT} ---")
        
        try:
            # Nos atamos EXCLUSIVAMENTE a la IP de ZeroTier
            self.transport, _ = await self.loop.create_datagram_endpoint(
                lambda: self.protocol, local_addr=(self.my_ip, PORT)
            )
        except Exception as e:
            print(f"Error crítico al abrir puerto: {e}")
            return

        print("--- Buscando usuarios en el túnel... ---")
        await self.discovery.start()

    def on_discovery(self, action, name, info):
        if action == "ADD" and info and info.addresses:
            if name == self.name: return

            # --- CORRECCIÓN CRÍTICA ---
            # No cogemos la primera IP (info.addresses[0]), buscamos la correcta.
            found_zt_ip = None
            
            # Iteramos todas las IPs que anuncia el otro usuario
            for addr_bytes in info.addresses:
                ip_str = socket.inet_ntoa(addr_bytes)
                
                # Solo aceptamos la IP si coincide con nuestro prefijo de ZeroTier
                if ip_str.startswith(self.network_prefix):
                    found_zt_ip = ip_str
                    break
            
            # Si no encontramos una IP de ZeroTier en su anuncio, la ignoramos (es ruido de WiFi)
            if not found_zt_ip:
                # Opcional: debug para ver qué estamos descartando
                # print(f"Ignorando usuario {name} (solo tiene IPs locales: {[socket.inet_ntoa(a) for a in info.addresses]})")
                return

            # Chequear duplicados
            for p in self.peers.values():
                if p['ip'] == found_zt_ip: return
            
            pid = self.peer_counter
            self.peers[pid] = {'ip': found_zt_ip, 'port': PORT, 'name': name}
            self.peer_counter += 1
            
            print(f"\n[+] COMPAÑERO EN EL TÚNEL: [{pid}] {name} IP: {found_zt_ip}")
            if self.target_ip is None:
                print("--> Escribe '/connect <id>' para empezar.")
                print("Comando > ", end="", flush=True)

    def connect_by_id(self, pid):
        if pid not in self.peers:
            print(f"Error ID {pid}")
            return

        peer = self.peers[pid]
        ip = peer['ip']
        print(f"--> Handshake a {peer['name']} usando ruta segura ({ip})...")
        
        session = SessionCrypto(self.key_manager.static_private)
        self.sessions[ip] = session
        my_key = session.get_ephemeral_public_bytes()
        
        for _ in range(3):
            self.protocol.send_packet(ip, PORT, MSG_HELLO, 0, my_key)
        
        self.target_ip = ip
        print("--> Handshake enviado. Si no conecta, revisa el Firewall de Windows (UDP 8888).")

    def on_packet(self, packet, addr):
        ip = addr[0] 
        
        # Filtro extra de seguridad: ignorar paquetes que no vengan del túnel
        if not ip.startswith(self.network_prefix):
            return

        if packet.msg_type == MSG_HELLO:
            is_new = ip not in self.sessions
            
            if is_new:
                print(f"\n[!] Handshake recibido de {ip}.")
                session = SessionCrypto(self.key_manager.static_private)
                self.sessions[ip] = session
            
            session = self.sessions[ip]
            my_key = session.get_ephemeral_public_bytes()
            # Respondemos a la IP que nos habló (que ya sabemos que es la del túnel)
            self.protocol.send_packet(ip, PORT, MSG_HELLO, 0, my_key)

            try:
                self.sessions[ip].perform_handshake(packet.payload, is_initiator=True)
                if is_new or self.target_ip != ip:
                    print(f"✅ CONEXIÓN ESTABLECIDA CON {ip}")
                    if self.target_ip is None: self.target_ip = ip
                    print("Tú > ", end="", flush=True)
            except Exception: pass 

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
    if len(sys.argv) > 1:
        name = sys.argv[1]
    else:
        name = input("Tu nombre: ")
    
    try:
        client = ChatClient(name)
        await client.start()
    except Exception as e:
        print(f"Error iniciando cliente: {e}")
        traceback.print_exc()
        return

    input_queue = queue.Queue()
    def kbd():
        while True:
            try:
                l = sys.stdin.readline()
                if l: input_queue.put(l.strip())
            except: break
    threading.Thread(target=kbd, daemon=True).start()

    print("\n--- SISTEMA LISTO (MODO ZEROTIER) ---")
    print("Comando > ", end="", flush=True)

    while True:
        while not input_queue.empty():
            msg = input_queue.get_nowait()
            if msg == "/quit": return

            if msg.startswith("/connect"):
                try:
                    parts = msg.split()
                    if len(parts) < 2: print("Falta ID")
                    else: client.connect_by_id(int(parts[1]))
                except: pass
            
            elif msg == "/list":
                 for pid, d in client.peers.items():
                     print(f"[{pid}] {d['name']} ({d['ip']})")
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
