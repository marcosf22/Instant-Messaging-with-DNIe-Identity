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

# Tus módulos
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
        if not zt_binary: return None

    try:
        res = subprocess.check_output([zt_binary, "-j", "listnetworks"], text=True)
        datos = json.loads(res)
        for red in datos:
            if red['status'] == 'OK' and red['assignedAddresses']:
                return red['assignedAddresses'][0].split('/')[0]
    except: pass
    return None

class ChatClient:
    def __init__(self, name):
        self.name = name
        self.loop = asyncio.get_running_loop()
        
        # 1. Detectamos NUESTRA IP de ZeroTier para saber el prefijo
        self.my_zt_ip = get_zerotier_ip()
        if not self.my_zt_ip:
            print("⚠️ NO SE DETECTÓ ZEROTIER. Usando IP local...")
            self.my_zt_ip = socket.gethostbyname(socket.gethostname())
        
        # Sacamos el "10.144." o lo que sea que use tu red ZeroTier
        parts = self.my_zt_ip.split('.')
        self.network_prefix = f"{parts[0]}.{parts[1]}." 

        print(f"--> Tu IP ZeroTier: {self.my_zt_ip}")
        print(f"--> Buscando compañeros que tengan IP empezando por: {self.network_prefix}")

        try:
            self.key_manager = KeyManager(f"{name}_identity")
        except Exception as e:
            sys.exit(1)

        self.sessions = {}        
        self.peers = {}           
        self.peer_counter = 0     
        self.target_ip = None     
        
        self.protocol = ChatProtocol(self.on_packet)
        self.discovery = DiscoveryManager(name, self.on_discovery)
        self.transport = None

    async def start(self):
        # CAMBIO IMPORTANTE: Escuchamos en 0.0.0.0 para oír el Discovery por WiFi
        print(f"--- INICIANDO ESCUCHA GLOBAL (Puerto {PORT}) ---")
        
        try:
            self.transport, _ = await self.loop.create_datagram_endpoint(
                lambda: self.protocol, local_addr=("0.0.0.0", PORT)
            )
        except Exception as e:
            print(f"Error crítico puerto {PORT}: {e}")
            return

        print("--- Buscando usuarios... ---")
        await self.discovery.start()

    def on_discovery(self, action, name, info):
        if action == "ADD" and info and info.addresses:
            if name == self.name: return

            # AQUÍ ESTÁ LA MAGIA:
            # El paquete de discovery trae una lista de TODAS las IPs del otro usuario.
            # Iteramos la lista y buscamos SOLO la que coincida con ZeroTier.
            
            zt_ip_found = None
            
            # Debug para ver qué llega
            # ips_recibidas = [socket.inet_ntoa(a) for a in info.addresses]
            # print(f"Usuario {name} reporta IPs: {ips_recibidas}")

            for addr_bytes in info.addresses:
                ip_str = socket.inet_ntoa(addr_bytes)
                if ip_str.startswith(self.network_prefix):
                    zt_ip_found = ip_str
                    break
            
            if zt_ip_found:
                # Chequear duplicados
                for p in self.peers.values():
                    if p['ip'] == zt_ip_found: return
                
                pid = self.peer_counter
                # GUARDAMOS SOLO LA IP DE ZEROTIER, NO LA DE LA WIFI
                self.peers[pid] = {'ip': zt_ip_found, 'port': PORT, 'name': name}
                self.peer_counter += 1
                
                print(f"\n[+] USUARIO CORRECTO: [{pid}] {name} -> IP VPN: {zt_ip_found}")
                if self.target_ip is None:
                    print("--> Escribe '/connect <id>' para conectar.")
                    print("Comando > ", end="", flush=True)
            else:
                # Si el usuario no tiene IP de ZeroTier, lo ignoramos
                pass

    def connect_by_id(self, pid):
        if pid not in self.peers:
            print(f"Error ID {pid}")
            return

        peer = self.peers[pid]
        target_ip = peer['ip'] # Esta ya será la 10.x.x.x garantizada
        
        print(f"--> Conectando a {peer['name']} en {target_ip}...")
        
        session = SessionCrypto(self.key_manager.static_private)
        self.sessions[target_ip] = session
        my_key = session.get_ephemeral_public_bytes()
        
        for _ in range(3):
            self.protocol.send_packet(target_ip, PORT, MSG_HELLO, 0, my_key)
        
        self.target_ip = target_ip
        print("--> Handshake enviado por el túnel. Esperando...")

    def on_packet(self, packet, addr):
        ip = addr[0] 
        
        if packet.msg_type == MSG_HELLO:
            is_new = ip not in self.sessions
            
            if is_new:
                # Opcional: Validar que la IP entrante sea de ZeroTier
                if not ip.startswith(self.network_prefix):
                    # print(f"Ignorando handshake de IP extraña: {ip}")
                    return

                print(f"\n[!] Handshake recibido de {ip}.")
                session = SessionCrypto(self.key_manager.static_private)
                self.sessions[ip] = session
            
            session = self.sessions[ip]
            my_key = session.get_ephemeral_public_bytes()
            self.protocol.send_packet(ip, PORT, MSG_HELLO, 0, my_key)

            try:
                self.sessions[ip].perform_handshake(packet.payload, is_initiator=True)
                if is_new or self.target_ip != ip:
                    print(f"✅ CONECTADO SEGURO CON {ip}")
                    if self.target_ip is None: self.target_ip = ip
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
                except: pass

    def send_chat(self, text):
        if not self.target_ip: return
        if self.target_ip not in self.sessions: return

        try:
            session = self.sessions[self.target_ip]
            encrypted = session.encrypt(text)
            self.protocol.send_packet(self.target_ip, PORT, MSG_DATA, 1, encrypted)
        except Exception as e:
            print(f"Error envio: {e}")

async def main():
    if len(sys.argv) > 1: name = sys.argv[1]
    else: name = input("Tu nombre: ")
    
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
                    parts = msg.split()
                    client.connect_by_id(int(parts[1]))
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
