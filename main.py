import asyncio
import sys
import socket
import threading
import queue
import json
import os

from crypto import KeyManager, SessionCrypto
from protocol import ChatProtocol, MSG_HELLO, MSG_DATA, MSG_DISCOVERY

PORT = 8888 
SESSION_FILE = "sessions.json"

def get_best_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 1)) 
        IP = s.getsockname()[0]
    except: IP = '127.0.0.1'
    finally: s.close()
    return IP

class ChatClient:
    def __init__(self, name):
        self.name = name
        self.loop = asyncio.get_running_loop()
        self.my_ip = get_best_ip()
        
        try:
            parts = self.my_ip.split('.')
            self.broadcast_addr = f"{parts[0]}.{parts[1]}.{parts[2]}.255"
        except: self.broadcast_addr = "255.255.255.255"

        print(f"--> Mi IP: {self.my_ip}")

        try:
            self.key_manager = KeyManager(f"{name}_identity")
        except Exception as e:
            print(f"❌ Error crypto: {e}")
            sys.exit(1)

        self.sessions = {}        
        self.peers = {}           
        self.peer_counter = 0     
        self.target_ip = None     
        self.pending_requests = {} 

        self.protocol = ChatProtocol(self.on_packet)
        self.transport = None
        self.load_sessions_from_disk()

    # --- PERSISTENCIA ---
    def load_sessions_from_disk(self):
        if not os.path.exists(SESSION_FILE): return
        try:
            with open(SESSION_FILE, 'r') as f:
                saved_data = json.load(f)
            count = 0
            for ip, hex_key in saved_data.items():
                session = SessionCrypto(self.key_manager.static_private)
                try:
                    session.load_secret(hex_key)
                    self.sessions[ip] = session
                    count += 1
                except: pass
            if count > 0: print(f"💾 {count} sesiones recuperadas.")
        except: pass

    def save_sessions_to_disk(self):
        data = {}
        for ip, session in self.sessions.items():
            k = session.export_secret()
            if k: data[ip] = k
        try:
            with open(SESSION_FILE, 'w') as f: json.dump(data, f, indent=4)
        except: pass

    # --- RED ---
    async def start(self):
        print(f"--- CHAT INICIADO EN {PORT} ---")
        self.transport, _ = await self.loop.create_datagram_endpoint(
            lambda: self.protocol, local_addr=("0.0.0.0", PORT), allow_broadcast=True
        )
        self.loop.create_task(self.beacon_loop())

    async def beacon_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try: sock.bind((self.my_ip, 0))
        except: pass
        msg = f"DISCOVERY:{self.name}".encode()
        while True:
            try: sock.sendto(msg, (self.broadcast_addr, PORT))
            except: pass
            await asyncio.sleep(3)

    # --- UI ---
    def show_peers(self):
        print("\n" + "="*30)
        print(" 👥  CONTACTOS")
        print("="*30)
        for pid, d in self.peers.items():
            status = " [🔐 Guardado]" if d['ip'] in self.sessions else ""
            print(f"   [{pid}]  {d['name']:<15} {status}")
        
        if self.pending_requests:
            print("-" * 30)
            for ip in self.pending_requests:
                name = "Desconocido"
                pid_s = "?"
                for pid, d in self.peers.items():
                    if d['ip'] == ip: 
                        name, pid_s = d['name'], str(pid)
                print(f" 🔔 {name} quiere conectar. (/accept {pid_s})")
        print("="*30)

    def disconnect_current(self):
        if self.target_ip:
            print(f"\n🔌 Desconectado de {self.target_ip}.")
            self.target_ip = None
        self.show_peers()
        print("(Lobby) > ", end="", flush=True)

    def accept_connection(self, peer_id):
        if peer_id not in self.peers: return print("❌ ID incorrecto")
        ip = self.peers[peer_id]['ip']
        if ip not in self.pending_requests: return print("⚠️ No hay solicitud.")
        
        print(f"✅ Aceptando...")
        session = SessionCrypto(self.key_manager.static_private)
        self.sessions[ip] = session
        try:
            session.perform_handshake(self.pending_requests[ip], True)
            mk = session.get_ephemeral_public_bytes()
            for _ in range(3): self.protocol.send_packet(ip, PORT, MSG_HELLO, 0, mk)
            
            self.target_ip = ip
            del self.pending_requests[ip]
            self.save_sessions_to_disk()
            print(f"\n✨ CONECTADO.")
            print("Tú > ", end="", flush=True)
        except Exception as e: print(f"❌ Error: {e}")

    # --- PACKETS ---
    def on_packet(self, packet, addr):
        ip = addr[0]
        if ip == self.my_ip: return 

        if packet.msg_type == MSG_DISCOVERY:
            name = packet.payload
            if ip not in [p['ip'] for p in self.peers.values()]:
                 pid = self.peer_counter
                 self.peers[pid] = {'ip': ip, 'port': PORT, 'name': name}
                 self.peer_counter += 1
                 if self.target_ip is None:
                     print(f"\n🔭 Nuevo contacto: [{pid}] {name}")
                     print("(Lobby) > ", end="", flush=True)

        elif packet.msg_type == MSG_HELLO:
            if ip in self.sessions:
                try:
                    self.sessions[ip].perform_handshake(packet.payload, True)
                    self.save_sessions_to_disk()
                    print(f"\n✅ CONEXIÓN COMPLETADA CON {ip}")
                    print("Tú > ", end="", flush=True)
                except: pass
                return

            if ip not in self.pending_requests:
                self.pending_requests[ip] = packet.payload
                # Avisar
                name, pid_s = ip, "?"
                for pid, d in self.peers.items():
                    if d['ip'] == ip: name, pid_s = d['name'], pid
                print(f"\n🔔 Solicitud de {name}. (/accept {pid_s})")
                print("Tú > " if self.target_ip else "(Lobby) > ", end="", flush=True)

        elif packet.msg_type == MSG_DATA:
            if ip in self.sessions:
                try:
                    msg = self.sessions[ip].decrypt(packet.payload)
                    name = ip
                    for p in self.peers.values():
                        if p['ip'] == ip: name = p['name']
                    sys.stdout.write("\r\033[K")
                    print(f"[{name}]: {msg}")
                    print("Tú > " if self.target_ip == ip else "(Lobby) > ", end="", flush=True)
                except:
                    print(f"\n♻️ Clave vieja falló. Renegociando...")
                    del self.sessions[ip]
                    self.save_sessions_to_disk()
                    self.connect_manual(ip)
            else:
                print(f"\n⚠️ Mensaje ilegible. Reconectando...")
                self.connect_manual(ip)

    def connect_manual(self, ip_target):
        if ip_target in self.sessions:
            self.target_ip = ip_target
            print("✅ Usando clave guardada. Chat listo.")
            return

        print(f"--> Enviando solicitud a {ip_target}...")
        session = SessionCrypto(self.key_manager.static_private)
        self.sessions[ip_target] = session
        try:
            mk = session.get_ephemeral_public_bytes()
            for _ in range(3): self.protocol.send_packet(ip_target, PORT, MSG_HELLO, 0, mk)
            self.target_ip = ip_target
            print("⏳ Esperando respuesta...")
        except: del self.sessions[ip_target]

    def send_chat(self, text):
        if self.target_ip and self.target_ip in self.sessions:
            try:
                enc = self.sessions[self.target_ip].encrypt(text)
                self.protocol.send_packet(self.target_ip, PORT, MSG_DATA, 1, enc)
            except: pass
        else: print("⛔ No conectado.")

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
    client.show_peers()
    print("(Lobby) > ", end="", flush=True)

    while True:
        while not input_queue.empty():
            msg = input_queue.get_nowait()
            if msg == "/quit": 
                client.save_sessions_to_disk()
                return
            elif msg == "/leave": client.disconnect_current()
            elif msg.startswith("/connect"):
                parts = msg.split()
                if len(parts) > 1 and parts[1].isdigit():
                    pid = int(parts[1])
                    if pid in client.peers: client.connect_manual(client.peers[pid]['ip'])
                    else: print("❌ ID incorrecto")
            elif msg.startswith("/accept"):
                parts = msg.split()
                if len(parts) > 1 and parts[1].isdigit(): client.accept_connection(int(parts[1]))
            elif msg == "/list":
                 client.show_peers()
                 print("Tú > " if client.target_ip else "(Lobby) > ", end="", flush=True)
            else:
                if client.target_ip:
                    client.send_chat(msg)
                    print("Tú > ", end="", flush=True)
                else:
                    if msg.strip(): 
                        print("⛔ Lobby: Usa /connect <ID>")
                        print("(Lobby) > ", end="", flush=True)
        await asyncio.sleep(0.1)

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try: asyncio.run(main())
    except KeyboardInterrupt: pass