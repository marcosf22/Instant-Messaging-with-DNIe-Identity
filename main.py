import asyncio
import sys
import socket
import threading
import queue
import json
import os
import struct

from crypto import KeyManager, SessionCrypto
from protocol import ChatProtocol, MSG_HELLO, MSG_DATA, MSG_DISCOVERY, MSG_AUTH

PORT = 8888 
SESSION_FILE = "sessions.json"

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: s.connect(('8.8.8.8', 1)); IP = s.getsockname()[0]
    except: IP = '127.0.0.1'
    finally: s.close()
    return IP

class ChatClient:
    def __init__(self, name):
        self.name = name
        self.loop = asyncio.get_running_loop()
        self.my_ip = get_ip()
        self.broadcast = "255.255.255.255"
        
        # Crypto
        try: self.km = KeyManager(f"{name}_identity")
        except Exception as e: print(f"❌ Error Crypto: {e}"); sys.exit(1)

        self.sessions = {}        
        self.peers = {}           
        self.target_ip = None     
        self.pending = {} 
        self.verified_users = {} # Lista de usuarios DNIe verificados

        self.proto = ChatProtocol(self.on_packet)
        self.load_sessions()

    # --- DISCO ---
    def load_sessions(self):
        if not os.path.exists(SESSION_FILE): return
        try:
            with open(SESSION_FILE,'r') as f: data = json.load(f)
            for ip, hx in data.items():
                s = SessionCrypto(None); s.load_secret(hx)
                self.sessions[ip] = s
        except: pass

    def save_sessions(self):
        d = {ip: s.export_secret() for ip, s in self.sessions.items() if s.export_secret()}
        try:
            with open(SESSION_FILE,'w') as f: json.dump(d, f)
        except: pass

    # --- RED ---
    async def start(self):
        print(f"--- CHAT EN {self.my_ip}:{PORT} ---")
        self.trans, _ = await self.loop.create_datagram_endpoint(
            lambda: self.proto, local_addr=("0.0.0.0", PORT), allow_broadcast=True
        )
        self.loop.create_task(self.beacon())

    async def beacon(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try: s.bind((self.my_ip,0))
        except: pass
        msg = f"DISCOVERY:{self.name}".encode()
        while True:
            try: s.sendto(msg, (self.broadcast, PORT))
            except: pass
            await asyncio.sleep(3)

    # --- VERIFICACIÓN DNIe ---
    def send_verification(self):
        """Pide PIN, firma y envía credenciales"""
        if not self.target_ip: return print("⛔ Conecta primero.")
        print("\n💳 Preparando DNIe (Te pedirá el PIN)...")
        try:
            # 1. Firmar
            pub_k, cert, sig = self.km.get_my_identity_pack()
            
            # 2. Empaquetar: [LenCert(4) + Cert + LenSig(4) + Sig + Key(32)]
            payload = struct.pack("!I", len(cert)) + cert + \
                      struct.pack("!I", len(sig)) + sig + \
                      pub_k
            
            # 3. Encriptar y Enviar como MSG_AUTH
            # IMPORTANTE: Encriptamos el paquete de auth para que nadie robe la firma en tránsito
            session = self.sessions[self.target_ip]
            encrypted_payload = session.encrypt(payload.decode('latin1')) # Hack para encryptar bytes raw
            
            # Enviamos como MSG_AUTH
            self.proto.send_packet(self.target_ip, PORT, MSG_AUTH, 0, encrypted_payload)
            print("📤 Credenciales enviadas. Esperando validación del otro...")
            
        except Exception as e:
            print(f"❌ Error DNIe: {e}")

    # --- PACKETS ---
    def on_packet(self, pkt, addr):
        ip = addr[0]
        if ip == self.my_ip: return

        if pkt.msg_type == MSG_DISCOVERY:
            name = pkt.payload
            if ip not in [p['ip'] for p in self.peers.values()]:
                self.peers[len(self.peers)] = {'ip': ip, 'name': name}
                if not self.target_ip: print(f"\n🔭 Nuevo: {name} ({ip})")

        elif pkt.msg_type == MSG_HELLO:
            if ip not in self.sessions:
                if ip not in self.pending:
                    self.pending[ip] = pkt.payload
                    print(f"\n🔔 Solicitud de {ip}. (/accept ID)")
            else:
                self.sessions[ip].perform_handshake(pkt.payload)

        elif pkt.msg_type == MSG_DATA:
            if ip in self.sessions:
                try:
                    msg = self.sessions[ip].decrypt(pkt.payload)
                    name = self.verified_users.get(ip, ip) # Usar nombre real si existe
                    print(f"\r[{name}]: {msg}\nTú > ", end="")
                except: 
                    print("\n♻️ Renegociando..."); del self.sessions[ip]; self.connect(ip)
        
        elif pkt.msg_type == MSG_AUTH:
            if ip in self.sessions:
                print(f"\n🕵️ Recibiendo documentación de {ip}...")
                try:
                    # 1. Desencriptar
                    # (Usamos decode latin1 para recuperar los bytes originales tras desencriptar)
                    decrypted_str = self.sessions[ip].decrypt(pkt.payload)
                    raw_data = decrypted_str.encode('latin1')
                    
                    # 2. Desempaquetar
                    offset = 0
                    l_cert = struct.unpack("!I", raw_data[offset:offset+4])[0]; offset+=4
                    cert = raw_data[offset:offset+l_cert]; offset+=l_cert
                    l_sig = struct.unpack("!I", raw_data[offset:offset+4])[0]; offset+=4
                    sig = raw_data[offset:offset+l_sig]; offset+=l_sig
                    pub_k = raw_data[offset:]
                    
                    # 3. VERIFICAR
                    valid, cn = self.km.verify_peer_identity(pub_k, cert, sig)
                    
                    if valid:
                        print(f"✅ IDENTIDAD VERIFICADA: {cn}")
                        print(f"   (El DNIe confirma que esta persona es real)")
                        self.verified_users[ip] = f"{cn} (Verificado)"
                    else:
                        print(f"❌ ALERTA: FIRMA INVÁLIDA. {cn}")
                except Exception as e:
                    print(f"❌ Error procesando Auth: {e}")

    # --- ACTIONS ---
    def connect(self, ip):
        s = SessionCrypto(None)
        self.sessions[ip] = s
        for _ in range(3): 
            self.proto.send_packet(ip, PORT, MSG_HELLO, 0, s.get_ephemeral_public_bytes())
        self.target_ip = ip

    def accept(self, pid):
        if pid not in self.peers: return
        ip = self.peers[pid]['ip']
        if ip in self.pending:
            self.connect(ip) # Inicia handshake reverso
            self.sessions[ip].perform_handshake(self.pending[ip])
            del self.pending[ip]
            self.save_sessions()
            print("✅ Conectado.")

# --- MAIN ---
async def main():
    name = sys.argv[1] if len(sys.argv)>1 else input("Nombre: ")
    c = ChatClient(name)
    await c.start()
    
    q = queue.Queue()
    threading.Thread(target=lambda: [q.put(sys.stdin.readline().strip()) for _ in iter(int,1)], daemon=True).start()

    print("--- LISTO ---")
    print("Comandos: /connect ID, /accept ID, /verify (Envia tu DNIe)")
    c.load_sessions()
    print("(Lobby) > ", end="")

    while True:
        while not q.empty():
            msg = q.get()
            if msg == "/quit": c.save_sessions(); return
            if msg == "/verify": c.send_verification()
            elif msg.startswith("/connect"): 
                try: c.connect(c.peers[int(msg.split()[1])]['ip'])
                except: print("ID Mal")
            elif msg.startswith("/accept"):
                try: c.accept(int(msg.split()[1]))
                except: print("ID Mal")
            elif msg == "/list": 
                for k,v in c.peers.items(): print(f"{k}: {v['name']} - {v['ip']}")
            else:
                if c.target_ip:
                    enc = c.sessions[c.target_ip].encrypt(msg)
                    c.proto.send_packet(c.target_ip, PORT, MSG_DATA, 0, enc)
                    print("Tú > ", end="")
        await asyncio.sleep(0.1)

if __name__ == "__main__":
    try: asyncio.run(main())
    except: pass