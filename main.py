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
        
        # Guardamos la clave pública del otro para verificarla después
        self.peer_static_keys = {} 

        try: self.km = KeyManager(f"{name}_identity")
        except: sys.exit(1)

        self.sessions = {}        
        self.peers = {}           
        self.target_ip = None     
        self.pending = {} 
        self.verified_users = {}

        self.proto = ChatProtocol(self.on_packet)
        self.load_sessions()

    # ... (Funciones de Persistencia load_sessions / save_sessions igual que antes) ...
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
        try: with open(SESSION_FILE,'w') as f: json.dump(d, f)
        except: pass

    # --- VERIFICACIÓN DNIe (CORREGIDA) ---
    def send_verification(self):
        if not self.target_ip: return print("⛔ Conecta primero.")
        
        print("\n💳 GENERANDO FIRMA DIGITAL DE TU CLAVE DE CHAT...")
        # Esto pedirá el PIN localmente, firmará tu clave y devolverá la firma
        cert_der, firma = self.km.generar_paquete_verificacion()
        
        if not cert_der or not firma:
            print("❌ Cancelado.")
            return

        # Empaquetamos: [LenCert(4) + Cert + LenFirma(4) + Firma]
        # NO ENVIAMOS LA CLAVE PÚBLICA, PORQUE EL OTRO YA LA TIENE DEL HANDSHAKE
        payload = struct.pack("!I", len(cert_der)) + cert_der + \
                  struct.pack("!I", len(firma)) + firma
        
        # Encriptamos el paquete de autenticación para privacidad
        try:
            session = self.sessions[self.target_ip]
            # Codificamos a latin1 para preservar bytes tras encriptar
            encrypted_payload = session.encrypt(payload.decode('latin1')) 
            self.proto.send_packet(self.target_ip, PORT, MSG_AUTH, 0, encrypted_payload)
            print("📤 Firma enviada. El otro usuario comprobará tu identidad.")
        except Exception as e:
            print(f"❌ Error enviando: {e}")

    # --- RED ---
    async def start(self):
        print(f"--- CHAT EN {self.my_ip}:{PORT} ---")
        self.transport, _ = await self.loop.create_datagram_endpoint(
            lambda: self.proto, local_addr=("0.0.0.0", PORT), allow_broadcast=True
        )
        self.loop.create_task(self.beacon())

    async def beacon(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try: s.bind((self.my_ip, 0))
        except: pass
        msg = f"DISCOVERY:{self.name}".encode()
        while True:
            try: s.sendto(msg, ("255.255.255.255", PORT))
            except: pass
            await asyncio.sleep(3)

    # --- PACKETS ---
    def on_packet(self, pkt, addr):
        ip = addr[0]
        if ip == self.my_ip: return

        if pkt.msg_type == MSG_DISCOVERY:
            if ip not in [p['ip'] for p in self.peers.values()]:
                self.peers[len(self.peers)] = {'ip': ip, 'name': pkt.payload}

        elif pkt.msg_type == MSG_HELLO:
            # GUARDAMOS SU CLAVE PÚBLICA PARA VERIFICARLA LUEGO
            self.peer_static_keys[ip] = pkt.payload

            if ip in self.sessions:
                try: self.sessions[ip].perform_handshake(pkt.payload)
                except: pass
            elif ip not in self.pending:
                self.pending[ip] = pkt.payload
                print(f"\n🔔 Solicitud de {ip}. (/accept ID)")

        elif pkt.msg_type == MSG_AUTH:
            if ip in self.sessions:
                print(f"\n🕵️ Verificando firma digital de {ip}...")
                try:
                    # 1. Desencriptar
                    decrypted = self.sessions[ip].decrypt(pkt.payload).encode('latin1')
                    
                    # 2. Desempaquetar
                    offset = 0
                    l_c = struct.unpack("!I", decrypted[offset:offset+4])[0]; offset+=4
                    cert = decrypted[offset:offset+l_c]; offset+=l_c
                    l_s = struct.unpack("!I", decrypted[offset:offset+4])[0]; offset+=4
                    firma = decrypted[offset:offset+l_s]
                    
                    # 3. VERIFICAR LA FIRMA CONTRA LA CLAVE DEL CHAT
                    # Recuperamos la clave pública que nos envió en el Handshake (HELLO)
                    clave_chat_usuario = self.peer_static_keys.get(ip)
                    
                    if not clave_chat_usuario:
                        print("❌ Error: No tengo la clave de chat original para verificar.")
                        return

                    valido, nombre_real = self.km.verificar_identidad_del_otro(
                        clave_chat_usuario, cert, firma
                    )
                    
                    if valido:
                        print(f"✅ DNIe VERIFICADO CORRECTAMENTE.")
                        print(f"   La persona usando este chat es realmente: {nombre_real}")
                        self.verified_users[ip] = nombre_real
                    else:
                        print(f"❌ ALERTA ROJA: La firma NO coincide. Identidad falsa o error.")
                        print(f"   Error: {nombre_real}")

                except Exception as e: print(f"❌ Error Auth: {e}")

        elif pkt.msg_type == MSG_DATA:
            if ip in self.sessions:
                try:
                    msg = self.sessions[ip].decrypt(pkt.payload)
                    name = self.verified_users.get(ip, ip) # Mostrar nombre real si verificado
                    print(f"\r[{name}]: {msg}\nTú > ", end="")
                except: 
                     print("\n♻️ Renegociando..."); del self.sessions[ip]; self.connect(ip)

    # --- ACCIONES ---
    def connect(self, ip):
        s = SessionCrypto(None)
        self.sessions[ip] = s
        mk = s.get_ephemeral_public_bytes()
        # Guardamos nuestra propia clave para referencias futuras si fuera necesario
        for _ in range(3): self.proto.send_packet(ip, PORT, MSG_HELLO, 0, mk)
        self.target_ip = ip

    def accept(self, pid):
        ip = self.peers[pid]['ip']
        if ip in self.pending:
            # Guardamos su clave pública antes de borrar pending
            self.peer_static_keys[ip] = self.pending[ip]
            
            self.connect(ip)
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

    print("--- LISTO (VERIFICACIÓN SEGURA) ---")
    c.show_peers = lambda: [print(f"{k}: {v['name']} ({v['ip']})") for k,v in c.peers.items()]
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
            elif msg == "/list": c.show_peers()
            else:
                if c.target_ip:
                    enc = c.sessions[c.target_ip].encrypt(msg)
                    c.proto.send_packet(c.target_ip, PORT, MSG_DATA, 0, enc)
                    print("Tú > ", end="")
        await asyncio.sleep(0.1)

if __name__ == "__main__":
    try: asyncio.run(main())
    except: pass
