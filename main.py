import asyncio
import sys
import socket
import threading
import queue
import json
import os
import struct

from crypto import KeyManager, SessionCrypto
from protocol import ChatProtocol, MSG_HELLO, MSG_DATA, MSG_DISCOVERY

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
        
        # Gestor de claves (ahora con sesión persistente)
        try: self.km = KeyManager(name)
        except: sys.exit(1)

        self.sessions = {}        
        self.peers = {}           
        self.proto = ChatProtocol(self.on_packet)
        self.load_sessions()

    # --- PERSISTENCIA ---
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

    # --- INICIO ---
    def iniciar_dnie(self):
        """Llama al login bloqueante antes de empezar nada"""
        if not self.km.iniciar_sesion_dnie():
            print("❌ No se pudo iniciar sesión con el DNIe. Saliendo.")
            sys.exit(1)

    async def start(self):
        print(f"\n--- CHAT ACTIVO EN {self.my_ip}:{PORT} ---")
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
            try: s.sendto(msg, ("255.255.255.255", PORT))
            except: pass
            await asyncio.sleep(3)

    # --- FIRMA Y ENVÍO ---
    def iniciar_conexion_segura(self, ip):
        print(f"\n🔐 Firmando handshake con DNIe (Sesión abierta)...")
        # Ahora esto es rápido, pero usamos thread para no bloquear si el chip tarda
        threading.Thread(target=self._firmar_y_enviar, args=(ip,), daemon=True).start()

    def _firmar_y_enviar(self, ip):
        try:
            session = SessionCrypto()
            mi_clave = session.get_public_bytes()
            
            # ¡YA NO PIDE PIN! USA LA SESIÓN DEL INICIO
            cert, firma = self.km.firmar_handshake(mi_clave)
            
            if not cert: return
            
            payload = struct.pack("!I", len(cert)) + cert + \
                      struct.pack("!I", len(firma)) + firma + \
                      mi_clave
            
            self.loop.call_soon_threadsafe(
                self.proto.send_packet, ip, PORT, MSG_HELLO, 0, payload
            )
            self.sessions[ip] = session
            print("📤 Solicitud firmada enviada.")
        except Exception as e:
            print(f"❌ Error firma: {e}")

    # --- PACKETS ---
    def on_packet(self, pkt, addr):
        ip = addr[0]
        if ip == self.my_ip: return

        if pkt.msg_type == MSG_DISCOVERY:
            if ip not in [p['ip'] for p in self.peers.values()]:
                self.peers[len(self.peers)] = {'ip': ip, 'name': pkt.payload}
                print(f"\n🔭 Detectado: {pkt.payload}")

        elif pkt.msg_type == MSG_HELLO:
            print(f"\n📨 Recibido Handshake de {ip}. Verificando...")
            try:
                data = pkt.payload
                off = 0
                l_c = struct.unpack("!I", data[off:off+4])[0]; off+=4
                cert = data[off:off+l_c]; off+=l_c
                l_s = struct.unpack("!I", data[off:off+4])[0]; off+=4
                sig = data[off:off+l_s]; off+=l_s
                clave_otro = data[off:]
                
                valido, nombre = self.km.verificar_handshake(clave_otro, cert, sig)
                if not valido: return print(f"⛔ FIRMA FALSA: {nombre}")

                print(f"✅ VERIFICADO: {nombre}")
                
                # Crear sesión
                if ip in self.sessions and self.sessions[ip].cipher: # Ya teníamos sesión
                     # Renegociación: actualizamos clave
                     self.sessions[ip].compute_secret(clave_otro)
                else:
                    # Nueva sesión: Calculamos y RESPONDEMOS
                    s = SessionCrypto()
                    s.compute_secret(clave_otro)
                    self.sessions[ip] = s
                    threading.Thread(target=self._responder, args=(ip, s), daemon=True).start()
                    self.save_sessions()

            except Exception as e: print(f"❌ Error: {e}")

        elif pkt.msg_type == MSG_DATA:
            if ip in self.sessions and self.sessions[ip].cipher:
                try:
                    msg = self.sessions[ip].decrypt(pkt.payload)
                    print(f"\r[{ip}]: {msg}\nTú > ", end="")
                except: 
                    print("\n♻️ Clave caducada. Reconectando...")
                    self.iniciar_conexion_segura(ip)

    def _responder(self, ip, session):
        try:
            mi_clave = session.get_public_bytes()
            # FIRMA RÁPIDA (SIN PIN)
            cert, firma = self.km.firmar_handshake(mi_clave)
            if not cert: return
            payload = struct.pack("!I", len(cert)) + cert + \
                      struct.pack("!I", len(firma)) + firma + \
                      mi_clave
            self.loop.call_soon_threadsafe(
                self.proto.send_packet, ip, PORT, MSG_HELLO, 0, payload
            )
            print("📤 Respuesta enviada. Chat Listo.")
        except: pass

async def main():
    name = sys.argv[1] if len(sys.argv)>1 else input("Tu nombre: ")
    c = ChatClient(name)
    
    # --- AQUÍ ESTÁ EL CAMBIO IMPORTANTE ---
    # Pedimos el PIN antes de arrancar nada
    c.iniciar_dnie() 
    # --------------------------------------

    await c.start()
    
    q = queue.Queue()
    threading.Thread(target=lambda: [q.put(sys.stdin.readline().strip()) for _ in iter(int,1)], daemon=True).start()

    print("--- CHAT SEGURO (Sesión DNIe Abierta) ---")
    print("Comandos: /connect ID, /list, /quit")
    print("(Lobby) > ", end="")

    while True:
        while not q.empty():
            msg = q.get()
            if msg == "/quit": c.save_sessions(); return
            if msg.startswith("/connect"): 
                try: c.iniciar_conexion_segura(c.peers[int(msg.split()[1])]['ip'])
                except: print("ID Mal")
            elif msg == "/list": 
                 for k,v in c.peers.items(): print(f"{k}: {v['name']}")
            else:
                # Buscar sesión activa
                target = None
                for ip, s in c.sessions.items():
                    if s.cipher: target = ip; break
                
                if target:
                    enc = c.sessions[target].encrypt(msg)
                    c.proto.send_packet(target, PORT, MSG_DATA, 0, enc)
                    print("Tú > ", end="")
                else: 
                    if msg: print("⛔ No conectado.")
        await asyncio.sleep(0.1)

if __name__ == "__main__":
    try: asyncio.run(main())
    except: pass