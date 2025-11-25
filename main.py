import asyncio
import sys
import socket
import threading
import queue
import struct

from crypto import KeyManager, SessionCrypto
from protocol import ChatProtocol, MSG_HELLO, MSG_DATA, MSG_DISCOVERY

PORT = 8888 

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
        
        self.km = KeyManager(name)
        self.sessions = {}        
        self.peers = {}           
        self.proto = ChatProtocol(self.on_packet)

    async def start(self):
        print(f"--- CHAT DNIe SEGURO EN {self.my_ip}:{PORT} ---")
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

    # --- LÓGICA DE FIRMA EN HILO APARTE (Para no congelar red) ---
    def _firmar_y_enviar_hello(self, ip_destino):
        """Esta función se ejecuta en segundo plano para pedir el PIN"""
        try:
            # 1. Crear sesión criptográfica temporal
            session = SessionCrypto()
            mi_clave_temp = session.get_public_bytes()
            
            # 2. FIRMAR CON DNIe (Bloqueante)
            # Pedirá el PIN aquí
            cert, firma = self.km.firmar_handshake(mi_clave_temp)
            
            if not cert or not firma:
                print("❌ Cancelado por usuario.")
                return

            # 3. Empaquetar: [LenCert + Cert + LenFirma + Firma + ClaveTemp]
            payload = struct.pack("!I", len(cert)) + cert + \
                      struct.pack("!I", len(firma)) + firma + \
                      mi_clave_temp
            
            # 4. Enviar
            # Usamos call_soon_threadsafe para volver al hilo principal y enviar
            self.loop.call_soon_threadsafe(
                self.proto.send_packet, ip_destino, PORT, MSG_HELLO, 0, payload
            )
            
            # 5. Guardar sesión pendiente (esperando respuesta o confirmación)
            # Como estamos en otro hilo, protegemos el acceso al dict
            self.sessions[ip_destino] = session 
            print("📤 Handshake firmado enviado. Esperando verificación del otro...")
            
        except Exception as e:
            print(f"❌ Error firmando: {e}")

    def iniciar_conexion_segura(self, ip):
        print(f"\n🔐 Iniciando Handshake con {ip}...")
        print("⚠️ Prepara tu DNIe. Se abrirá la petición de PIN.")
        # Ejecutamos la firma en un hilo para no bloquear el chat
        threading.Thread(target=self._firmar_y_enviar_hello, args=(ip,), daemon=True).start()


    # --- RECEPCIÓN DE PAQUETES ---
    def on_packet(self, pkt, addr):
        ip = addr[0]
        if ip == self.my_ip: return

        if pkt.msg_type == MSG_DISCOVERY:
            if ip not in [p['ip'] for p in self.peers.values()]:
                self.peers[len(self.peers)] = {'ip': ip, 'name': pkt.payload}
                print(f"\n🔭 Encontrado: {pkt.payload} ({ip})")

        elif pkt.msg_type == MSG_HELLO:
            # ALGUIEN NOS MANDA SU CLAVE FIRMADA
            print(f"\n📨 Recibido Handshake firmado de {ip}. Verificando...")
            
            # 1. Desempaquetar
            try:
                data = pkt.payload
                off = 0
                l_cert = struct.unpack("!I", data[off:off+4])[0]; off+=4
                cert = data[off:off+l_cert]; off+=l_cert
                l_sig = struct.unpack("!I", data[off:off+4])[0]; off+=4
                sig = data[off:off+l_sig]; off+=l_sig
                clave_temp_otro = data[off:]
                
                # 2. VERIFICAR FIRMA
                valido, nombre_dnie = self.km.verificar_handshake(clave_temp_otro, cert, sig)
                
                if not valido:
                    print(f"⛔ ALERTA: Firma inválida de {ip}. Error: {nombre_dnie}")
                    return

                print(f"✅ IDENTIDAD VERIFICADA: {nombre_dnie}")
                print(f"   (El DNIe confirma que esta clave es suya)")

                # 3. Establecer Sesión
                # Si yo inicié (ya tengo sesión creada), calculo secreto
                if ip in self.sessions and self.sessions[ip].cipher is None:
                    self.sessions[ip].compute_secret(clave_temp_otro)
                    print(f"🤝 Canal cifrado establecido con {nombre_dnie}")
                
                # Si yo soy el receptor (no tengo sesión), debo RESPONDER
                elif ip not in self.sessions:
                    print(f"👉 Debes responder para completar la conexión.")
                    # Aceptamos automáticamente la parte criptográfica
                    s = SessionCrypto()
                    s.compute_secret(clave_temp_otro)
                    self.sessions[ip] = s
                    
                    # PERO AHORA DEBO FIRMAR MI CLAVE PARA ENVIARSELA
                    print("⚠️ Te toca firmar tu parte. Introduce PIN...")
                    threading.Thread(target=self._responder_handshake, args=(ip, s), daemon=True).start()

            except Exception as e:
                print(f"❌ Error procesando handshake: {e}")

        elif pkt.msg_type == MSG_DATA:
            if ip in self.sessions and self.sessions[ip].cipher:
                try:
                    msg = self.sessions[ip].decrypt(pkt.payload)
                    print(f"\r[{ip}]: {msg}\nTú > ", end="")
                except: print("\n⚠️ Error desencriptando.")

    def _responder_handshake(self, ip, session):
        # Función auxiliar para responder (similar a iniciar pero con la sesión ya creada)
        try:
            mi_clave = session.get_public_bytes()
            cert, firma = self.km.firmar_handshake(mi_clave)
            if not cert: return
            
            payload = struct.pack("!I", len(cert)) + cert + \
                      struct.pack("!I", len(firma)) + firma + \
                      mi_clave
            
            self.loop.call_soon_threadsafe(
                self.proto.send_packet, ip, PORT, MSG_HELLO, 0, payload
            )
            print("📤 Respuesta firmada enviada. Chat Listo.")
        except: pass

async def main():
    c = ChatClient("Yo")
    await c.start()
    
    q = queue.Queue()
    threading.Thread(target=lambda: [q.put(sys.stdin.readline().strip()) for _ in iter(int,1)], daemon=True).start()

    print("--- CHAT DNIe (PIN REQUERIDO EN CADA CONEXIÓN) ---")
    print("Usa: /connect ID")
    print("(Lobby) > ", end="")

    while True:
        while not q.empty():
            msg = q.get()
            if msg.startswith("/connect"): 
                try: 
                    pid = int(msg.split()[1])
                    c.iniciar_conexion_segura(c.peers[pid]['ip'])
                except: print("ID Mal")
            elif msg == "/list": 
                 for k,v in c.peers.items(): print(f"{k}: {v['name']}")
            else:
                # Enviar chat si hay sesión activa (primer peer encontrado con cipher)
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