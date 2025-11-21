import asyncio
import socket
import logging
import binascii
import struct
import os
import sys
import getpass
import time
from smartcard.System import readers

# Librerías criptográficas auxiliares
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, x25519
from cryptography.hazmat.primitives import serialization

# Zeroconf para descubrimiento (mDNS)
from zeroconf import ServiceInfo
from zeroconf.asyncio import AsyncServiceBrowser, AsyncZeroconf

# --- AQUÍ ESTÁ LA LIBRERÍA NOISE (OBLIGATORIA) ---
from noise.connection import NoiseConnection, Keypair

# --- CONFIGURACIÓN ---
SERVICE_TYPE = "_dni-im._udp.local." # [cite: 7]
MY_PORT = 443                        # [cite: 7, 11]
# Protocolo Noise IK requerido por el enunciado 
NOISE_PROTOCOL = b'Noise_IK_25519_ChaChaPoly_BLAKE2s'

# AJUSTA ESTA RUTA A TU INSTALACIÓN DE OPENSC
LIB_PATH = r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"

# Variables Globales para caché
MI_CERT_DER = None
CACHED_PIN = None

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("DNIe-Client")

# Intenta importar PyKCS11
try:
    import PyKCS11
except ImportError:
    print("ERROR: Instala PyKCS11 (pip install PyKCS11)")
    sys.exit(1)

# ==============================================================================
#  GESTIÓN HARDWARE (DNIe) [cite: 6, 63]
# ==============================================================================
def cargar_driver():
    pkcs11 = PyKCS11.PyKCS11Lib()
    try:
        pkcs11.load(LIB_PATH)
    except Exception as e:
        print(f"Error cargando DLL ({LIB_PATH}): {e}")
        sys.exit(1)
    return pkcs11

def iniciar_sesion_bloqueante(pkcs11_lib):
    global CACHED_PIN
    while True:
        l = readers()
        if l: break
        print("[DNIe] Conecta el lector...", end='\r')
        time.sleep(1)

    slot = None
    while True:
        try:
            slots = pkcs11_lib.getSlotList(tokenPresent=True)
            if slots:
                slot = slots[0]
                break
        except: pass
        print("[DNIe] Inserta la tarjeta...", end='\r')
        time.sleep(1)

    session = pkcs11_lib.openSession(slot)
    try:
        if not CACHED_PIN:
            CACHED_PIN = getpass.getpass("\n[PIN] Introduce el PIN del DNIe: ")
        session.login(CACHED_PIN)
        return session
    except Exception as e:
        print(f"\n[!] Error de Login: {e}")
        CACHED_PIN = None
        raise e

def extraer_certificado():
    global MI_CERT_DER
    if os.path.exists("certificado.der"):
        print("[init] Cargando 'certificado.der' del disco...")
        with open("certificado.der", "rb") as f:
            MI_CERT_DER = f.read()
        # Verificar PIN aunque esté cacheado para asegurar presencia 
        print("[init] Verificando titularidad (PIN)...")
        lib = cargar_driver()
        try:
            session = iniciar_sesion_bloqueante(lib)
            session.logout()
            session.closeSession()
        except Exception as e:
            print(f"Error: {e}"); sys.exit(1)
        return

    print("[init] Leyendo certificado del DNIe...")
    lib = cargar_driver()
    try:
        session = iniciar_sesion_bloqueante(lib)
        objs = session.findObjects([
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
            (PyKCS11.CKA_CERTIFICATE_TYPE, PyKCS11.CKC_X_509)
        ])
        if not objs: raise Exception("No hay certificados")
        MI_CERT_DER = bytes(objs[0].to_dict()['CKA_VALUE'])
        session.logout()
        session.closeSession()
    except Exception as e:
        print(f"Error: {e}"); sys.exit(1)

def firmar_bloqueante(data):
    lib = cargar_driver()
    session = None
    try:
        session = iniciar_sesion_bloqueante(lib)
        keys = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])
        target_key = keys[0]
        for k in keys:
            try:
                label = session.getAttributeValue(k, [PyKCS11.CKA_LABEL])[0]
                if "Firma" in label: target_key = k; break
            except: pass
        
        mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
        sig = bytes(session.sign(target_key, data, mech))
        session.logout()
        return sig
    except Exception as e:
        print(f"\n[!] Error firmando: {e}"); return None
    finally:
        if session: session.closeSession()

async def firmar_async(data):
    loop = asyncio.get_running_loop()
    print("\n[DNIe] Firmando handshake...", end='', flush=True)
    sig = await loop.run_in_executor(None, firmar_bloqueante, data)
    print(" Hecho.")
    return sig

def verificar(cert_bytes, firma, datos):
    try:
        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
        cert.public_key().verify(firma, datos, padding.PKCS1v15(), hashes.SHA256())
        cn = "Desconocido"
        for attr in cert.subject:
            if attr.oid == x509.NameOID.COMMON_NAME: cn = attr.value
        return True, cn
    except:
        return False, None

# ==============================================================================
#  LÓGICA DE SESIÓN (NOISE) - CORREGIDA
# ==============================================================================
def generar_claves_noise():
    # Generamos claves compatibles con Curve25519 (usadas por Noise)
    priv = x25519.X25519PrivateKey.generate()
    priv_b = priv.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
    pub_b = priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return priv_b, pub_b

class SecureSession:
    def __init__(self, priv, remote_pub=None):
        # 1. INICIALIZAMOS LA LIBRERÍA NOISE [cite: 8]
        self.proto = NoiseConnection.from_name(NOISE_PROTOCOL)
        
        # 2. CARGAMOS NUESTRA CLAVE PRIVADA EN NOISE
        self.proto.set_keypair_from_private_bytes(Keypair.STATIC, priv)
        
        if remote_pub: 
            self.proto.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, remote_pub)
        
        # Guardamos nuestra clave PÚBLICA (calculada desde la privada 'priv')
        # para poder firmarla con el DNIe y enviarla en el payload.
        # ESTA ES LA CORRECCIÓN: No intentamos leerla de self.proto._handshake...
        # porque esa variable es privada/inaccesible de esa forma.
        tmp_priv = x25519.X25519PrivateKey.from_private_bytes(priv)
        self.my_static_public = tmp_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, 
            format=serialization.PublicFormat.Raw
        )

        self.handshake_done = False
        self.cipher_tx = None
        self.cipher_rx = None
        self.local_cid = os.urandom(4) # Connection ID [cite: 11]
        self.remote_cid = None

    async def _build_payload(self):
        # Usamos nuestra clave pública estática para firmarla
        mi_static = self.my_static_public
        
        # Firma de la clave pública estática con DNIe [cite: 65]
        firma = await firmar_async(mi_static) 
        if not firma: raise Exception("Fallo Firma")
        
        # Payload: CID + Longitud Cert + Certificado + Firma
        return self.local_cid + struct.pack('!H', len(MI_CERT_DER)) + MI_CERT_DER + firma

    async def start_handshake(self):
        # Usamos métodos nativos de Noise para iniciar
        self.proto.set_as_initiator()
        self.proto.start_handshake()
        
        # Creamos el payload firmado
        pl = await self._build_payload()
        
        # Noise escribe el mensaje inicial + nuestro payload
        return self.proto.write_message(pl)

    async def process_packet(self, data):
        if self.handshake_done: return None
        if not self.proto.handshake_started:
            self.proto.set_as_responder()
            self.proto.start_handshake()

        try:
            # Noise procesa el mensaje entrante
            full = self.proto.read_message(data)
            
            # Decodificamos el payload recibido (CID, Cert, Firma)
            if len(full) < 8: raise Exception("Payload corto")
            self.remote_cid = full[:4]
            l_c = struct.unpack('!H', full[4:6])[0]
            cert_rem = full[6 : 6+l_c]
            firma_rem = full[6+l_c :]
            
            # Obtenemos la clave pública remota que Noise ha extraído del handshake
            # NOTA: Aquí SÍ podemos usar rs (remote static) si el handshake avanzó,
            # pero es más seguro confiar en la que noise ya ha validado criptográficamente.
            rem_static = self.proto.noise_protocol.handshake_state.rs.public_bytes
            
            # Verificar identidad del peer [cite: 65]
            ok, name = verificar(cert_rem, firma_rem, rem_static)
            if not ok: raise Exception("Firma Inválida")
            
            logger.info(f"Verificado: {name}")

            if self.proto.handshake_finished:
                self.cipher_tx, self.cipher_rx = self.proto.transition()
                self.handshake_done = True
                return True
            
            resp = await self._build_payload()
            return self.proto.write_message(resp)

        except Exception as e:
            logger.error(f"Error HS: {e}")
            return None

    def encrypt(self, msg):
        # Cifrado post-handshake con ChaCha20-Poly1305 (manejado por Noise) [cite: 8]
        return self.remote_cid + self.cipher_tx.encrypt(msg.encode())

    def decrypt(self, data):
        return self.cipher_rx.decrypt(data).decode()

class SessionManager:
    def __init__(self, priv):
        self.priv = priv
        self.s_cid = {}
        self.s_addr = {}

    def get_initiator(self, addr, pk):
        s = SecureSession(self.priv, pk)
        self.s_addr[addr] = s; self.s_cid[s.local_cid] = s
        return s

    def get_responder(self, addr):
        s = SecureSession(self.priv)
        self.s_addr[addr] = s; self.s_cid[s.local_cid] = s
        return s

    def find_cid(self, cid): return self.s_cid.get(cid)
    def find_addr(self, addr): return self.s_addr.get(addr)

# ==============================================================================
#  RED Y MAIN [cite: 66]
# ==============================================================================
class DNIeTransport(asyncio.DatagramProtocol):
    def __init__(self, mgr): self.mgr = mgr; self.transport = None
    def connection_made(self, tr): self.transport = tr; print(f"[✓] UDP 443 Activo")
    
    def datagram_received(self, data, addr):
        asyncio.create_task(self._handle(data, addr))

    async def _handle(self, data, addr):
        if len(data) < 4: return
        cid = data[:4] # [cite: 11]
        sess = self.mgr.find_cid(cid)

        if sess and sess.handshake_done:
            try:
                txt = sess.decrypt(data[4:])
                print(f"\n[MSG] {addr[0]}: {txt}\n>> ", end='', flush=True)
            except: pass
        else:
            if not sess:
                sess = self.mgr.find_addr(addr)
                if not sess: sess = self.mgr.get_responder(addr)
            
            res = await sess.process_packet(data)
            if isinstance(res, bytes): self.transport.sendto(res, addr)
            elif res is True: print(f"\n[★] CONEXIÓN OK: {addr}\n>> ", end='', flush=True)

class DiscoveryListener:
    def __init__(self, me, peers): self.me = me; self.peers = peers
    def add_service(self, zc, type, name):
        if name == self.me: return
        asyncio.create_task(self._proc(zc, type, name))
    async def _proc(self, zc, type, name):
        info = await zc.async_get_service_info(type, name)
        # Descubrimiento via mDNS [cite: 7]
        if info and info.properties.get(b'pk'):
            self.peers[name] = {'ip': socket.inet_ntoa(info.addresses[0]), 'pk': binascii.unhexlify(info.properties[b'pk'])}
            print(f"\n[+] Usuario: {name}\n>> ", end='', flush=True)
    def remove_service(self, *args): pass
    def update_service(self, *args): pass

async def main():
    print("--- INICIANDO SISTEMA DNIe ---")
    extraer_certificado()
    my_priv, my_pub = generar_claves_noise()
    
    # Determinar IP Local
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: s.connect(('8.8.8.8', 1)); my_ip = s.getsockname()[0]
    except: my_ip = '127.0.0.1'
    finally: s.close()
    
    my_name = f"User-{my_ip.replace('.', '-')}.{SERVICE_TYPE}"
    
    mgr = SessionManager(my_priv)
    peers = {}
    loop = asyncio.get_running_loop()
    
    # Puerto UDP 443 [cite: 7]
    try:
        tr, pr = await loop.create_datagram_endpoint(lambda: DNIeTransport(mgr), local_addr=('0.0.0.0', MY_PORT))
    except PermissionError:
        print("[!] EJECUTA COMO ADMIN (Puerto 443)"); return

    aiozc = AsyncZeroconf()
    # Publicar servicio mDNS [cite: 7]
    info = ServiceInfo(SERVICE_TYPE, my_name, addresses=[socket.inet_aton(my_ip)], port=MY_PORT, properties={b'pk': binascii.hexlify(my_pub), b'version': '1.0'})
    await aiozc.async_register_service(info)
    AsyncServiceBrowser(aiozc.zeroconf, SERVICE_TYPE, listener=DiscoveryListener(my_name, peers))

    print(f"Identidad: {my_name} | IP: {my_ip}")
    print("Comandos: lista, conectar <IP>, msg <IP> <txt>, salir")

    try:
        while True:
            cmd = await loop.run_in_executor(None, input, ">> ")
            parts = cmd.split()
            if not parts: continue
            act = parts[0].lower()

            if act == "lista":
                for n, p in peers.items(): print(f" - {n} ({p['ip']})")
                if not peers: print(" No hay peers disponibles.")
            elif act == "conectar":
                if len(parts)<2: continue
                # Se busca la clave pública del peer (anunciada en mDNS)
                pk = next((p['pk'] for p in peers.values() if p['ip'] == parts[1]), None)
                if pk:
                    print("Firmando handshake...")
                    sess = mgr.get_initiator((parts[1], MY_PORT), pk)
                    pkt = await sess.start_handshake() # Inicia handshake Noise IK [cite: 8]
                    tr.sendto(pkt, (parts[1], MY_PORT))
                else: print("Peer desconocido (espera a que aparezca en mDNS)")
            elif act == "msg":
                if len(parts)<3: continue
                sess = next((s for s in mgr.s_cid.values() if mgr.s_addr.get((parts[1], MY_PORT)) == s), None)
                if sess and sess.handshake_done:
                    tr.sendto(sess.encrypt(" ".join(parts[2:])), (parts[1], MY_PORT))
                    print("Enviado.")
                else: print("No conectado")
            elif act == "salir": break
    finally:
        await aiozc.async_close()
        tr.close()

if __name__ == "__main__":
    if hasattr(asyncio, 'WindowsSelectorEventLoopPolicy'):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try: asyncio.run(main())
    except KeyboardInterrupt: pass