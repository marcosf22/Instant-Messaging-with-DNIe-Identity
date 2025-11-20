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
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, x25519
from cryptography.hazmat.primitives import serialization
from zeroconf import ServiceInfo
from zeroconf.asyncio import AsyncServiceBrowser, AsyncZeroconf
from noise.connection import NoiseConnection, Keypair

# --- CONFIGURACIÓN ---
SERVICE_TYPE = "_dni-im._udp.local."
MY_PORT = 443
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
#  GESTIÓN HARDWARE (DNIe)
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
    """Espera lector y tarjeta. Usa PIN cacheado o pide uno nuevo."""
    global CACHED_PIN
    
    # 1. Esperar Lector
    while True:
        l = readers()
        if l: 
            # print(f"\r[DNIe] Lector: {l[0]}", end='')
            break
        print("[DNIe] Conecta el lector...", end='\r')
        time.sleep(1)

    # 2. Esperar Tarjeta
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

    # 3. Abrir Sesión
    session = pkcs11_lib.openSession(slot)
    
    # 4. Login (Reusar PIN si existe)
    try:
        if not CACHED_PIN:
            CACHED_PIN = getpass.getpass("\n[PIN] Introduce el PIN del DNIe: ")
        session.login(CACHED_PIN)
        return session
    except Exception as e:
        print(f"\n[!] Error de Login (PIN incorrecto?): {e}")
        CACHED_PIN = None # Resetear PIN si falló
        raise e

def extraer_certificado():
    """Carga certificado del DNIe y lo guarda en variable global."""
    global MI_CERT_DER
    
    # Si ya tenemos el archivo, cargarlo rápido
    if os.path.exists("certificado.der"):
        print("[init] Cargando 'certificado.der' del disco...")
        with open("certificado.der", "rb") as f:
            MI_CERT_DER = f.read()
            
        # [NUEVO] Forzar verificación de PIN aunque tengamos el certificado
        print("[init] Verificando titularidad (PIN)...")
        lib = cargar_driver()
        try:
            session = iniciar_sesion_bloqueante(lib)
            session.logout()
            session.closeSession()
        except Exception as e:
            print(f"Error de autenticación: {e}")
            sys.exit(1)
            
        return

    # Si no, leerlo del DNIe
    print("[init] Leyendo certificado del DNIe (esto tarda un poco)...")
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
        print(f"Error extrayendo certificado: {e}")
        sys.exit(1)

def firmar_bloqueante(data):
    """Firma datos usando el hardware. Se ejecuta en un hilo aparte."""
    lib = cargar_driver()
    session = None
    try:
        session = iniciar_sesion_bloqueante(lib)
        
        # Buscar clave privada de firma
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
        print(f"\n[!] Error firmando: {e}")
        return None
    finally:
        if session: session.closeSession()

async def firmar_async(data):
    """Wrapper para no bloquear el bucle de eventos principal."""
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
#  LÓGICA DE SESIÓN (NOISE)
# ==============================================================================
def generar_claves_noise():
    priv = x25519.X25519PrivateKey.generate()
    priv_b = priv.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
    pub_b = priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return priv_b, pub_b

class SecureSession:
    def __init__(self, priv, remote_pub=None):
        self.proto = NoiseConnection.from_name(NOISE_PROTOCOL)
        self.proto.set_keypair_from_private_bytes(Keypair.STATIC, priv)
        if remote_pub: self.proto.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, remote_pub)
        self.handshake_done = False
        self.cipher_tx = None
        self.cipher_rx = None
        self.local_cid = os.urandom(4)
        self.remote_cid = None

    async def _build_payload(self):
        mi_static = self.proto.handshake_state.s.public_bytes
        firma = await firmar_async(mi_static) # ASÍNCRONO
        if not firma: raise Exception("Fallo Firma")
        return self.local_cid + struct.pack('!H', len(MI_CERT_DER)) + MI_CERT_DER + firma

    async def start_handshake(self):
        self.proto.set_as_initiator()
        self.proto.start_handshake()
        pl = await self._build_payload()
        return self.proto.write_message(pl)

    async def process_packet(self, data):
        if self.handshake_done: return None
        if not self.proto.handshake_started:
            self.proto.set_as_responder()
            self.proto.start_handshake()

        try:
            full = self.proto.read_message(data)
            if len(full) < 8: raise Exception("Payload corto")
            
            self.remote_cid = full[:4]
            l_c = struct.unpack('!H', full[4:6])[0]
            cert_rem = full[6 : 6+l_c]
            firma_rem = full[6+l_c :]
            
            rem_static = self.proto.handshake_state.rs.public_bytes
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
#  RED Y MAIN
# ==============================================================================
class DNIeTransport(asyncio.DatagramProtocol):
    def __init__(self, mgr): self.mgr = mgr; self.transport = None
    def connection_made(self, tr): self.transport = tr; print(f"[✓] UDP 443 Activo")
    
    def datagram_received(self, data, addr):
        asyncio.create_task(self._handle(data, addr))

    async def _handle(self, data, addr):
        if len(data) < 4: return
        cid = data[:4]
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
        if info and info.properties.get(b'pk'):
            self.peers[name] = {'ip': socket.inet_ntoa(info.addresses[0]), 'pk': binascii.unhexlify(info.properties[b'pk'])}
            print(f"\n[+] Usuario: {name}\n>> ", end='', flush=True)
    def remove_service(self, *args): pass
    def update_service(self, *args): pass

async def main():
    print("--- INICIANDO SISTEMA DNIe ---")
    
    # 1. Cargar Certificado (Bloqueante, pero necesario al inicio)
    extraer_certificado()
    
    # 2. Generar Claves
    my_priv, my_pub = generar_claves_noise()
    
    # 3. IP
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: s.connect(('8.8.8.8', 1)); my_ip = s.getsockname()[0]
    except: my_ip = '127.0.0.1'
    finally: s.close()
    
    my_name = f"User-{my_ip.replace('.', '-')}.{SERVICE_TYPE}"
    
    # 4. Iniciar Red
    mgr = SessionManager(my_priv)
    peers = {}
    loop = asyncio.get_running_loop()
    
    try:
        tr, pr = await loop.create_datagram_endpoint(lambda: DNIeTransport(mgr), local_addr=('0.0.0.0', MY_PORT))
    except PermissionError:
        print("[!] EJECUTA COMO ADMIN (Puerto 443)"); return

    aiozc = AsyncZeroconf()
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
                pk = next((p['pk'] for p in peers.values() if p['ip'] == parts[1]), None)
                if pk:
                    print("Firmando handshake...")
                    sess = mgr.get_initiator((parts[1], MY_PORT), pk)
                    pkt = await sess.start_handshake()
                    tr.sendto(pkt, (parts[1], MY_PORT))
                else: print("Peer desconocido")
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