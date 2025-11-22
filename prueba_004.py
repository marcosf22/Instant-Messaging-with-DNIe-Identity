import asyncio
import socket
import logging
import struct
import os
import sys
import getpass
import time
import datetime
import traceback

# --- LIBRERÍAS CRIPTOGRÁFICAS ---
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, x25519, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

# --- LIBRERÍA NOISE ---
from noise.connection import NoiseConnection, Keypair

# ==============================================================================
#  CONFIGURACIÓN DEL MODO DE USO
# ==============================================================================
# [!!!] CAMBIA ESTO A 'True' PARA PROBAR SIN DNIe FÍSICO
MODO_SIMULACION = True 

NOISE_PROTOCOL = b'Noise_XX_25519_ChaChaPoly_BLAKE2s'
MY_PORT = 55555 
LIB_PATH = r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"

# Variables Globales
MI_CERT_DER = None
MI_KEY_ID = None   
CACHED_PIN = None
MOCK_PRIVATE_KEY = None # Se usará solo en modo simulación

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("DNIe-Client")

# Importación condicional de PyKCS11 (Para que no falle si no tienes la librería en casa)
if not MODO_SIMULACION:
    try:
        import PyKCS11
        from smartcard.System import readers
    except ImportError:
        print("ERROR: Instala PyKCS11 (pip install PyKCS11) o activa MODO_SIMULACION")
        sys.exit(1)

# ==============================================================================
#  1. GENERADOR DE IDENTIDAD FALSA (SOLO PARA SIMULACIÓN)
# ==============================================================================
def generar_identidad_simulada():
    """Genera un par de claves RSA y un certificado X.509 autofirmado al vuelo."""
    print("[SIM] Generando claves RSA falsas y certificado de prueba...")
    
    # 1. Generar clave privada RSA (Simulando la del chip del DNIe)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    
    # 2. Crear un certificado autofirmado
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"USUARIO SIMULADO SIN DNI"),
    ])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=1)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(key, hashes.SHA256(), default_backend())
    
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    
    return cert_der, key

# ==============================================================================
#  2. GESTIÓN DE IDENTIDAD (Abstracta: Real o Simulada)
# ==============================================================================
def extraer_certificado():
    """Carga el certificado. Si es simulación lo genera, si es real lee el chip."""
    global MI_CERT_DER, MI_KEY_ID, MOCK_PRIVATE_KEY
    
    if MODO_SIMULACION:
        MI_CERT_DER, MOCK_PRIVATE_KEY = generar_identidad_simulada()
        print("[SIM] Identidad cargada en memoria RAM.")
        return

    # --- LÓGICA REAL (DNIe) ---
    print("[init] Leyendo DNIe REAL...")
    pkcs11 = PyKCS11.PyKCS11Lib()
    try: pkcs11.load(LIB_PATH)
    except: print(f"Error DLL {LIB_PATH}"); sys.exit(1)

    # Esperar lector
    while True:
        try: 
            if readers(): break
        except: pass
        print("[DNIe] Esperando lector...", end='\r'); time.sleep(1)

    # Slot y Login
    slot = pkcs11.getSlotList(tokenPresent=True)[0]
    session = pkcs11.openSession(slot)
    
    global CACHED_PIN
    if not CACHED_PIN: CACHED_PIN = getpass.getpass("\n[PIN] DNIe: ")
    try: session.login(CACHED_PIN)
    except: CACHED_PIN=None; raise Exception("PIN Incorrecto")

    # Buscar Certificado Firma
    objs = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE), (PyKCS11.CKA_CERTIFICATE_TYPE, PyKCS11.CKC_X_509)])
    target = None
    for o in objs:
        lbl = o.to_dict().get('CKA_LABEL', b'').decode('utf-8', errors='ignore')
        if "Firma" in lbl or "Sign" in lbl: target = o; break
    if not target: target = objs[0]

    attrs = session.getAttributeValue(target, [PyKCS11.CKA_VALUE, PyKCS11.CKA_ID])
    MI_CERT_DER = bytes(attrs[0])
    MI_KEY_ID = attrs[1]
    
    print(f"[DNIe] ID Clave Real: {bytes(MI_KEY_ID).hex()}")
    session.logout(); session.closeSession()

def firmar_bloqueante(data):
    """Firma los datos. Si es simulación usa la clave en RAM, si es real usa el chip."""
    
    # --- CAMINO SIMULADO ---
    if MODO_SIMULACION:
        # Usamos la clave RSA generada por software
        signature = MOCK_PRIVATE_KEY.sign(
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return signature

    # --- CAMINO REAL ---
    pkcs11 = PyKCS11.PyKCS11Lib()
    pkcs11.load(LIB_PATH)
    
    # Login rápido (asumiendo lector conectado)
    try:
        slot = pkcs11.getSlotList(tokenPresent=True)[0]
        session = pkcs11.openSession(slot)
        session.login(CACHED_PIN)
        
        keys = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY), (PyKCS11.CKA_ID, MI_KEY_ID)])
        if not keys: raise Exception("Clave privada no encontrada")
        
        mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
        sig = bytes(session.sign(keys[0], data, mech))
        session.logout(); session.closeSession()
        return sig
    except Exception as e:
        print(f"[!] Error firma hardware: {e}"); return None

async def firmar_async(data):
    loop = asyncio.get_running_loop()
    modo = "SIMULADO" if MODO_SIMULACION else "HARDWARE"
    print(f"\n[{modo}] Firmando...", end='', flush=True)
    sig = await loop.run_in_executor(None, firmar_bloqueante, data)
    print(" OK.")
    return sig

def verificar(cert_bytes, firma, datos):
    try:
        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
        cert.public_key().verify(firma, datos, padding.PKCS1v15(), hashes.SHA256())
        cn = "Desconocido"
        for attr in cert.subject:
            if attr.oid == NameOID.COMMON_NAME: cn = attr.value
        return True, cn
    except: return False, None

# ==============================================================================
#  3. PROTOCOLO DE RED Y NOISE (IGUAL QUE ANTES)
# ==============================================================================
class SecureSession:
    def __init__(self, priv):
        self.proto = NoiseConnection.from_name(NOISE_PROTOCOL)
        self.proto.set_keypair_from_private_bytes(Keypair.STATIC, priv)
        
        tmp_priv = x25519.X25519PrivateKey.from_private_bytes(priv)
        self.my_static_public = tmp_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        self.handshake_done = False
        self.cipher_tx = None; self.cipher_rx = None
        self.local_cid = os.urandom(4)
        self.remote_cid = None
        self.is_initiator = False

    async def _build_payload(self):
        firma = await firmar_async(self.my_static_public)
        if not firma: raise Exception("Fallo Firma")
        return self.local_cid + struct.pack('!H', len(MI_CERT_DER)) + MI_CERT_DER + firma

    async def _verify_payload(self, payload):
        if len(payload) < 8: raise Exception("Payload corto")
        self.remote_cid = payload[:4]
        l_c = struct.unpack('!H', payload[4:6])[0]
        cert_rem = payload[6 : 6+l_c]
        firma_rem = payload[6+l_c :]
        rem_static = self.proto.keypairs[Keypair.REMOTE_STATIC].public_bytes
        
        ok, name = verificar(cert_rem, firma_rem, rem_static)
        if not ok: raise Exception("FIRMA INVÁLIDA")
        logger.info(f"Identidad Verificada: {name}")
        return True

    async def start_handshake(self):
        self.is_initiator = True
        self.proto.set_as_initiator()
        self.proto.start_handshake()
        return self.proto.write_message()

    async def process_packet(self, data):
        if self.handshake_done: return None 
        if not self.is_initiator and not self.proto.handshake_started:
            self.proto.set_as_responder()
            self.proto.start_handshake()

        try:
            payload_rx = self.proto.read_message(data)
            if payload_rx: await self._verify_payload(payload_rx)

            if self.proto.handshake_finished:
                self.cipher_tx, self.cipher_rx = self.proto.transition()
                self.handshake_done = True
                return True
            
            payload_tx = b''
            if (not self.is_initiator) or (self.is_initiator and len(payload_rx) > 0):
                 payload_tx = await self._build_payload()
            return self.proto.write_message(payload_tx)
        except Exception as e:
            if "InvalidTag" in str(e): logger.error("Desincronización (InvalidTag).")
            else: logger.error(f"Error HS: {e}")
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

    def reset_session(self, addr):
        if addr in self.s_addr:
            print(f"[!] Reset sesión {addr[0]}")
            old = self.s_addr[addr]
            if old.local_cid in self.s_cid: del self.s_cid[old.local_cid]
            del self.s_addr[addr]

    def get_initiator(self, addr):
        if addr in self.s_addr: return self.s_addr[addr]
        s = SecureSession(self.priv)
        self.s_addr[addr] = s; self.s_cid[s.local_cid] = s
        return s

    def get_responder(self, addr):
        if addr in self.s_addr: return self.s_addr[addr]
        s = SecureSession(self.priv)
        self.s_addr[addr] = s; self.s_cid[s.local_cid] = s
        return s

    def find_cid(self, cid): return self.s_cid.get(cid)
    def find_addr(self, addr): return self.s_addr.get(addr)

class DNIeTransport(asyncio.DatagramProtocol):
    def __init__(self, mgr): self.mgr = mgr; self.transport = None
    def connection_made(self, tr): self.transport = tr; print(f"[✓] Escuchando UDP {MY_PORT}")
    
    def datagram_received(self, data, addr):
        print(f"[RED] Recibido {len(data)} bytes de {addr[0]}")
        asyncio.create_task(self._handle(data, addr))

    async def _handle(self, data, addr):
        if len(data) < 4: return 
        
        # DETECCIÓN DE RESET (32 bytes = Handshake Init)
        if len(data) == 32:
            self.mgr.reset_session(addr)

        sess = self.mgr.find_cid(data[:4])
        if sess and sess.handshake_done:
            try:
                print(f"\n[MSG] {addr[0]}: {sess.decrypt(data[4:])}\n>> ", end='', flush=True)
            except: pass
        else:
            sess = self.mgr.find_addr(addr)
            if not sess: sess = self.mgr.get_responder(addr)
            
            res = await sess.process_packet(data)
            if isinstance(res, bytes): self.transport.sendto(res, addr)
            elif res is True: print(f"\n[★] CONEXIÓN OK: {addr[0]}\n>> ", end='', flush=True)

async def main():
    modo_txt = "SIMULADO (Sin tarjeta)" if MODO_SIMULACION else "REAL (Con DNIe)"
    print(f"--- CHAT DNIe: MODO {modo_txt} ---")
    
    extraer_certificado()
    
    # Self Test
    test_data = b"TEST"
    firma = firmar_bloqueante(test_data)
    if verificar(MI_CERT_DER, firma, test_data)[0]:
        print("✅ Autocomprobación: OK")
    else:
        print("❌ Autocomprobación: FALLO. Certificado/Clave no coinciden."); return

    # Noise Keys
    priv = x25519.X25519PrivateKey.generate()
    priv_b = priv.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
    
    mgr = SessionManager(priv_b)
    loop = asyncio.get_running_loop()
    
    try:
        tr, pr = await loop.create_datagram_endpoint(lambda: DNIeTransport(mgr), local_addr=('0.0.0.0', MY_PORT))
    except Exception as e:
        print(f"Error puerto: {e}"); return

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: s.connect(('8.8.8.8', 1)); my_ip = s.getsockname()[0]
    except: my_ip = '127.0.0.1'
    finally: s.close()
    
    print(f"Mi IP: {my_ip}")
    print("Comandos: conectar <IP>, msg <IP> <txt>, salir")

    try:
        while True:
            cmd = await loop.run_in_executor(None, input, ">> ")
            parts = cmd.split()
            if not parts: continue
            act = parts[0].lower()

            if act == "conectar" and len(parts) >= 2:
                mgr.reset_session((parts[1], MY_PORT))
                print(f"Conectando a {parts[1]}...")
                sess = mgr.get_initiator((parts[1], MY_PORT))
                try:
                    pkt = await sess.start_handshake()
                    tr.sendto(pkt, (parts[1], MY_PORT))
                except Exception as e: print(f"Error: {e}")
                
            elif act == "msg" and len(parts) >= 3:
                sess = mgr.find_addr((parts[1], MY_PORT))
                if sess and sess.handshake_done:
                    tr.sendto(sess.encrypt(" ".join(parts[2:])), (parts[1], MY_PORT))
                    print("Enviado.")
                else: print("No conectado.")
            elif act == "salir": break
    finally: tr.close()

if __name__ == "__main__":
    if hasattr(asyncio, 'WindowsSelectorEventLoopPolicy'):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try: asyncio.run(main())
    except KeyboardInterrupt: pass
