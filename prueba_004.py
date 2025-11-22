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

# --- LIBRERÍAS ---
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, x25519, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from noise.connection import NoiseConnection, Keypair

# ==============================================================================
#  CONFIGURACIÓN
# ==============================================================================
# [!!!] CAMBIA ESTO SEGÚN EL PC:
# True  = Estás en casa SIN lector (Genera identidad falsa)
# False = Tienes el DNIe conectado (Busca certificado real)
MODO_SIMULACION = False

NOISE_PROTOCOL = b'Noise_XX_25519_ChaChaPoly_BLAKE2s'
MY_PORT = 55555 
LIB_PATH = r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"

# Globales
MI_CERT_DER = None
MI_KEY_ID = None   
CACHED_PIN = None
MOCK_PRIVATE_KEY = None 

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("DNIe-Client")

if not MODO_SIMULACION:
    try:
        import PyKCS11
        from smartcard.System import readers
    except ImportError:
        print("ERROR: Instala PyKCS11 (pip install PyKCS11) o pon MODO_SIMULACION=True")
        sys.exit(1)

# ==============================================================================
#  1. GESTIÓN DE IDENTIDAD (SIMULADA)
# ==============================================================================
def generar_identidad_simulada():
    print("[SIM] Generando identidad temporal en RAM...")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"USUARIO SIMULADO"),
    ])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
        key.public_key()
    ).serial_number(x509.random_serial_number()).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=1)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(key, hashes.SHA256(), default_backend())
    return cert.public_bytes(serialization.Encoding.DER), key

# ==============================================================================
#  2. GESTIÓN DE IDENTIDAD (REAL - CON ANTI-BLOQUEO)
# ==============================================================================
def extraer_certificado():
    global MI_CERT_DER, MI_KEY_ID, MOCK_PRIVATE_KEY
    
    if MODO_SIMULACION:
        MI_CERT_DER, MOCK_PRIVATE_KEY = generar_identidad_simulada()
        return

    print("[init] Analizando DNIe (Búsqueda de par correcto)...")
    pkcs11 = PyKCS11.PyKCS11Lib()
    try: pkcs11.load(LIB_PATH)
    except: print(f"Error DLL {LIB_PATH}"); sys.exit(1)

    while True:
        try: 
            if readers(): break
        except: pass
        print("[DNIe] Esperando lector...", end='\r'); time.sleep(1)

    try:
        slot = pkcs11.getSlotList(tokenPresent=True)[0]
    except:
        print("\n[!] No se detecta tarjeta."); sys.exit(1)

    session = pkcs11.openSession(slot)
    try:
        global CACHED_PIN
        if not CACHED_PIN: CACHED_PIN = getpass.getpass("\n[PIN] DNIe: ")
        session.login(CACHED_PIN)

        # --- BÚSQUEDA INTELIGENTE (PROBAR TODOS) ---
        objs = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE), (PyKCS11.CKA_CERTIFICATE_TYPE, PyKCS11.CKC_X_509)])
        
        pareja_encontrada = False
        test_data = b"TEST_INIT"
        
        print(f"[init] Probando {len(objs)} certificados internos...")
        
        for i, cert_obj in enumerate(objs):
            try:
                # Extraer datos
                attrs = session.getAttributeValue(cert_obj, [PyKCS11.CKA_VALUE, PyKCS11.CKA_ID])
                c_der = bytes(attrs[0])
                c_id = attrs[1]
                
                # Buscar clave privada hermana
                keys = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY), (PyKCS11.CKA_ID, c_id)])
                if not keys: continue
                
                # Prueba de firma
                mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
                sig = bytes(session.sign(keys[0], test_data, mech))
                
                # Prueba de verificación
                if verificar(c_der, sig, test_data)[0]:
                    print(f"  -> Certificado #{i}: FUNCIONA. Seleccionado.")
                    MI_CERT_DER = c_der
                    MI_KEY_ID = c_id
                    pareja_encontrada = True
                    
                    # Guardar en disco
                    with open("certificado.der", "wb") as f: f.write(MI_CERT_DER)
                    break
            except: continue
            
        if not pareja_encontrada:
            print("\n[!] ERROR: Ningún certificado de la tarjeta funciona para firmar.")
            sys.exit(1)

    except Exception as e:
        print(f"\n[!] Error init: {e}"); CACHED_PIN=None; sys.exit(1)
    finally:
        # ESTO ES CRUCIAL: Liberar la tarjeta para que no se bloquee después
        try: session.logout(); session.closeSession()
        except: pass

def firmar_bloqueante(data):
    if MODO_SIMULACION:
        return MOCK_PRIVATE_KEY.sign(data, padding.PKCS1v15(), hashes.SHA256())

    # MODO REAL
    pkcs11 = PyKCS11.PyKCS11Lib()
    pkcs11.load(LIB_PATH)
    session = None
    try:
        slot = pkcs11.getSlotList(tokenPresent=True)[0]
        session = pkcs11.openSession(slot)
        session.login(CACHED_PIN)
        
        keys = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY), (PyKCS11.CKA_ID, MI_KEY_ID)])
        if not keys: raise Exception("Clave no encontrada (¿Sacaste el DNI?)")
        
        mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
        sig = bytes(session.sign(keys[0], data, mech))
        return sig
    except Exception as e:
        print(f"[!] Error firma hardware: {e}"); return None
    finally:
        # SIEMPRE CERRAR SESIÓN
        if session: 
            try: session.logout(); session.closeSession()
            except: pass

async def firmar_async(data):
    loop = asyncio.get_running_loop()
    modo = "SIM" if MODO_SIMULACION else "DNIe"
    print(f"\n[{modo}] Firmando...", end='', flush=True)
    sig = await loop.run_in_executor(None, firmar_bloqueante, data)
    print(" OK.", end=' ', flush=True)
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
#  3. NOISE
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
        logger.info(f"Verificado: {name}")
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
            if "InvalidTag" in str(e): logger.error("Error Sync (InvalidTag).")
            else: logger.error(f"Error HS: {e}")
            return None

    def encrypt(self, msg):
        return self.remote_cid + self.cipher_tx.encrypt(msg.encode())

    def decrypt(self, data):
        return self.cipher_rx.decrypt(data).decode()

class SessionManager:
    def __init__(self, priv):
        self.priv = priv; self.s_cid = {}; self.s_addr = {}

    def reset_session(self, addr):
        if addr in self.s_addr:
            print(f"[!] Limpiando sesión vieja con {addr[0]}")
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
    def connection_made(self, tr): self.transport = tr; print(f"[✓] UDP Escuchando en {MY_PORT}")
    
    def datagram_received(self, data, addr):
        print(f"[RED] RX {len(data)} bytes <- {addr[0]}")
        asyncio.create_task(self._handle(data, addr))

    async def _handle(self, data, addr):
        if len(data) < 4: return 
        if len(data) == 32: self.mgr.reset_session(addr)

        sess = self.mgr.find_cid(data[:4])
        if sess and sess.handshake_done:
            try: print(f"\n[MSG] {addr[0]}: {sess.decrypt(data[4:])}\n>> ", end='', flush=True)
            except: pass
        else:
            sess = self.mgr.find_addr(addr)
            if not sess: sess = self.mgr.get_responder(addr)
            res = await sess.process_packet(data)
            if isinstance(res, bytes): 
                print(f"[RED] TX {len(res)} bytes -> {addr[0]}")
                self.transport.sendto(res, addr)
            elif res is True: print(f"\n[★] CONEXIÓN OK: {addr[0]}\n>> ", end='', flush=True)

async def main():
    modo_txt = "SIMULADO" if MODO_SIMULACION else "REAL"
    print(f"--- CHAT DNIe v6.0: {modo_txt} ---")
    
    extraer_certificado()
    
    # Self Test Rápido
    print("[init] Autocomprobación...", end='')
    td = b"T"; f = firmar_bloqueante(td)
    if verificar(MI_CERT_DER, f, td)[0]: print(" OK")
    else: print(" FALLO"); return

    priv = x25519.X25519PrivateKey.generate()
    priv_b = priv.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
    
    mgr = SessionManager(priv_b)
    loop = asyncio.get_running_loop()
    
    try:
        tr, pr = await loop.create_datagram_endpoint(lambda: DNIeTransport(mgr), local_addr=('0.0.0.0', MY_PORT))
    except Exception as e: print(f"Error puerto: {e}"); return

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
                print(f"Iniciando Handshake con {parts[1]}...")
                sess = mgr.get_initiator((parts[1], MY_PORT))
                try:
                    pkt = await sess.start_handshake()
                    # --- AQUI ES DONDE SE TE QUEDABA PENSANDO ---
                    print(f"[RED] Enviando paquete inicial ({len(pkt)} bytes)...") 
                    tr.sendto(pkt, (parts[1], MY_PORT))
                    # Si ves este mensaje y no pasa nada más, ES EL FIREWALL.
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
