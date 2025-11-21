import asyncio
import socket
import logging
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

# --- CAMBIO 1: USAMOS PATRÓN XX (Permite conectar sin conocer la clave de antemano) ---
from noise.connection import NoiseConnection, Keypair
NOISE_PROTOCOL = b'Noise_XX_25519_ChaChaPoly_BLAKE2s'

# CONFIGURACIÓN
MY_PORT = 55555  # Puerto alto para evitar conflictos
LIB_PATH = r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"

# Variables Globales
MI_CERT_DER = None
MI_KEY_ID = None   # <--- IMPORTANTE PARA TU ERROR DE FIRMA
CACHED_PIN = None

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("DNIe-Client")

try:
    import PyKCS11
except ImportError:
    print("ERROR: Instala PyKCS11 (pip install PyKCS11)")
    sys.exit(1)

# ==============================================================================
#  GESTIÓN HARDWARE (DNIe) - VERSIÓN CORREGIDA (ID)
# ==============================================================================
def cargar_driver():
    pkcs11 = PyKCS11.PyKCS11Lib()
    try:
        pkcs11.load(LIB_PATH)
    except Exception as e:
        print(f"Error cargando DLL: {e}"); sys.exit(1)
    return pkcs11

def iniciar_sesion_bloqueante(pkcs11_lib):
    global CACHED_PIN
    while True:
        if readers(): break
        print("[DNIe] Conecta el lector...", end='\r'); time.sleep(1)

    slot = pkcs11_lib.getSlotList(tokenPresent=True)[0]
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
    global MI_CERT_DER, MI_KEY_ID
    
    # NOTA: Forzamos lectura del DNIe para obtener el ID correcto
    print("[init] Leyendo DNIe para emparejar Clave y Certificado...")
    lib = cargar_driver()
    try:
        session = iniciar_sesion_bloqueante(lib)
        objs = session.findObjects([
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
            (PyKCS11.CKA_CERTIFICATE_TYPE, PyKCS11.CKC_X_509)
        ])
        
        target_cert = None
        for cert_obj in objs:
            try:
                label = cert_obj.to_dict().get('CKA_LABEL', b'').decode('utf-8', errors='ignore')
                if "Firma" in label or "Sign" in label:
                    target_cert = cert_obj; break
            except: continue
        if not target_cert: target_cert = objs[0]

        # OBTENEMOS EL ID (CKA_ID) PARA USAR LA CLAVE CORRECTA LUEGO
        attrs = session.getAttributeValue(target_cert, [PyKCS11.CKA_VALUE, PyKCS11.CKA_ID])
        MI_CERT_DER = bytes(attrs[0])
        MI_KEY_ID = attrs[1]
        print(f"[DNIe] ID de Clave seleccionado: {bytes(MI_KEY_ID).hex()}")

        session.logout(); session.closeSession()
    except Exception as e:
        print(f"Error: {e}"); sys.exit(1)

def firmar_bloqueante(data):
    lib = cargar_driver()
    session = None
    try:
        session = iniciar_sesion_bloqueante(lib)
        if MI_KEY_ID is None: raise Exception("Falta ID de clave")
        
        # BUSCAMOS LA CLAVE POR SU ID EXACTO (SOLUCIÓN AL ERROR DE FIRMA)
        keys = session.findObjects([
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_ID, MI_KEY_ID)
        ])
        if not keys: raise Exception("Clave privada no encontrada para este certificado")
        
        mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
        sig = bytes(session.sign(keys[0], data, mech))
        session.logout()
        return sig
    except Exception as e:
        print(f"\n[!] Error firmando: {e}"); return None
    finally:
        if session: session.closeSession()

async def firmar_async(data):
    loop = asyncio.get_running_loop()
    print("\n[DNIe] Firmando...", end='', flush=True)
    sig = await loop.run_in_executor(None, firmar_bloqueante, data)
    print(" Hecho.")
    return sig

def verificar(cert_bytes, firma, datos):
    try:
        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
        cert.public_key().verify(firma, datos, padding.PKCS1v15(), hashes.SHA256())
        cn = next((a.value for a in cert.subject if a.oid == x509.NameOID.COMMON_NAME), "Desc.")
        return True, cn
    except: return False, None

# ==============================================================================
#  SESIÓN NOISE XX (INTERCAMBIO SIN CONOCIMIENTO PREVIO)
# ==============================================================================
class SecureSession:
    def __init__(self, priv):
        self.proto = NoiseConnection.from_name(NOISE_PROTOCOL)
        self.proto.set_keypair_from_private_bytes(Keypair.STATIC, priv)
        
        # Preparamos nuestra clave pública estática para firmarla luego
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
        # Firma de nuestra clave estática
        firma = await firmar_async(self.my_static_public)
        if not firma: raise Exception("Fallo Firma")
        return self.local_cid + struct.pack('!H', len(MI_CERT_DER)) + MI_CERT_DER + firma

    async def _verify_payload(self, payload):
        if len(payload) < 8: raise Exception("Payload corto")
        self.remote_cid = payload[:4]
        l_c = struct.unpack('!H', payload[4:6])[0]
        cert_rem = payload[6 : 6+l_c]
        firma_rem = payload[6+l_c :]
        
        # En Noise XX, la clave remota ya está en el estado tras leer el mensaje
        rem_static = self.proto.keypairs[Keypair.REMOTE_STATIC].public_bytes
        ok, name = verificar(cert_rem, firma_rem, rem_static)
        if not ok: raise Exception("FIRMA INVÁLIDA")
        logger.info(f"Peer Verificado: {name}")
        return True

    async def start_handshake(self):
        self.is_initiator = True
        self.proto.set_as_initiator()
        self.proto.start_handshake()
        # Paso 1 XX: -> e (Payload vacío)
        return self.proto.write_message()

    async def process_packet(self, data):
        if self.handshake_done: return None
        
        # Si soy responder y es el primer paquete
        if not self.is_initiator and not self.proto.handshake_started:
            self.proto.set_as_responder()
            self.proto.start_handshake()

        try:
            # --- LÓGICA DEL HANDSHAKE XX (3 Pasos) ---
            payload_rx = self.proto.read_message(data)
            
            # Si recibimos payload (Responder en paso 1 recibe vacío, Init en paso 2 recibe datos)
            if payload_rx:
                await self._verify_payload(payload_rx)

            if self.proto.handshake_finished:
                self.cipher_tx, self.cipher_rx = self.proto.transition()
                self.handshake_done = True
                return True
            
            # Generar respuesta si toca
            # Responder envía su payload en el paso 2
            # Initiator envía su payload en el paso 3
            payload_tx = b''
            if (not self.is_initiator) or (self.is_initiator and len(payload_rx) > 0):
                 payload_tx = await self._build_payload()
                 
            return self.proto.write_message(payload_tx)

        except Exception as e:
            import traceback; traceback.print_exc()
            logger.error(f"Error HS: {e}")
            return None

    def encrypt(self, msg):
        return self.remote_cid + self.cipher_tx.encrypt(msg.encode())

    def decrypt(self, data):
        return self.cipher_rx.decrypt(data).decode()

class SessionManager:
    def __init__(self, priv):
        self.priv = priv
        self.s_cid = {}   # Mapa CID -> Session
        self.s_addr = {}  # Mapa (IP, Port) -> Session

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

# ==============================================================================
#  RED
# ==============================================================================
class DNIeTransport(asyncio.DatagramProtocol):
    def __init__(self, mgr): self.mgr = mgr; self.transport = None
    def connection_made(self, tr): self.transport = tr; print(f"[✓] Escuchando en puerto {MY_PORT}")
    
    def datagram_received(self, data, addr):
        asyncio.create_task(self._handle(data, addr))

    async def _handle(self, data, addr):
        # Mensajes Noise siempre tienen longitud mínima (header)
        if len(data) < 4: return 
        
        # Intentamos identificar sesión por CID (bytes 0-4)
        # En el handshake inicial de Noise XX, el CID aún no se intercambia en claro
        # así que confiamos en la IP si no hay sesión establecida.
        cid = data[:4]
        sess = self.mgr.find_cid(cid)
        
        if sess and sess.handshake_done:
            try:
                txt = sess.decrypt(data[4:])
                print(f"\n[MSG] {addr[0]}: {txt}\n>> ", end='', flush=True)
            except: pass
        else:
            # Handshake
            sess = self.mgr.find_addr(addr)
            if not sess: sess = self.mgr.get_responder(addr)
            
            res = await sess.process_packet(data)
            if isinstance(res, bytes): self.transport.sendto(res, addr)
            elif res is True: print(f"\n[★] CONEXIÓN SEGURA ESTABLECIDA: {addr}\n>> ", end='', flush=True)

async def main():
    print("--- CHAT DNIe SIN SERVIDOR ---")
    extraer_certificado()
    
    # Generar claves privadas Noise
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
    
    print(f"Mi IP: {my_ip} | Puerto: {MY_PORT}")
    print("Uso: conectar <IP_DESTINO>  |  msg <IP> <TEXTO>")

    try:
        while True:
            cmd = await loop.run_in_executor(None, input, ">> ")
            parts = cmd.split()
            if not parts: continue
            
            if parts[0] == "conectar" and len(parts) >= 2:
                target_ip = parts[1]
                print(f"Iniciando Handshake XX con {target_ip}...")
                sess = mgr.get_initiator((target_ip, MY_PORT))
                pkt = await sess.start_handshake()
                tr.sendto(pkt, (target_ip, MY_PORT))
                
            elif parts[0] == "msg" and len(parts) >= 3:
                target_ip = parts[1]
                sess = mgr.find_addr((target_ip, MY_PORT))
                if sess and sess.handshake_done:
                    tr.sendto(sess.encrypt(" ".join(parts[2:])), (target_ip, MY_PORT))
                    print("Enviado.")
                else:
                    print("¡Primero haz 'conectar <IP>' y espera la confirmación!")
                    
            elif parts[0] == "salir": break
    finally:
        tr.close()

if __name__ == "__main__":
    if hasattr(asyncio, 'WindowsSelectorEventLoopPolicy'):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try: asyncio.run(main())
    except KeyboardInterrupt: pass
