import asyncio
import socket
import logging
import struct
import os
import sys
import getpass
import time
import traceback
from smartcard.System import readers

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, x25519
from cryptography.hazmat.primitives import serialization

# LIBRERÍA NOISE (Instalar con: pip install noise)
from noise.connection import NoiseConnection, Keypair

# --- CONFIGURACIÓN ---
# Usamos Noise_XX para intercambio de claves sin conocimiento previo
NOISE_PROTOCOL = b'Noise_XX_25519_ChaChaPoly_BLAKE2s'
MY_PORT = 55555 
LIB_PATH = r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"

# --- VARIABLES GLOBALES ---
MI_CERT_DER = None
MI_KEY_ID = None   # <--- CRUCIAL: ID interno para vincular certificado y clave privada
CACHED_PIN = None

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("DNIe-Client")

try:
    import PyKCS11
except ImportError:
    print("ERROR: Instala PyKCS11 (pip install PyKCS11)")
    sys.exit(1)

# ==============================================================================
#  GESTIÓN HARDWARE (DNIe) - CON BÚSQUEDA POR ID (CKA_ID)
# ==============================================================================
def cargar_driver():
    pkcs11 = PyKCS11.PyKCS11Lib()
    try:
        pkcs11.load(LIB_PATH)
    except Exception as e:
        print(f"Error cargando DLL: {e}"); sys.exit(1)
    return pkcs11

def iniciar_sesion_bloqueante(pkcs11_lib):
    """Espera lector y tarjeta, pide PIN y devuelve sesión."""
    global CACHED_PIN
    
    # 1. Esperar Lector
    while True:
        try:
            if readers(): break
        except: pass
        print("[DNIe] Conecta el lector...", end='\r'); time.sleep(1)

    # 2. Esperar Tarjeta
    slot = None
    while True:
        try:
            slots = pkcs11_lib.getSlotList(tokenPresent=True)
            if slots: slot = slots[0]; break
        except: pass
        print("[DNIe] Inserta la tarjeta...", end='\r'); time.sleep(1)

    # 3. Login
    session = pkcs11_lib.openSession(slot)
    try:
        if not CACHED_PIN:
            CACHED_PIN = getpass.getpass("\n[PIN] Introduce el PIN del DNIe: ")
        session.login(CACHED_PIN)
        return session
    except Exception as e:
        print(f"\n[!] Error de Login (PIN incorrecto): {e}")
        CACHED_PIN = None # Resetear PIN
        raise e

def extraer_certificado():
    """Busca el certificado de FIRMA y guarda su ID interno."""
    global MI_CERT_DER, MI_KEY_ID
    
    # Nota: Forzamos lectura del DNIe (sin caché de disco inicial) para asegurar el ID correcto
    print("[init] Leyendo DNIe para emparejar Clave y Certificado...")
    lib = cargar_driver()
    try:
        session = iniciar_sesion_bloqueante(lib)
        objs = session.findObjects([
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
            (PyKCS11.CKA_CERTIFICATE_TYPE, PyKCS11.CKC_X_509)
        ])
        
        if not objs: raise Exception("No se encontraron certificados.")

        # Buscar específicamente el de firma
        target_cert = None
        for cert_obj in objs:
            try:
                label = cert_obj.to_dict().get('CKA_LABEL', b'').decode('utf-8', errors='ignore')
                if "Firma" in label or "Sign" in label:
                    target_cert = cert_obj; break
            except: continue
        
        # Si no hay etiqueta clara, usamos el primero
        if not target_cert: 
            print("[!] Aviso: No se detectó etiqueta 'Firma', usando el primer certificado.")
            target_cert = objs[0]

        # OBTENEMOS VALOR Y ID (CKA_ID)
        attrs = session.getAttributeValue(target_cert, [PyKCS11.CKA_VALUE, PyKCS11.CKA_ID])
        MI_CERT_DER = bytes(attrs[0])
        MI_KEY_ID = attrs[1]
        
        print(f"[DNIe] ID de Clave seleccionado: {bytes(MI_KEY_ID).hex()}")
        session.logout(); session.closeSession()
        
    except Exception as e:
        print(f"Error extrayendo certificado: {e}"); sys.exit(1)

def firmar_bloqueante(data):
    """Firma datos usando la clave privada vinculada al ID obtenido."""
    lib = cargar_driver()
    session = None
    try:
        session = iniciar_sesion_bloqueante(lib)
        if MI_KEY_ID is None: raise Exception("Falta ID de clave (ejecuta extraer primero)")
        
        # BUSCAMOS LA CLAVE POR SU ID EXACTO
        keys = session.findObjects([
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_ID, MI_KEY_ID)
        ])
        if not keys: raise Exception("Clave privada no encontrada para el ID del certificado.")
        
        mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
        sig = bytes(session.sign(keys[0], data, mech))
        session.logout()
        return sig
    except Exception as e:
        print(f"\n[!] Error firmando: {e}"); return None
    finally:
        if session: session.closeSession()

async def firmar_async(data):
    """Wrapper asíncrono para no congelar el chat mientras firmas."""
    loop = asyncio.get_running_loop()
    print("\n[DNIe] Solicitando firma al hardware...", end='', flush=True)
    sig = await loop.run_in_executor(None, firmar_bloqueante, data)
    print(" Hecho.")
    return sig

def verificar(cert_bytes, firma, datos):
    """Verifica matemáticamente la firma recibida."""
    try:
        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
        cert.public_key().verify(firma, datos, padding.PKCS1v15(), hashes.SHA256())
        # Extraer nombre común (CN)
        cn = "Desconocido"
        for attr in cert.subject:
            if attr.oid == x509.NameOID.COMMON_NAME: cn = attr.value
        return True, cn
    except: return False, None

# ==============================================================================
#  SESIÓN NOISE (PROTOCOLO XX)
# ==============================================================================
class SecureSession:
    def __init__(self, priv):
        self.proto = NoiseConnection.from_name(NOISE_PROTOCOL)
        self.proto.set_keypair_from_private_bytes(Keypair.STATIC, priv)
        
        # Preparar mi clave pública para firmarla
        tmp_priv = x25519.X25519PrivateKey.from_private_bytes(priv)
        self.my_static_public = tmp_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

        self.handshake_done = False
        self.cipher_tx = None; self.cipher_rx = None
        self.local_cid = os.urandom(4) # ID único de sesión
        self.remote_cid = None
        self.is_initiator = False

    async def _build_payload(self):
        """Construye el paquete de identidad: CID + Cert + Firma(ClaveNoise)"""
        firma = await firmar_async(self.my_static_public)
        if not firma: raise Exception("Fallo al firmar con DNIe")
        return self.local_cid + struct.pack('!H', len(MI_CERT_DER)) + MI_CERT_DER + firma

    async def _verify_payload(self, payload):
        """Verifica la identidad del otro extremo."""
        if len(payload) < 8: raise Exception("Payload corrupto (muy corto)")
        
        self.remote_cid = payload[:4]
        l_c = struct.unpack('!H', payload[4:6])[0]
        
        cert_rem = payload[6 : 6+l_c]
        firma_rem = payload[6+l_c :]
        
        # Noise ya ha extraído la clave pública del otro en el handshake
        rem_static = self.proto.keypairs[Keypair.REMOTE_STATIC].public_bytes
        
        ok, name = verificar(cert_rem, firma_rem, rem_static)
        if not ok: raise Exception("FIRMA INVÁLIDA (Suplantación o error de configuración)")
        
        logger.info(f"Identidad Verificada: {name}")
        return True

    async def start_handshake(self):
        """Inicia la conexión (Rol: Initiator)"""
        self.is_initiator = True
        self.proto.set_as_initiator()
        self.proto.start_handshake()
        # Noise XX Paso 1: Enviar clave efímera (sin payload)
        return self.proto.write_message()

    async def process_packet(self, data):
        """Procesa paquetes de red (Handshake o Datos)"""
        if self.handshake_done: return None # Si ya acabamos, esto lo maneja el manager
        
        # Si soy Responder y llega el primer mensaje
        if not self.is_initiator and not self.proto.handshake_started:
            self.proto.set_as_responder()
            self.proto.start_handshake()

        try:
            # --- LÓGICA NOISE ---
            payload_rx = self.proto.read_message(data)
            
            # Si el mensaje traía payload (Pasos 2 y 3 de XX), verificar firma
            if payload_rx:
                await self._verify_payload(payload_rx)

            if self.proto.handshake_finished:
                self.cipher_tx, self.cipher_rx = self.proto.transition()
                self.handshake_done = True
                return True
            
            # Generar respuesta si el protocolo lo requiere
            payload_tx = b''
            # Responder envía datos en paso 2, Initiator en paso 3
            if (not self.is_initiator) or (self.is_initiator and len(payload_rx) > 0):
                 payload_tx = await self._build_payload()
                 
            return self.proto.write_message(payload_tx)

        except Exception as e:
            if "InvalidTag" in str(e) or "MacCheckFailed" in str(e):
                logger.error("ERROR CRÍTICO: Desajuste de claves. Reinicia el programa o reconecta.")
            else:
                logger.error(f"Error en Handshake: {e}")
                # traceback.print_exc() # Descomentar para debug profundo
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
        """Borra sesiones anteriores con una IP para empezar limpio."""
        if addr in self.s_addr:
            old = self.s_addr[addr]
            if old.local_cid in self.s_cid: del self.s_cid[old.local_cid]
            del self.s_addr[addr]

    def get_initiator(self, addr):
        # Siempre reseteamos antes de iniciar (manejado en main), pero por seguridad:
        if addr in self.s_addr: return self.s_addr[addr]
        s = SecureSession(self.priv)
        self.s_addr[addr] = s; self.s_cid[s.local_cid] = s
        return s

    def get_responder(self, addr):
        # Si llega un paquete nuevo de una IP conocida pero el CID no cuadra, 
        # podríamos necesitar resetear, pero aquí asumimos flujo normal.
        if addr in self.s_addr: return self.s_addr[addr]
        s = SecureSession(self.priv)
        self.s_addr[addr] = s; self.s_cid[s.local_cid] = s
        return s

    def find_cid(self, cid): return self.s_cid.get(cid)
    def find_addr(self, addr): return self.s_addr.get(addr)

# ==============================================================================
#  RED UDP Y BUCLE PRINCIPAL
# ==============================================================================
class DNIeTransport(asyncio.DatagramProtocol):
    def __init__(self, mgr): self.mgr = mgr; self.transport = None
    def connection_made(self, tr): self.transport = tr; print(f"[✓] Escuchando UDP en puerto {MY_PORT}")
    
    def datagram_received(self, data, addr):
        asyncio.create_task(self._handle(data, addr))

    async def _handle(self, data, addr):
        if len(data) < 4: return 
        
        # Intentamos recuperar sesión por CID (4 primeros bytes)
        cid = data[:4]
        sess = self.mgr.find_cid(cid)
        
        if sess and sess.handshake_done:
            try:
                txt = sess.decrypt(data[4:])
                print(f"\n[MSG] {addr[0]}: {txt}\n>> ", end='', flush=True)
            except Exception:
                print(f"\n[!] Mensaje indescifrable de {addr[0]}")
        else:
            # Es un paquete de Handshake
            sess = self.mgr.find_addr(addr)
            if not sess: sess = self.mgr.get_responder(addr)
            
            res = await sess.process_packet(data)
            if isinstance(res, bytes): 
                self.transport.sendto(res, addr)
            elif res is True: 
                print(f"\n[★] CONEXIÓN SEGURA ESTABLECIDA con {addr[0]}\n>> ", end='', flush=True)

async def main():
    print("--- CHAT DNIe v3.0 (Direct IP + Noise XX + Fix ID) ---")
    
    # 1. Preparar DNIe
    extraer_certificado()
    
    # 2. Claves efímeras para Noise
    priv = x25519.X25519PrivateKey.generate()
    priv_b = priv.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
    
    # 3. Red
    mgr = SessionManager(priv_b)
    loop = asyncio.get_running_loop()
    
    try:
        tr, pr = await loop.create_datagram_endpoint(lambda: DNIeTransport(mgr), local_addr=('0.0.0.0', MY_PORT))
    except Exception as e:
        print(f"No se pudo abrir el puerto {MY_PORT}. ¿Ya está en uso? Error: {e}"); return

    # Detectar IP propia
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: s.connect(('8.8.8.8', 1)); my_ip = s.getsockname()[0]
    except: my_ip = '127.0.0.1'
    finally: s.close()
    
    print(f"Mi IP: {my_ip}")
    print("Comandos: conectar <IP>, msg <IP> <txt>, salir")
    print("------------------------------------------------")

    try:
        while True:
            cmd = await loop.run_in_executor(None, input, ">> ")
            parts = cmd.split()
            if not parts: continue
            
            act = parts[0].lower()

            if act == "conectar" and len(parts) >= 2:
                target_ip = parts[1]
                
                # LIMPIEZA: Borramos sesión anterior para evitar conflicto de claves
                mgr.reset_session((target_ip, MY_PORT))
                
                print(f"Iniciando Handshake con {target_ip}...")
                sess = mgr.get_initiator((target_ip, MY_PORT))
                try:
                    pkt = await sess.start_handshake()
                    tr.sendto(pkt, (target_ip, MY_PORT))
                except Exception as e:
                    print(f"Error iniciando conexión: {e}")
                
            elif act == "msg" and len(parts) >= 3:
                target_ip = parts[1]
                sess = mgr.find_addr((target_ip, MY_PORT))
                if sess and sess.handshake_done:
                    try:
                        tr.sendto(sess.encrypt(" ".join(parts[2:])), (target_ip, MY_PORT))
                        print("Enviado.")
                    except Exception as e:
                        print(f"Error enviando: {e}")
                else:
                    print("¡No estás conectado! Usa: conectar <IP>")
                    
            elif act == "salir": break
    finally:
        tr.close()

if __name__ == "__main__":
    # Fix para Windows y asyncio
    if hasattr(asyncio, 'WindowsSelectorEventLoopPolicy'):
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try: asyncio.run(main())
    except KeyboardInterrupt: pass
