import os
import sys
import time
import json
import getpass
import base64
import textwrap

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

import PyKCS11
from smartcard.System import readers

# --- RUTA DLL (Verifica tu ruta) ---
DLL_PATH = r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"
# DLL_PATH = r"C:\Windows\System32\DNIe_P11_priv.dll"

PROTOCOL_NAME = b"Noise_IK_25519_ChaChaPoly_BLAKE2s"
CERT_FILE = "certificado.der"

class DNIeHandler:
    def __init__(self):
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        try:
            self.lib = self.pkcs11.load(DLL_PATH)
        except Exception as e:
            print(f"❌ Error cargando DLL: {e}")
            sys.exit(1)
        self.session = None
        self.slot = None

    def login_inicial(self):
        """
        ESTA FUNCIÓN SE LLAMA UNA VEZ AL PRINCIPIO.
        Deja la sesión abierta permanentemente.
        """
        print("\n=== INICIANDO SESIÓN DNIe (Modo Persistente) ===")
        
        # 1. Esperar lector
        lectores = False
        leido = False
        while not lectores:
            try: lectores = readers()
            except: pass
            if not lectores and not leido:
                print("⌛ Esperando lector...", end="\r")
                sys.stdout.flush()
                leido = True
            time.sleep(1)
        print(f"✅ Lector detectado: {lectores[0]}")

        # 2. Esperar tarjeta
        slots = False
        leido = False
        while not slots:
            try: slots = self.pkcs11.getSlotList(tokenPresent=True)
            except: pass
            if not slots and not leido:
                print("⌛ Esperando DNIe...", end="\r")
                sys.stdout.flush()
                leido = True
            time.sleep(1)
        
        self.slot = slots[0]
        print(f"✅ Tarjeta detectada: {self.slot}")
        
        # 3. Pedir PIN (Una sola vez)
        password = None
        while not password:
            print("") # Salto de línea para limpiar buffer
            password = getpass.getpass("🔑 Introduce el PIN del DNIe: ")
        
        try:
            self.session = self.pkcs11.openSession(self.slot)
            self.session.login(password)
            print('✅ Sesión iniciada y mantenida abierta.')
            del password
            return True
        except Exception as e:
            print(f"❌ Error de PIN: {e}")
            return False

    def firmar_rapido(self, datos_a_firmar):
        """
        Firma usando la sesión YA ABIERTA. No pide PIN.
        """
        if not self.session:
            print("❌ Error: No hay sesión DNIe abierta.")
            return None, None

        try:
            # 1. Intentar cargar cert de disco
            cert_der = None
            if os.path.exists(CERT_FILE):
                try: 
                    with open(CERT_FILE, "rb") as f: cert_der = f.read()
                except: pass

            # 2. Si no hay cert en disco, buscar en chip
            if not cert_der:
                print("🔎 Leyendo certificado del chip...")
                certificados = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])
                for cert in certificados:
                    val = self.session.getAttributeValue(cert, [PyKCS11.CKA_VALUE], True)
                    if not val: continue
                    raw = bytes(val[0])
                    x = x509.load_der_x509_certificate(raw, default_backend())
                    subj = x.subject.rfc4514_string().upper()
                    if "AUTENTICA" in subj or "FIRMA" in subj:
                        cert_der = raw
                        break
                
                # Guardar en disco
                if cert_der:
                    with open(CERT_FILE, "wb") as f: f.write(cert_der)

            # 3. Buscar clave privada
            keys = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])
            priv_key = None
            for k in keys:
                l = self.session.getAttributeValue(k, [PyKCS11.CKA_LABEL])
                if l and l[0] == "KprivAutenticacion": priv_key = k; break
            if not priv_key and keys: priv_key = keys[0]

            # 4. Firmar
            mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
            firma = bytes(self.session.sign(priv_key, datos_a_firmar, mech))
            return cert_der, firma

        except Exception as e:
            print(f"❌ Error firmando: {e}")
            return None, None
        # OJO: AQUÍ NO CERRAMOS LA SESIÓN. SE QUEDA ABIERTA PARA LA PRÓXIMA.

class KeyManager:
    def __init__(self, prefix):
        # Inicializamos el Handler UNA VEZ y lo guardamos
        self.dnie = DNIeHandler()

    def iniciar_sesion_dnie(self):
        """Método puente para iniciar sesión desde fuera"""
        return self.dnie.login_inicial()

    def firmar_handshake(self, datos):
        # Reutilizamos el handler que ya tiene la sesión abierta
        return self.dnie.firmar_rapido(datos)

    def verificar_handshake(self, clave, cert_der, firma):
        try:
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            cert.public_key().verify(
                firma, clave, padding.PKCS1v15(), hashes.SHA256()
            )
            cn = "Desconocido"
            for a in cert.subject:
                if a.oid == x509.NameOID.COMMON_NAME: cn = a.value
            return True, cn
        except Exception as e:
            return False, str(e)

class SessionCrypto:
    def __init__(self, private_key=None):
        self.ephemeral = x25519.X25519PrivateKey.generate()
        self.cipher = None
        self.shared_key = None
    def get_public_bytes(self):
        return self.ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    def compute_secret(self, peer_bytes):
        peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_bytes)
        shared = self.ephemeral.exchange(peer_pub)
        hkdf = HKDF(hashes.BLAKE2s(32), 32, None, info=PROTOCOL_NAME)
        self.shared_key = hkdf.derive(shared)
        self.cipher = ChaCha20Poly1305(self.shared_key)
    def encrypt(self, txt):
        if not self.cipher: raise Exception("No Key")
        n = os.urandom(12)
        return n + self.cipher.encrypt(n, txt.encode(), None)
    def decrypt(self, data):
        if not self.cipher: raise Exception("No Key")
        return self.cipher.decrypt(data[:12], data[12:], None).decode()
    def export_secret(self): return self.shared_key.hex() if self.shared_key else None
    def load_secret(self, hx): 
        self.shared_key = bytes.fromhex(hx)
        self.cipher = ChaCha20Poly1305(self.shared_key)