import os
import sys
import time
import json
import getpass
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import PyKCS11
from smartcard.System import readers

# --- CONFIGURACIÓN ---
# CAMBIA ESTO SI TU RUTA ES DIFERENTE
DLL_PATH = r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"
PROTOCOL_NAME = b"Noise_IK_25519_ChaChaPoly_BLAKE2s"
CERT_FILE = "certificado.der"

class DNIeHandler:
    def __init__(self):
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        try: self.lib = self.pkcs11.load(DLL_PATH)
        except: print(f"❌ Error DLL: {DLL_PATH}"); sys.exit(1)
        self.session = None
        self.slot = None

    def login_inicial(self):
        """Pide PIN una vez y mantiene la sesión"""
        print("\n=== INICIANDO SISTEMA DE SEGURIDAD DNIe ===")
        # Esperar lector
        lectores = []
        while not lectores:
            try: lectores = readers()
            except: pass
            if not lectores: print("⌛ Conecta el lector...", end="\r"); time.sleep(1)
        print(f"✅ Lector: {lectores[0]}")

        # Esperar tarjeta
        slots = []
        while not slots:
            try: slots = self.pkcs11.getSlotList(tokenPresent=True)
            except: pass
            if not slots: print("⌛ Inserta DNIe...", end="\r"); time.sleep(1)
        
        self.slot = slots[0]
        print(f"✅ Tarjeta detectada.")
        
        pwd = None
        while not pwd:
            print("") 
            pwd = getpass.getpass("🔑 Introduce PIN: ")
        
        try:
            self.session = self.pkcs11.openSession(self.slot)
            self.session.login(pwd)
            print('✅ Sesión iniciada.')
            return True
        except Exception as e:
            print(f"❌ Error PIN: {e}")
            return False

    def firmar_rapido(self, datos):
        if not self.session: return None, None
        try:
            # 1. Certificado (Disco o Chip)
            cert_der = None
            if os.path.exists(CERT_FILE):
                try: 
                    with open(CERT_FILE, "rb") as f: cert_der = f.read()
                except: pass

            if not cert_der:
                objs = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])
                for o in objs:
                    val = self.session.getAttributeValue(o, [PyKCS11.CKA_VALUE], True)
                    if not val: continue
                    raw = bytes(val[0])
                    x = x509.load_der_x509_certificate(raw, default_backend())
                    if "AUTENTICA" in x.subject.rfc4514_string().upper():
                        cert_der = raw; break
                if cert_der: 
                    with open(CERT_FILE, "wb") as f: f.write(cert_der)

            # 2. Clave Privada
            keys = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])
            priv = None
            for k in keys:
                l = self.session.getAttributeValue(k, [PyKCS11.CKA_LABEL])
                if l and l[0] == "KprivAutenticacion": priv = k; break
            if not priv and keys: priv = keys[0]

            # 3. Firmar
            mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
            sig = bytes(self.session.sign(priv, datos, mech))
            return cert_der, sig
        except: return None, None

class KeyManager:
    def __init__(self, prefix):
        self.dnie = DNIeHandler()

    def iniciar_sesion_dnie(self):
        return self.dnie.login_inicial()

    def firmar_handshake(self, datos):
        return self.dnie.firmar_rapido(datos)

    def verificar_handshake(self, clave, cert_der, firma):
        try:
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            cert.public_key().verify(firma, clave, padding.PKCS1v15(), hashes.SHA256())
            cn = "Desconocido"
            for a in cert.subject:
                if a.oid == x509.NameOID.COMMON_NAME: cn = a.value
            return True, cn
        except Exception as e: return False, str(e)

class SessionCrypto:
    def __init__(self):
        self.ephemeral = x25519.X25519PrivateKey.generate()
        self.cipher = None
        self.shared_key = None

    def get_public_bytes(self):
        return self.ephemeral.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def compute_secret(self, peer_bytes):
        peer = x25519.X25519PublicKey.from_public_bytes(peer_bytes)
        shared = self.ephemeral.exchange(peer)
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