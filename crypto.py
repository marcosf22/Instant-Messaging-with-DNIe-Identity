import os
import sys
import time
import json
import getpass

# Librerías de Criptografía
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Librería del DNIe
import PyKCS11
from smartcard.System import readers

# CONFIGURACIÓN DLL (Verifica tu ruta)
DLL_PATH = r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"
PROTOCOL_NAME = b"Noise_IK_25519_ChaChaPoly_BLAKE2s"

class DNIeHandler:
    def __init__(self):
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        try:
            self.lib = self.pkcs11.load(DLL_PATH)
        except:
            print(f"❌ Error cargando DLL en: {DLL_PATH}")
            sys.exit(1)
        self.session = None
        self.slot = None

    def wait_for_card(self):
        print("⌛ Esperando DNIe...")
        while True:
            try:
                slots = self.pkcs11.getSlotList(tokenPresent=True)
                if slots:
                    self.slot = slots[0]
                    break
            except: pass
            time.sleep(1)

    def login(self):
        self.wait_for_card()
        pwd = None
        while not pwd:
            pwd = getpass.getpass("Introduce PIN DNIe: ")
        try:
            self.session = self.pkcs11.openSession(self.slot)
            self.session.login(pwd)
            print("✔ PIN Correcto.")
        except Exception as e:
            print(f"❌ Login fallido: {e}")
            sys.exit(1)

    def logout(self):
        if self.session:
            try:
                self.session.logout()
                self.session.closeSession()
            except: pass

    def find_auth_certificate(self):
        objs = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])
        for obj in objs:
            try:
                val = self.session.getAttributeValue(obj, [PyKCS11.CKA_VALUE], True)
                if not val: continue
                cert_der = bytes(val[0])
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                subj = cert.subject.rfc4514_string().upper()
                if "AUTENTICA" in subj or "FIRMA" in subj:
                    return obj, cert_der
            except: continue
        return None, None

class KeyManager:
    def __init__(self, prefix="identity"):
        self.key_file = f"{prefix}_x25519.json"
        self.cert_file = "certificado.der"
        self.static_private = None
        self.static_public = None
        self._load_or_gen_x25519()

    def _load_or_gen_x25519(self):
        if os.path.exists(self.key_file):
            try:
                with open(self.key_file, 'r') as f:
                    data = json.load(f)
                    priv = bytes.fromhex(data['private_key'])
                    self.static_private = x25519.X25519PrivateKey.from_private_bytes(priv)
            except: self._generate_x25519()
        else: self._generate_x25519()
        self.static_public = self.static_private.public_key()

    def _generate_x25519(self):
        self.static_private = x25519.X25519PrivateKey.generate()
        priv_bytes = self.static_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(self.key_file, 'w') as f:
            json.dump({'private_key': priv_bytes.hex()}, f)
    
    # --- FUNCIONES DE VERIFICACIÓN ---
    def extract_name_from_cert(self, cert_der):
        try:
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            for attr in cert.subject:
                if attr.oid == x509.NameOID.COMMON_NAME:
                    return attr.value
            return "Nombre Desconocido"
        except: return "Certificado Inválido"

class SessionCrypto:
    def __init__(self, private_key):
        self.my_static_private = private_key
        self.cipher = None
        self.shared_key = None # Aquí guardamos la clave para el JSON
        self.ephemeral_private = x25519.X25519PrivateKey.generate()

    def get_ephemeral_public_bytes(self):
        return self.ephemeral_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def perform_handshake(self, peer_public_bytes, is_initiator=True):
        peer_public = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
        shared_secret = self.ephemeral_private.exchange(peer_public)
        
        hkdf = HKDF(
            algorithm=hashes.BLAKE2s(32), length=32, salt=None, info=PROTOCOL_NAME,
        )
        key_material = hkdf.derive(shared_secret)
        
        # GUARDAMOS LA CLAVE Y CREAMOS EL CIFRADOR
        self.shared_key = key_material
        self.cipher = ChaCha20Poly1305(key_material)
        return True

    def encrypt(self, plaintext):
        if not self.cipher: raise Exception("No Handshake")
        nonce = os.urandom(12)
        return nonce + self.cipher.encrypt(nonce, plaintext.encode('utf-8'), None)

    def decrypt(self, payload):
        if not self.cipher: raise Exception("No Handshake")
        nonce = payload[:12]
        ciphertext = payload[12:]
        return self.cipher.decrypt(nonce, ciphertext, None).decode('utf-8')

    # --- PERSISTENCIA ---
    def export_secret(self):
        if self.shared_key: return self.shared_key.hex()
        return None

    def load_secret(self, hex_secret):
        key_bytes = bytes.fromhex(hex_secret)
        self.shared_key = key_bytes
        self.cipher = ChaCha20Poly1305(key_bytes) # Recreamos el cifrador