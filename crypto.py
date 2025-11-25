import os
import sys
import time
import json
import getpass
import base64
import textwrap

# Librerías de Criptografía
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519, padding, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Librería del DNIe
import PyKCS11
from smartcard.System import readers

# --- CONFIGURACIÓN DE LA LIBRERÍA ---
# Asegúrate de que esta ruta es correcta en tu PC
DLL_PATH = r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"
# DLL_PATH = r"C:\Windows\System32\DNIe_P11_priv.dll" 

PROTOCOL_NAME = b"Noise_IK_25519_ChaChaPoly_BLAKE2s"

class DNIeHandler:
    """Clase encargada de hablar con el lector de tarjetas."""
    def __init__(self):
        self.lib = None
        self.session = None
        self.slot = None
        
        try:
            self.pkcs11 = PyKCS11.PyKCS11Lib()
            self.lib = self.pkcs11.load(DLL_PATH)
        except Exception as e:
            print(f"ERROR CARGANDO DLL ({DLL_PATH}): {e}")
            sys.exit(1)

    def wait_for_card(self):
        print("\n--- CONEXIÓN CON DNIe REQUERIDA ---")
        while True:
            try:
                lectores_disp = readers()
                if lectores_disp: break
            except: pass
            time.sleep(1)

        while True:
            try:
                slots = self.pkcs11.getSlotList(tokenPresent=True)
                if slots:
                    self.slot = slots[0]
                    break
            except: pass
            time.sleep(1)
        print("Tarjeta DNIe detectada.")

    def login(self):
        self.wait_for_card()
        password = None
        while not password:
            password = getpass.getpass("Introduce el PIN del DNIe: ")
        
        try:
            self.session = self.pkcs11.openSession(self.slot)
            self.session.login(password)
            print("PIN Correcto. Sesión abierta.")
        except Exception as e:
            print(f"Error de login: {e}")
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
                subject = cert.subject.rfc4514_string().upper()
                if "AUTENTICA" in subject or "FIRMA" in subject:
                    return obj, cert_der
            except: continue
        return None, None

    def find_private_key(self):
        keys = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])
        for key in keys:
            label_attr = self.session.getAttributeValue(key, [PyKCS11.CKA_LABEL])
            if label_attr and label_attr[0]:
                if label_attr[0] == "KprivAutenticacion":
                    return key
        return keys[0] if keys else None

    def sign_data(self, data_bytes):
        priv_key = self.find_private_key()
        if not priv_key: raise Exception("No se encontró clave privada en DNIe.")
        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
        return bytes(self.session.sign(priv_key, data_bytes, mechanism))

class KeyManager:
    """Gestiona la identidad híbrida (X25519 + DNIe)."""
    def __init__(self, storage_prefix="identity"):
        self.key_file = f"{storage_prefix}_x25519.json"
        self.cert_file = "certificado.der"
        
        self.static_private = None
        self.static_public = None
        
        self._load_or_gen_x25519()
        self._load_or_extract_dnie()

    def _load_or_gen_x25519(self):
        if os.path.exists(self.key_file):
            try:
                with open(self.key_file, 'r') as f:
                    data = json.load(f)
                    priv_bytes = bytes.fromhex(data['private_key'])
                    self.static_private = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
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

    def _load_or_extract_dnie(self):
        if not os.path.exists(self.cert_file):
            print(f"⚠ Extrayendo certificado del DNIe...")
            handler = DNIeHandler()
            handler.login()
            _, cert_der = handler.find_auth_certificate()
            if not cert_der: sys.exit(1)
            with open(self.cert_file, "wb") as f: f.write(cert_der)
            handler.logout()

    def sign_my_static_key(self):
        pub_bytes = self.static_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        print("\n🔐 SOLICITANDO FIRMA CON DNIe...")
        handler = DNIeHandler()
        handler.login()
        signature = handler.sign_data(pub_bytes)
        handler.logout()
        return signature

class SessionCrypto:
    """Maneja el cifrado de la sesión."""
    def __init__(self, private_key):
        self.my_static_private = private_key
        self.cipher = None
        self.shared_key = None # <--- IMPORTANTE: Variable para guardar la clave
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
            algorithm=hashes.BLAKE2s(32),
            length=32,
            salt=None,
            info=PROTOCOL_NAME,
        )
        # 1. Calculamos la clave
        key_material = hkdf.derive(shared_secret)
        
        # 2. LA GUARDAMOS EN LA CLASE (Esto faltaba antes)
        self.shared_key = key_material
        
        # 3. Creamos el cifrador
        self.cipher = ChaCha20Poly1305(key_material)
        return True

    def encrypt(self, plaintext):
        if not self.cipher: raise Exception("No Handshake")
        nonce = os.urandom(12)
        data = plaintext.encode('utf-8')
        return nonce + self.cipher.encrypt(nonce, data, None)

    def decrypt(self, payload):
        if not self.cipher: raise Exception("No Handshake")
        nonce = payload[:12]
        ciphertext = payload[12:]
        return self.cipher.decrypt(nonce, ciphertext, None).decode('utf-8')
    
    # --- MÉTODOS DE PERSISTENCIA CORREGIDOS ---

    def export_secret(self):
        """Devuelve la clave guardada en hexadecimal"""
        if self.shared_key:
            return self.shared_key.hex()
        return None

    def load_secret(self, hex_secret):
        """Carga la clave desde hex y RECREA EL CIFRADOR"""
        key_bytes = bytes.fromhex(hex_secret)
        self.shared_key = key_bytes
        # ¡CRUCIAL! Recreamos el motor de cifrado con la clave cargada
        self.cipher = ChaCha20Poly1305(key_bytes)