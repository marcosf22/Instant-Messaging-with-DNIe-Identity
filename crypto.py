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
# ¡¡¡ VERIFICA QUE ESTA RUTA ES LA CORRECTA EN TU PC !!!
# Opción A (OpenSC):
DLL_PATH = r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"
# Opción B (DNIe Oficial):
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
            print("Asegúrate de tener OpenSC instalado o cambia la ruta DLL_PATH.")
            sys.exit(1)

    def wait_for_card(self):
        """Espera a que haya un lector y una tarjeta insertada."""
        print("\n--- CONEXIÓN CON DNIe REQUERIDA ---")
        
        # 1. Esperar lector
        while True:
            try:
                lectores_disp = readers()
                if lectores_disp:
                    break
            except: pass
            print("Esperando lector de tarjetas...", end="\r")
            time.sleep(1)

        # 2. Esperar tarjeta
        while True:
            try:
                slots = self.pkcs11.getSlotList(tokenPresent=True)
                if slots:
                    self.slot = slots[0]
                    break
            except: pass
            print("Por favor, inserta el DNIe...", end="\r")
            time.sleep(1)
        print("Tarjeta DNIe detectada.                  ")

    def login(self):
        """Pide el PIN e inicia sesión."""
        self.wait_for_card()
        password = None
        while not password:
            password = getpass.getpass("Introduce el PIN del DNIe: ")
        
        try:
            self.session = self.pkcs11.openSession(self.slot)
            self.session.login(password)
            print("PIN Correcto. Sesión abierta.")
        except Exception as e:
            print(f"Error de login (¿PIN incorrecto?): {e}")
            sys.exit(1)

    def logout(self):
        if self.session:
            try:
                self.session.logout()
                self.session.closeSession()
            except: pass

    def find_auth_certificate(self):
        """Busca el objeto certificado de Autenticación en el chip."""
        objs = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])
        for obj in objs:
            try:
                val = self.session.getAttributeValue(obj, [PyKCS11.CKA_VALUE], True)
                if not val: continue
                cert_der = bytes(val[0])
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                
                subject = cert.subject.rfc4514_string().upper()
                # Buscamos cualquier certificado de firma o autenticación
                if "AUTENTICA" in subject or "FIRMA" in subject:
                    return obj, cert_der
            except: continue
        return None, None

    def find_private_key(self):
        """Busca la clave privada asociada."""
        keys = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])
        for key in keys:
            label_attr = self.session.getAttributeValue(key, [PyKCS11.CKA_LABEL])
            if label_attr and label_attr[0]:
                label = label_attr[0]
                if label == "KprivAutenticacion":
                    return key
        return keys[0] if keys else None

    def sign_data(self, data_bytes):
        """Firma bytes usando la clave privada del DNIe."""
        priv_key = self.find_private_key()
        if not priv_key:
            raise Exception("No se encontró la clave privada en el DNIe.")
        
        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
        signature = bytes(self.session.sign(priv_key, data_bytes, mechanism))
        return signature

class KeyManager:
    """Gestiona la identidad híbrida (X25519 + DNIe)."""
    def __init__(self, storage_prefix="identity"):
        self.key_file = f"{storage_prefix}_x25519.json"
        self.cert_file = "certificado.der"
        
        self.static_private = None
        self.static_public = None
        self.dnie_cert_der = None
        
        self._load_or_gen_x25519()
        self._load_or_extract_dnie()

    def _load_or_gen_x25519(self):
        if os.path.exists(self.key_file):
            try:
                with open(self.key_file, 'r') as f:
                    data = json.load(f)
                    priv_bytes = bytes.fromhex(data['private_key'])
                    self.static_private = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
            except:
                self._generate_x25519()
        else:
            self._generate_x25519()
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
        if os.path.exists(self.cert_file):
            print(f"✔ Certificado encontrado en {self.cert_file}. Cargando...")
            try:
                with open(self.cert_file, "rb") as f:
                    self.dnie_cert_der = f.read()
            except: pass
        else:
            print(f"⚠ No se encuentra {self.cert_file}. Iniciando extracción DNIe...")
            handler = DNIeHandler()
            handler.login()
            
            _, cert_der = handler.find_auth_certificate()
            if not cert_der:
                print("❌ No se encontró certificado en el DNIe.")
                handler.logout()
                sys.exit(1)
            
            self.dnie_cert_der = cert_der
            with open(self.cert_file, "wb") as f:
                f.write(cert_der)
            print("✔ Certificado extraído y guardado.")
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

    def get_public_bytes(self):
        return self.static_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

class SessionCrypto:
    """Maneja el cifrado de la sesión."""
    def __init__(self, private_key):
        self.my_static_private = private_key
        self.cipher = None
        # Generamos solo la privada
        self.ephemeral_private = x25519.X25519PrivateKey.generate()

    def get_ephemeral_public_bytes(self):
        # --- CORRECCIÓN AQUÍ ---
        # Derivamos la pública desde la privada en el momento
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
        key_material = hkdf.derive(shared_secret)
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
    
    # PEGAR ESTO DENTRO DE LA CLASE SessionCrypto EN crypto.py

    def export_secret(self):
        """Intenta encontrar la clave compartida probando varios nombres comunes"""
        # Lista de posibles nombres que pudiste haber usado
        posibles_nombres = ['shared_key', 'key', 'symmetric_key', 'secret', 'derived_key', 'k']
        
        for nombre in posibles_nombres:
            if hasattr(self, nombre):
                val = getattr(self, nombre)
                if val is not None and isinstance(val, bytes):
                    # ¡Encontrado!
                    return val.hex()
        
        # Si llega aquí, es que no encontró la clave en ninguna variable
        return None

    def load_secret(self, hex_secret):
        """Carga la clave en la variable estándar 'shared_key' (y 'key' por si acaso)"""
        key_bytes = bytes.fromhex(hex_secret)
        self.shared_key = key_bytes
        self.key = key_bytes # Asignamos a ambas para asegurar compatibilidad
        self.symmetric_key = key_bytes
