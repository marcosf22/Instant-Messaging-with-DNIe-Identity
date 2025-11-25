import os
import sys
import time
import json
import getpass

# Criptografía
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# DNIe
import PyKCS11
from smartcard.System import readers

# --- RUTA DE TU DRIVER (Ajusta esto) ---
DLL_PATH = r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"

# --- GESTOR DEL DNIe (Hardware) ---
class DNIeHandler:
    def __init__(self):
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        try: self.lib = self.pkcs11.load(DLL_PATH)
        except: print("❌ Error cargando DLL DNIe"); sys.exit(1)
        self.session = None

    def login_y_firmar(self, datos_a_firmar):
        """
        1. Pide el PIN (LOCALMENTE).
        2. Lo envía a la tarjeta.
        3. La tarjeta firma los datos DENTRO DEL CHIP.
        4. Devuelve SOLO LA FIRMA y el CERTIFICADO PÚBLICO.
        ¡EL PIN SE DESTRUYE AQUÍ Y NO SALE!
        """
        print("⌛ Buscando lector DNIe...")
        while True:
            try:
                if self.pkcs11.getSlotList(tokenPresent=True): break
            except: pass
            time.sleep(1)
        
        # --- AQUÍ PEDIMOS EL PIN (LOCAL) ---
        pin_local = getpass.getpass("👉 Introduce PIN DNIe para firmar: ")
        
        try:
            slot = self.pkcs11.getSlotList(tokenPresent=True)[0]
            self.session = self.pkcs11.openSession(slot)
            self.session.login(pin_local) # Se envía al chip, no a la red
            del pin_local # Borramos el PIN de la memoria RAM inmediatamente
            print("✅ Chip desbloqueado. Firmando...")
        except Exception as e:
            print(f"❌ PIN Incorrecto: {e}"); return None, None

        # --- BUSCAR CERTIFICADO Y FIRMAR ---
        try:
            # 1. Buscar Certificado de Firma/Autenticación
            objs = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])
            cert_der = None
            for obj in objs:
                val = self.session.getAttributeValue(obj, [PyKCS11.CKA_VALUE], True)
                if val:
                    raw_cert = bytes(val[0])
                    x509_cert = x509.load_der_x509_certificate(raw_cert, default_backend())
                    # Usamos el de firma o autenticación
                    if "AUTENTICA" in x509_cert.subject.rfc4514_string().upper():
                        cert_der = raw_cert; break
            
            # 2. Buscar Clave Privada (Dentro del chip)
            keys = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])
            priv_key = keys[0] # Simplificación: cogemos la primera llave privada disponible
            
            # 3. FIRMAR EL PAQUETE (Handshake Key)
            mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
            
            # ¡ESTO ES LO QUE SE ENVÍA! LA FIRMA MATEMÁTICA
            firma_digital = bytes(self.session.sign(priv_key, datos_a_firmar, mech))
            
            self.session.logout()
            self.session.closeSession()
            
            return cert_der, firma_digital
            
        except Exception as e:
            print(f"❌ Error al firmar: {e}")
            return None, None

# --- GESTOR DE IDENTIDAD (X25519) ---
class KeyManager:
    def __init__(self, prefix="identity"):
        self.key_file = f"{prefix}_x25519.json"
        self.static_private = None
        self.static_public = None
        self._load_keys()

    def _load_keys(self):
        if os.path.exists(self.key_file):
            with open(self.key_file, 'r') as f:
                d = json.load(f)
                self.static_private = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(d['priv']))
        else:
            self.static_private = x25519.X25519PrivateKey.generate()
            with open(self.key_file, 'w') as f:
                json.dump({'priv': self.static_private.private_bytes(
                    serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
                ).hex()}, f)
        self.static_public = self.static_private.public_key()

    def obtener_mi_clave_publica_bytes(self):
        """Devuelve mi clave de chat (32 bytes) para enviarla"""
        return self.static_public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def generar_paquete_verificacion(self):
        """
        Genera el paquete que demuestra tu identidad:
        1. Coge tu Clave Pública de Chat.
        2. Usa el DNIe para firmarla.
        3. Devuelve: [Certificado] + [Firma]
        """
        mis_bytes_chat = self.obtener_mi_clave_publica_bytes()
        
        handler = DNIeHandler()
        # Aquí te pedirá el PIN, pero solo devuelve la firma resultante
        cert_der, firma = handler.login_y_firmar(mis_bytes_chat)
        
        return cert_der, firma

    def verificar_identidad_del_otro(self, su_clave_chat_bytes, su_cert_der, su_firma):
        """
        Verifica que la clave de chat del otro usuario fue firmada por su DNIe.
        """
        try:
            # 1. Cargar el certificado del DNIe del otro
            cert = x509.load_der_x509_certificate(su_cert_der, default_backend())
            rsa_public_key = cert.public_key()
            
            # 2. Comprobar la firma:
            # ¿Es 'su_firma' válida para los datos 'su_clave_chat' usando la 'rsa_public_key'?
            rsa_public_key.verify(
                su_firma,
                su_clave_chat_bytes, # <--- VERIFICAMOS QUE FIRMÓ SU CLAVE DE CHAT
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            
            # 3. Extraer nombre real
            nombre_real = "Desconocido"
            for attr in cert.subject:
                if attr.oid == x509.NameOID.COMMON_NAME:
                    nombre_real = attr.value
            
            return True, nombre_real
        except Exception as e:
            return False, str(e)

# --- CLASE DE SESIÓN (Persistencia) ---
class SessionCrypto:
    def __init__(self, private_key):
        self.ephemeral = x25519.X25519PrivateKey.generate()
        self.cipher = None
        self.shared_key = None 

    def get_ephemeral_public_bytes(self):
        return self.ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def perform_handshake(self, peer_bytes, is_initiator=True):
        peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_bytes)
        shared = self.ephemeral.exchange(peer_pub)
        hkdf = HKDF(hashes.BLAKE2s(32), 32, None, b"CHAT_V1")
        self.shared_key = hkdf.derive(shared)
        self.cipher = ChaCha20Poly1305(self.shared_key)

    def encrypt(self, txt):
        nonce = os.urandom(12)
        return nonce + self.cipher.encrypt(nonce, txt.encode(), None)

    def decrypt(self, data):
        return self.cipher.decrypt(data[:12], data[12:], None).decode()

    def export_secret(self): return self.shared_key.hex() if self.shared_key else None
    def load_secret(self, hx): 
        self.shared_key = bytes.fromhex(hx)
        self.cipher = ChaCha20Poly1305(self.shared_key)
