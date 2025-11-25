import os
import sys
import time
import json
import getpass

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519, padding

# DNIe
import PyKCS11
from smartcard.System import readers

# --- AJUSTA TU RUTA DLL AQUÍ ---
DLL_PATH = r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"
# DLL_PATH = r"C:\Windows\System32\DNIe_P11_priv.dll"

# --- Parte DNIe (Igual que antes) ---
class DNIeHandler:
    def __init__(self):
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        try:
            self.lib = self.pkcs11.load(DLL_PATH)
        except Exception as e:
            print(f"❌ Error cargando DLL ({DLL_PATH}): {e}")
            sys.exit(1)
        self.session = None
        self.slot = None

    def wait_for_card(self):
        print("⌛ Buscando lector y tarjeta...", end="", flush=True)
        # Intentamos hasta 10 veces para no bloquear eternamente
        intentos = 0
        while intentos < 20:
            try:
                # tokenPresent=True es clave para no listar lectores vacíos
                slots = self.pkcs11.getSlotList(tokenPresent=True)
                if slots:
                    self.slot = slots[0]
                    print(" [Detectada]")
                    return True
            except:
                pass
            
            print(".", end="", flush=True)
            time.sleep(1)
            intentos += 1
        
        print("\n❌ Tiempo de espera agotado. ¿Está el DNIe bien insertado?")
        return False

    def login(self):
        # 1. Asegurar que hay tarjeta
        if not self.wait_for_card():
            raise Exception("No se detectó tarjeta")

        # 2. Intentamos limpiar sesiones previas bloqueadas
        try:
            self.session = self.pkcs11.openSession(self.slot)
            self.session.logout()
            self.session.closeSession()
        except: pass # Si falla no pasa nada, era por limpiar

        # 3. Abrir sesión limpia
        try:
            self.session = self.pkcs11.openSession(self.slot)
        except Exception as e:
            raise Exception(f"No se pudo abrir sesión con el chip: {e}")

        # 4. PEDIR PIN (Con cuidado)
        # A veces el driver oficial saca un popup. OpenSC pide por consola.
        print("\n" + "-"*40)
        print("🔐 SEGURIDAD DNIe")
        print("   Si sale una ventana emergente, pon el PIN ahí.")
        print("   Si no sale nada, escríbelo aquí abajo.")
        print("-" * 40)
        sys.stdout.flush() # Obligar a mostrar el texto

        # Intentamos login nulo primero (algunos drivers lo requieren para sacar el popup)
        try:
            self.session.login(None) 
            print("✅ Login automático (Popup detectado).")
            return
        except:
            # Si falla el nulo, es que necesitamos meter el PIN manual
            pass

        # Login Manual
        pwd = getpass.getpass("👉 Introduce el PIN aquí: ")
        try:
            self.session.login(pwd)
            print("✅ PIN Correcto.")
        except Exception as e:
            print(f"❌ Error de PIN: {e}")
            # Importante: cerrar sesión si falla para no bloquear el DNI
            self.logout()
            raise e

    def logout(self):
        if self.session:
            try:
                self.session.logout()
                self.session.closeSession()
            except: pass
            self.session = None

    # (El resto de métodos find_auth_certificate y find_private_key déjalos igual...)
    def find_auth_cert_and_sign(self, data_to_sign):
        # Copia aquí el contenido de la función find_auth_cert_and_sign que te pasé
        # en el mensaje anterior ("Dame el codigo completo de ambos programas").
        # Es vital que esa función esté dentro de esta clase.
        # ... (código anterior) ...
        # (Si no lo tienes a mano dímelo y te lo repego, pero es largo)
        
        # --- REPEGO LA LÓGICA DE FIRMA AQUÍ PARA QUE NO FALTE ---
        objs = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])
        cert_der = None
        for obj in objs:
            try:
                val = self.session.getAttributeValue(obj, [PyKCS11.CKA_VALUE], True)
                if val:
                    tmp_cert = bytes(val[0])
                    c = x509.load_der_x509_certificate(tmp_cert, default_backend())
                    subj = c.subject.rfc4514_string().upper()
                    if "AUTENTICA" in subj or "FIRMA" in subj:
                        cert_der = tmp_cert
                        break
            except: continue
            
        keys = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])
        priv_key = None
        for k in keys:
            label = self.session.getAttributeValue(k, [PyKCS11.CKA_LABEL])
            if label and label[0] == "KprivAutenticacion":
                priv_key = k; break
        if not priv_key and keys: priv_key = keys[0]
        
        mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
        signature = bytes(self.session.sign(priv_key, data_to_sign, mech))
        return cert_der, signature

# --- GESTOR DE CLAVES ---
class KeyManager:
    def __init__(self, prefix="identity"):
        self.key_file = f"{prefix}_x25519.json"
        self.static_private = None
        self.static_public = None
        self._load_keys()

    def _load_keys(self):
        if os.path.exists(self.key_file):
            try:
                with open(self.key_file, 'r') as f:
                    d = json.load(f)
                    self.static_private = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(d['priv']))
            except: self._gen_keys()
        else: self._gen_keys()
        self.static_public = self.static_private.public_key()

    def _gen_keys(self):
        self.static_private = x25519.X25519PrivateKey.generate()
        pk = self.static_private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        with open(self.key_file, 'w') as f: json.dump({'priv': pk.hex()}, f)

    def get_my_identity_pack(self):
        """Genera el paquete de identidad: [MiClaveChat + Certificado + Firma]"""
        # 1. Obtener bytes de mi clave de chat
        pub_bytes = self.static_public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        
        # 2. Firmar esos bytes con el DNIe
        handler = DNIeHandler()
        handler.login()
        cert_der, signature = handler.find_auth_cert_and_sign(pub_bytes)
        handler.logout()
        
        return pub_bytes, cert_der, signature

    def verify_peer_identity(self, static_key_bytes, cert_der, signature):
        """Verifica matemáticamente que el DNIe firmó la clave del chat"""
        try:
            # 1. Cargar certificado
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            rsa_pub = cert.public_key()
            
            # 2. Verificar firma RSA (Sha256)
            rsa_pub.verify(
                signature,
                static_key_bytes,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            
            # 3. Extraer nombre
            cn = "Desconocido"
            for attr in cert.subject:
                if attr.oid == x509.NameOID.COMMON_NAME:
                    cn = attr.value
            
            return True, cn
        except Exception as e:
            return False, str(e)

# --- SESIÓN CHAT ---
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

class SessionCrypto:
    def __init__(self, private_key):
        self.ephemeral = x25519.X25519PrivateKey.generate()
        self.cipher = None
        self.shared_key = None

    def get_ephemeral_public_bytes(self):
        return self.ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def perform_handshake(self, peer_bytes, is_initiator=True):
        peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_bytes)
        secret = self.ephemeral.exchange(peer_pub)
        hkdf = HKDF(hashes.BLAKE2s(32), 32, None, b"CHAT_V1")
        self.shared_key = hkdf.derive(secret)
        self.cipher = ChaCha20Poly1305(self.shared_key)

    def encrypt(self, txt):
        nonce = os.urandom(12)
        return nonce + self.cipher.encrypt(nonce, txt.encode(), None)

    def decrypt(self, data):
        return self.cipher.decrypt(data[:12], data[12:], None).decode()

    def export_secret(self):
        return self.shared_key.hex() if self.shared_key else None
    
    def load_secret(self, hx):
        self.shared_key = bytes.fromhex(hx)
        self.cipher = ChaCha20Poly1305(self.shared_key)
