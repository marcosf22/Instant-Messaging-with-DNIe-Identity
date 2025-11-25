import os, sys, time, json, getpass, hashlib, PyKCS11

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM

from smartcard.System import readers

# Configuración para acceder a la librería para gestionar el DNIe (windows).
DLL_PATH = r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"
PROTOCOL_NAME = b"Noise_IK_25519_ChaChaPoly_BLAKE2s"
CERT_FILE = "certificado.der"


# En esta clase definimos las funciones que tiene el DNIe.
class DNIeHandler:


    # Abrimos la librería.
    def __init__(self):
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        try: self.lib = self.pkcs11.load(DLL_PATH)
        except: print(f"❌ Error al importar librería: {DLL_PATH}"); sys.exit(1)
        self.session = None
        self.slot = None


    # Abrimos una sesión del DNIe para firmar y extraer el certificado.
    def login_inicial(self):
        print("\n=== ACCESO SEGURO CON DNIe ===")
        lectores = []
        while not lectores:
            try: lectores = readers()
            except: pass
            if not lectores: print("⌛ Esperando lector...", end="\r"); time.sleep(1)
        
        slots = []
        while not slots:
            try: slots = self.pkcs11.getSlotList(tokenPresent=True)
            except: pass
            if not slots: print("⌛ Esperando DNIe...", end="\r"); time.sleep(1)
        
        self.slot = slots[0]
        print(f"✅ Tarjeta detectada.")
        
        pwd = None
        while not pwd:
            print("") 
            pwd = getpass.getpass("Introduce PIN: ")
        

        # La llave maestra sirve para encriptar y desencriptar el contenido del JSON del usuario.
        master_key = None
        try:
            self.session = self.pkcs11.openSession(self.slot)
            self.session.login(pwd)
            print('✅ PIN Correcto. Sesión establecida.')
            
            # Borramos el PIN de la memoria inmediatamente.
            del pwd 
            
            # Generar clave maestra (simplemente es una palabra firmada). 
            keys = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])
            priv = keys[0]
            for k in keys:
                l = self.session.getAttributeValue(k, [PyKCS11.CKA_LABEL])
                if l and l[0] == "KprivAutenticacion": priv = k; break
            
            mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
            signature = bytes(self.session.sign(priv, b"MASTER_KEY_SEED", mech))
            master_key = hashlib.sha256(signature).digest()
            
            return True, master_key
        except Exception as e:
            print(f"❌ Error PIN: {e}")
            self.cerrar()
            return False, None


    # Función que firma los datos introducimos con la clave privada del DNIe.
    def firmar_rapido(self, datos):
        """Usa la sesión YA ABIERTA para firmar"""
        if not self.session: 
            print("❌ Sesión perdida.")
            return None, None
        
        try:

            # Obtenemos el certificado (si tenemos uno ya en el directorio usamos ese).
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

            # Obtenemos la clave privada de autenticación.
            keys = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])
            priv = keys[0]
            for k in keys:
                l = self.session.getAttributeValue(k, [PyKCS11.CKA_LABEL])
                if l and l[0] == "KprivAutenticacion": priv = k; break

            # Firmamos los datos introducidos (en bytes).
            mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
            sig = bytes(self.session.sign(priv, datos, mech))
            
            return cert_der, sig
        except Exception as e: 
            print(f"Error firma: {e}")
            return None, None

    def cerrar(self):
        if self.session:
            try: self.session.logout(); self.session.closeSession()
            except: pass
            self.session = None


# Clase que gestiona las funciones de encriptado y desencriptado.
class KeyManager:
    def __init__(self, prefix):
        self.dnie = DNIeHandler()
        self.disk_key = None


    # Iniciamos sesión con el DNIe y obtenemos la llave maestra.
    def iniciar_sesion_dnie(self):
        success, key = self.dnie.login_inicial()
        if success: self.disk_key = key
        return success


    # Firma de las claves dentro del handshake.
    def firmar_handshake(self, datos):
        return self.dnie.firmar_rapido(datos)


    # Función que nos permite verificar el handshake y obtener el nombre del remitente.
    def verificar_handshake(self, clave, cert_der, firma):
        try:
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            cert.public_key().verify(firma, clave, padding.PKCS1v15(), hashes.SHA256())
            cn = "Desconocido"
            for a in cert.subject:
                if a.oid == x509.NameOID.COMMON_NAME: cn = a.value
            return True, cn
        except Exception as e: return False, str(e)
    

    # Función que encripta el JSON donde guardamos las claves de sesión con nuestros contactos y los mensajes.
    def encrypt_disk_data(self, text):
        if not self.disk_key: return None
        aes = AESGCM(self.disk_key)
        n = os.urandom(12)
        return n + aes.encrypt(n, text.encode('utf-8'), None)


    # Función que desencripta el JSON.
    def decrypt_disk_data(self, data):
        if not self.disk_key: return None
        try:
            aes = AESGCM(self.disk_key)
            return aes.decrypt(data[:12], data[12:], None).decode('utf-8')
        except: return None


# Esta clase nos define las funciones para generar y leer las claves para el handshake.
class SessionCrypto:


    # Generamos unas claves nuevas para cada conversación.
    def __init__(self):
        self.ephemeral = x25519.X25519PrivateKey.generate()
        self.cipher = None
        self.shared_key = None


    # Extraemos la clave pública.
    def get_public_bytes(self):
        return self.ephemeral.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


    # Combinamos la clave pública del otro extremo con nuestra privada para obtener las claves simétricas.
    def compute_secret(self, peer_bytes):
        peer = x25519.X25519PublicKey.from_public_bytes(peer_bytes)
        shared = self.ephemeral.exchange(peer)
        hkdf = HKDF(hashes.BLAKE2s(32), 32, None, info=PROTOCOL_NAME)
        self.shared_key = hkdf.derive(shared)
        self.cipher = ChaCha20Poly1305(self.shared_key)


    # Función para encriptar el mensaje. Le pasamos el número con el que hemos cifrado para que pueda descifrarlo luego el extremo.
    def encrypt(self, txt):
        if not self.cipher: raise Exception("No Key")
        n = os.urandom(12)
        return n + self.cipher.encrypt(n, txt.encode(), None)


    # Desencriptación del mensaje usando el número que viene en los primeros bytes del mensaje y la clave que hemos guardado antes.
    def decrypt(self, data):
        if not self.cipher: raise Exception("No Key")
        return self.cipher.decrypt(data[:12], data[12:], None).decode()


    # Función que nos permite exportar las claves al JSON para futuras conexiones.
    def export_secret(self): return self.shared_key.hex() if self.shared_key else None


    # Cargamos las claves del JSON.
    def load_secret(self, hx): 
        self.shared_key = bytes.fromhex(hx)
        self.cipher = ChaCha20Poly1305(self.shared_key)