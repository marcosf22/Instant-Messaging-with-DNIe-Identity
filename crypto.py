import os
import sys
import time
import json
import getpass
import struct

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

import PyKCS11
from smartcard.System import readers

# RUTA DLL (Ajústala)
DLL_PATH = r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"

class DNIeHandler:
    def __init__(self):
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        try: self.lib = self.pkcs11.load(DLL_PATH)
        except: print("❌ Error DLL"); sys.exit(1)
    
    def firmar_bytes(self, datos):
        """Pide PIN y devuelve Certificado + Firma"""
        print("\n⏳ Buscando DNIe...")
        while True:
            try:
                if self.pkcs11.getSlotList(tokenPresent=True): break
            except: pass
            time.sleep(1)
        
        # PIN LOCAL
        pwd = getpass.getpass("🔑 Introduce PIN para firmar el Handshake: ")
        
        try:
            session = self.pkcs11.openSession(self.pkcs11.getSlotList(tokenPresent=True)[0])
            session.login(pwd)
            del pwd
            print("✅ Chip desbloqueado. Firmando clave...")
        except: 
            print("❌ PIN Incorrecto"); return None, None

        # Buscar cert y privkey
        objs = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])
        cert_der = None
        for obj in objs:
            val = session.getAttributeValue(obj, [PyKCS11.CKA_VALUE], True)
            if val:
                tmp = bytes(val[0])
                c = x509.load_der_x509_certificate(tmp, default_backend())
                if "AUTENTICA" in c.subject.rfc4514_string().upper():
                    cert_der = tmp; break
        
        keys = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])
        priv_key = keys[0] # Simplificado
        
        mech = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
        signature = bytes(session.sign(priv_key, datos, mech))
        
        session.logout()
        session.closeSession()
        return cert_der, signature

class KeyManager:
    def __init__(self, prefix):
        # Aquí solo usamos identidad para logs, ya no guardamos claves estáticas X25519
        # Porque la autenticación la da el DNIe
        pass

    def firmar_handshake(self, clave_temporal_bytes):
        """Usa el DNIe para firmar la clave que vamos a enviar"""
        handler = DNIeHandler()
        cert_der, firma = handler.firmar_bytes(clave_temporal_bytes)
        return cert_der, firma

    def verificar_handshake(self, clave_temporal_recibida, cert_der, firma):
        """Comprueba que la clave recibida fue firmada por ese DNIe"""
        try:
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            pub_rsa = cert.public_key()
            
            pub_rsa.verify(
                firma,
                clave_temporal_recibida,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            
            # Extraer nombre
            cn = "Desconocido"
            for a in cert.subject:
                if a.oid == x509.NameOID.COMMON_NAME: cn = a.value
            return True, cn
        except Exception as e:
            return False, str(e)

class SessionCrypto:
    def __init__(self):
        self.ephemeral = x25519.X25519PrivateKey.generate()
        self.cipher = None
        self.shared_key = None

    def get_public_bytes(self):
        return self.ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def compute_secret(self, peer_bytes):
        peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_bytes)
        shared = self.ephemeral.exchange(peer_pub)
        hkdf = HKDF(hashes.BLAKE2s(32), 32, None, b"CHAT_DNIE_V2")
        self.shared_key = hkdf.derive(shared)
        self.cipher = ChaCha20Poly1305(self.shared_key)

    def encrypt(self, txt):
        nonce = os.urandom(12)
        return nonce + self.cipher.encrypt(nonce, txt.encode(), None)

    def decrypt(self, data):
        return self.cipher.decrypt(data[:12], data[12:], None).decode()