import os
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Constantes del protocolo
PROTOCOL_NAME = b"Noise_IK_25519_ChaChaPoly_BLAKE2s"

class KeyManager:
    """
    Simula el comportamiento del DNIe y gestiona las claves.
    Guarda la clave privada en un archivo JSON local (identity_mock.json).
    """
    def __init__(self, storage_file="identity_mock.json"):
        self.storage_file = storage_file
        self.static_private = None
        self.static_public = None
        self._load_or_generate_identity()

    def _load_or_generate_identity(self):
        """Carga la identidad o crea una nueva si no existe."""
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, 'r') as f:
                    data = json.load(f)
                    priv_bytes = bytes.fromhex(data['private_key'])
                    self.static_private = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
            except Exception as e:
                print(f"Error cargando identidad, regenerando: {e}")
                self._generate_new_identity()
        else:
            self._generate_new_identity()

        # Derivamos la pública siempre de la privada
        self.static_public = self.static_private.public_key()

    def _generate_new_identity(self):
        """Genera un par de claves X25519 y las guarda."""
        self.static_private = x25519.X25519PrivateKey.generate()
        
        priv_bytes = self.static_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        with open(self.storage_file, 'w') as f:
            json.dump({'private_key': priv_bytes.hex()}, f)

    def get_public_bytes(self):
        """Devuelve la clave pública en bytes raw (32 bytes)."""
        return self.static_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

class SessionCrypto:
    """
    Maneja la criptografía de una sesión de chat (Noise IK).
    """
    def __init__(self, private_key: x25519.X25519PrivateKey):
        self.my_static_private = private_key
        self.cipher = None
        
        # Clave efímera para esta sesión específica
        self.ephemeral_private = x25519.X25519PrivateKey.generate()
        self.ephemeral_public = self.ephemeral_private.public_key()

    def get_ephemeral_public_bytes(self):
        return self.ephemeral_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def perform_handshake(self, peer_public_bytes: bytes, is_initiator: bool):
        """
        Realiza el intercambio Diffie-Hellman y deriva las claves de sesión.
        """
        peer_public = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
        
        # Intercambio ECDH
        shared_secret = self.ephemeral_private.exchange(peer_public)

        # Derivación de clave (HKDF)
        # CORRECCIÓN: BLAKE2s(32) significa digest de 32 bytes (256 bits)
        hkdf = HKDF(
            algorithm=hashes.BLAKE2s(32),
            length=32,
            salt=None,
            info=PROTOCOL_NAME,
        )
        key_material = hkdf.derive(shared_secret)
        
        # Inicializamos el cifrador AEAD
        self.cipher = ChaCha20Poly1305(key_material)
        return True

    def encrypt(self, plaintext: str) -> bytes:
        """Cifra texto a bytes."""
        if not self.cipher:
            raise Exception("Handshake no completado")
        
        nonce = os.urandom(12)
        data = plaintext.encode('utf-8')
        ciphertext = self.cipher.encrypt(nonce, data, None)
        
        return nonce + ciphertext

    def decrypt(self, payload: bytes) -> str:
        """Descifra bytes a texto."""
        if not self.cipher:
            raise Exception("Handshake no completado")
        
        nonce = payload[:12]
        ciphertext = payload[12:]
        
        plaintext_bytes = self.cipher.decrypt(nonce, ciphertext, None)
        return plaintext_bytes.decode('utf-8')

# --- PRUEBA UNITARIA ---
if __name__ == "__main__":
    print("--- TEST DE CRIPTOGRAFÍA (MOCK) ---")
    
    # 1. Identidades
    alice_mgr = KeyManager("alice_identity.json")
    bob_mgr = KeyManager("bob_identity.json")
    
    print(f"Alice PubKey: {alice_mgr.get_public_bytes().hex()[:10]}...")
    print(f"Bob PubKey:   {bob_mgr.get_public_bytes().hex()[:10]}...")

    # 2. Sesión
    alice_session = SessionCrypto(alice_mgr.static_private)
    bob_session = SessionCrypto(bob_mgr.static_private)

    # Simulamos intercambio
    alice_msg = alice_session.get_ephemeral_public_bytes() 
    bob_msg = bob_session.get_ephemeral_public_bytes()    

    # 3. Handshake
    alice_session.perform_handshake(bob_msg, is_initiator=True)
    bob_session.perform_handshake(alice_msg, is_initiator=False)

    # 4. Chat
    msg = "Hola mundo seguro!"
    encrypted = alice_session.encrypt(msg)
    print(f"\nAlice envía cifrado: {encrypted.hex()[:20]}...")
    
    decrypted = bob_session.decrypt(encrypted)
    print(f"Bob lee: {decrypted}")
    
    assert msg == decrypted
    print("\n[OK] Prueba exitosa.")