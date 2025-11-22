import socket
import logging
from typing import Callable, Optional
from zeroconf import Zeroconf, ServiceInfo, ServiceBrowser, ServiceStateChange

# Configuración definida en el documento
SERVICE_TYPE = "_dni-im._udp.local."
CHAT_PORT = 443  # [cite: 7, 11] El tráfico real va por el 443, aunque mDNS usa 5353

# Configurar logging básico para ver qué pasa
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Discovery")

def get_local_ip():
    """Obtiene la IP local de la interfaz que sale a internet/LAN."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # No se envía nada, solo se usa para determinar la ruta
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

class DiscoveryListener:
    """Clase callback que maneja los eventos de encontrar/perder peers."""
    
    def __init__(self, on_peer_update: Callable):
        self.on_peer_update = on_peer_update

    def remove_service(self, zeroconf, type, name):
        logger.info(f"Peer desconectado: {name}")
        # Notificamos con data=None para indicar borrado
        self.on_peer_update(name, None)

    def add_service(self, zeroconf, type, name):
        logger.info(f"Peer encontrado: {name}")
        # Intentamos resolver la info completa (IP, Puerto, TXT records)
        info = zeroconf.get_service_info(type, name)
        if info:
            self.on_peer_update(name, info)

    def update_service(self, zeroconf, type, name):
        # Para simplificar, tratamos la actualización como un 'add'
        self.add_service(zeroconf, type, name)

class DiscoveryService:
    def __init__(self, display_name: str, on_peer_found_callback: Callable):
        self.zeroconf = Zeroconf()
        self.display_name = display_name
        self.local_ip = get_local_ip()
        self.callback = on_peer_found_callback
        self.browser = None
        self.info = None

    def start_advertising(self):
        """
        Anuncia nuestra presencia en la red (mDNS Advertising).
        Punta al puerto 443 donde escuchará nuestro servidor UDP.
        """
        # El nombre debe ser único en la red: "Nombre._dni-im._udp.local."
        service_name = f"{self.display_name}.{SERVICE_TYPE}"
        
        # Aquí construimos el paquete que explicamos antes
        self.info = ServiceInfo(
            type_=SERVICE_TYPE,
            name=service_name,
            addresses=[socket.inet_aton(self.local_ip)], # IP en bytes
            port=CHAT_PORT,                              # Puerto 443 
            properties={
                # Aquí pondremos el fingerprint del DNIe más adelante 
                b'version': b'0.1', 
                b'display_name': self.display_name.encode('utf-8')
            },
            server=f"{self.display_name}.local."
        )

        logger.info(f"Anunciando presencia: {service_name} en {self.local_ip}:{CHAT_PORT}")
        self.zeroconf.register_service(self.info)

    def start_browsing(self):
        """
        Empieza a buscar otros peers en la red (mDNS Browsing).
        """
        logger.info(f"Buscando peers en {SERVICE_TYPE}...")
        listener = DiscoveryListener(self.callback)
        self.browser = ServiceBrowser(self.zeroconf, SERVICE_TYPE, listener)

    def stop(self):
        """Limpia los recursos al cerrar el programa."""
        if self.info:
            self.zeroconf.unregister_service(self.info)
        if self.browser:
            self.browser.cancel()
        self.zeroconf.close()

# --- BLOQUE DE PRUEBA (Para ejecutar este archivo solo) ---
if __name__ == "__main__":
    import time

    # Función simple para imprimir cuando encontramos a alguien
    def print_peer(name, info):
        if info:
            # Convertir dirección IP de bytes a string
            address = socket.inet_ntoa(info.addresses[0])
            print(f"\n[+] NUEVO CONTACTO: {name}")
            print(f"    IP: {address} | Puerto: {info.port}")
            print(f"    Datos extra (TXT): {info.properties}")
        else:
            print(f"\n[-] CONTACTO PERDIDO: {name}")

    # Simular usuario "UsuarioPrueba"
    disco = DiscoveryService("UsuarioPrueba", print_peer)
    
    try:
        disco.start_advertising()
        disco.start_browsing()
        
        print("Presiona Ctrl+C para salir...")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Cerrando...")
        disco.stop()
