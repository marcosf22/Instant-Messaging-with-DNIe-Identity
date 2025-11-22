import socket
import logging
import asyncio
from zeroconf import Zeroconf, ServiceInfo, ServiceBrowser, ServiceStateChange

# Configuración del documento
SERVICE_TYPE = "_dni-im._udp.local." # [cite: 7]
CHAT_PORT = 443                       # [cite: 7]

logger = logging.getLogger("Discovery")

class DiscoveryManager:
    def __init__(self, display_name, contacts_callback):
        """
        display_name: Tu nombre (ej. "Alex").
        contacts_callback: Función que se ejecuta al encontrar/perder a alguien.
                           Debe aceptar (action, name, info).
        """
        self.zeroconf = Zeroconf()
        self.display_name = display_name
        self.callback = contacts_callback
        self.browser = None
        self.info = None
        self.running = False

    def _get_local_ip(self):
        """Truco para obtener la IP real de la LAN."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = "127.0.0.1"
        finally:
            s.close()
        return ip

    def on_service_state_change(self, zeroconf, service_type, name, state_change):
        """
        Este método se ejecuta AUTOMÁTICAMENTE en segundo plano
        cada vez que hay movimiento en la red.
        """
        if state_change is ServiceStateChange.Added or state_change is ServiceStateChange.Updated:
            # Alguien ha aparecido o se ha actualizado
            info = zeroconf.get_service_info(service_type, name)
            if info:
                # Llamamos al callback de forma thread-safe para asyncio
                self.callback("ADD", name, info)
        
        elif state_change is ServiceStateChange.Removed:
            # Alguien se ha ido
            self.callback("REMOVE", name, None)

    async def start(self):
        """Inicia el anuncio y la escucha de forma constante."""
        self.running = True
        local_ip = self._get_local_ip()

        # 1. PREPARAR EL ANUNCIO (Advertising)
        # Esto se queda activo hasta que llamemos a close()
        self.info = ServiceInfo(
            type_=SERVICE_TYPE,
            name=f"{self.display_name}.{SERVICE_TYPE}",
            addresses=[socket.inet_aton(local_ip)],
            port=CHAT_PORT,  # [cite: 7] Anunciamos puerto 443
            properties={
                b'name': self.display_name.encode()
                # Aquí meteremos el DNIe fingerprint luego
            },
            server=f"{self.display_name}.local."
        )
        
        logger.info(f"[*] Anunciando {self.display_name} en {local_ip}:{CHAT_PORT}")
        self.zeroconf.register_service(self.info)

        # 2. INICIAR LA ESCUCHA (Browsing)
        # ServiceBrowser crea sus propios hilos y se queda "vivo" buscando.
        logger.info("[*] Escuchando tráfico mDNS...")
        self.browser = ServiceBrowser(
            self.zeroconf, 
            SERVICE_TYPE, 
            handlers=[self.on_service_state_change]
        )

        # No necesitamos un bucle aquí, zeroconf ya corre en background.
        # Solo devolvemos el control para que asyncio siga con otras cosas (TUI/Chat).

    async def stop(self):
        """Detiene todo limpiamente."""
        logger.info("Deteniendo Discovery...")
        self.running = False
        if self.browser:
            self.browser.cancel()
        if self.info:
            self.zeroconf.unregister_service(self.info)
        self.zeroconf.close()

# --- CÓDIGO DE PRUEBA (Simulación del bucle principal) ---
if __name__ == "__main__":
    # Configurar logs
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

    # Esta función simula lo que hará tu Interfaz (TUI) cuando llegue un contacto
    def update_contacts_ui(action, name, info):
        if action == "ADD":
            addr = socket.inet_ntoa(info.addresses[0])
            print(f"\n>>> TUI UPDATE: Nuevo usuario detectado: {name} ({addr}:{info.port})")
        elif action == "REMOVE":
            print(f"\n>>> TUI UPDATE: Usuario desconectado: {name}")

    async def main():
        # Instanciamos el gestor
        discovery = DiscoveryManager("MiUsuario", update_contacts_ui)
        
        # Arrancamos (esto no bloquea, solo inicia los servicios)
        await discovery.start()

        print("--- SISTEMA CORRIENDO (Ctrl+C para salir) ---")
        print("--- Tu nodo está visible y buscando peers constantemente ---")
        
        # Mantenemos el programa vivo para simular que la app está abierta
        try:
            while True:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass
        finally:
            await discovery.stop()

    # Ejecutar con asyncio
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
