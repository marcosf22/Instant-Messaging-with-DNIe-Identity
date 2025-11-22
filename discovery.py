import socket
import logging
import asyncio
from zeroconf import ServiceStateChange
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

# Configuración del documento
SERVICE_TYPE = "_dni-im._udp.local."
CHAT_PORT = 8888

logger = logging.getLogger("Discovery")

class DiscoveryManager:
    def __init__(self, display_name, contacts_callback):
        self.aio_zeroconf = None 
        self.display_name = display_name
        self.callback = contacts_callback
        self.browser = None
        self.info = None

    def _get_local_ip(self):
        """Obtiene la IP local de la interfaz principal."""
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
        """Callback para cambios en la red."""
        asyncio.ensure_future(self._process_service_change(zeroconf, service_type, name, state_change))

    async def _process_service_change(self, zeroconf, service_type, name, state_change):
        if state_change is ServiceStateChange.Added or state_change is ServiceStateChange.Updated:
            # CORRECCIÓN: Usamos self.aio_zeroconf.async_get_service_info
            # en lugar de zeroconf.get_service_info
            if self.aio_zeroconf:
                info = await self.aio_zeroconf.async_get_service_info(service_type, name)
                if info:
                    self.callback("ADD", name, info)
        
        elif state_change is ServiceStateChange.Removed:
            self.callback("REMOVE", name, None)

    async def start(self):
        """Inicia el anuncio y la escucha usando AsyncZeroconf."""
        local_ip = self._get_local_ip()
        
        # 1. Inicializar AsyncZeroconf
        self.aio_zeroconf = AsyncZeroconf()

        # 2. PREPARAR EL ANUNCIO (Advertising)
        self.info = AsyncServiceInfo(
            type_=SERVICE_TYPE,
            name=f"{self.display_name}.{SERVICE_TYPE}",
            addresses=[socket.inet_aton(local_ip)],
            port=CHAT_PORT,
            properties={
                b'name': self.display_name.encode()
            },
            server=f"{self.display_name}.local."
        )
        
        logger.info(f"[*] Anunciando {self.display_name} en {local_ip}:{CHAT_PORT}")
        
        await self.aio_zeroconf.async_register_service(self.info)

        # 3. INICIAR LA ESCUCHA (Browsing)
        logger.info("[*] Escuchando tráfico mDNS...")
        self.browser = AsyncServiceBrowser(
            self.aio_zeroconf.zeroconf, 
            SERVICE_TYPE, 
            handlers=[self.on_service_state_change]
        )

    async def stop(self):
        """Detiene todo limpiamente."""
        logger.info("Deteniendo Discovery...")
        if self.browser:
            self.browser.cancel()
        
        if self.info and self.aio_zeroconf:
            await self.aio_zeroconf.async_unregister_service(self.info)
        
        if self.aio_zeroconf:
            await self.aio_zeroconf.async_close()

# --- CÓDIGO DE PRUEBA ---
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

    def update_contacts_ui(action, name, info):
        if action == "ADD":
            if info.addresses:
                addr = socket.inet_ntoa(info.addresses[0])
                print(f">>> NUEVO USUARIO: {name} ({addr}:{info.port})")
        elif action == "REMOVE":
            print(f">>> USUARIO DESCONECTADO: {name}")

    async def main():
        discovery = DiscoveryManager("Marcos", update_contacts_ui)
        
        try:
            await discovery.start()
            print("--- CORRIENDO (Ctrl+C para salir) ---")
            while True:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass
        finally:
            await discovery.stop()

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass