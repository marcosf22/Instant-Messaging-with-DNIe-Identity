import socket, logging, asyncio

from zeroconf import ServiceStateChange
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf


# Establecemos el tipo de servicio que estamos anunciando/detectando.
SERVICE_TYPE = "_dni-im._udp.local."
logger = logging.getLogger("Discovery")


# Clase que gestiona el descubrimiento de usuarios en nuestra red.
class DiscoveryManager:
    def __init__(self, display_name, port, contacts_callback):
        self.aio_zeroconf = None 
        self.display_name = display_name
        self.port = port
        self.callback = contacts_callback
        self.browser = None
        self.info = None


    # Obtenemos la ip de la red en la que esatmos (y donde vamos a buscar/anunciar).
    def _get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        except: ip = "127.0.0.1"
        finally: s.close()
        return ip


    # Función a la que llama zeroconf cuando detecta un mDNS.
    def on_service_state_change(self, zeroconf, service_type, name, state_change):
        asyncio.ensure_future(self._process_service_change(zeroconf, service_type, name, state_change))


    # Aquí procesamos la información que hemos recibido mediante mDNS.
    async def _process_service_change(self, zeroconf, service_type, name, state_change):
        if state_change is ServiceStateChange.Added or state_change is ServiceStateChange.Updated:
            if self.aio_zeroconf:
                info = await self.aio_zeroconf.async_get_service_info(service_type, name)
                if info: self.callback("ADD", name, info)
        elif state_change is ServiceStateChange.Removed:
            self.callback("REMOVE", name, None)


    # Función que hace el simultáneamente el anuncio y la escucha mDNS.
    async def start(self):
        local_ip = self._get_local_ip()
        self.aio_zeroconf = AsyncZeroconf()

        # Anuncio
        self.info = AsyncServiceInfo(
            type_=SERVICE_TYPE,
            name=f"{self.display_name}.{SERVICE_TYPE}",
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
            properties={b'name': self.display_name.encode()},
            server=f"{self.display_name}.local."
        )
        try: await self.aio_zeroconf.async_register_service(self.info)
        except: pass

        # Escucho
        self.browser = AsyncServiceBrowser(
            self.aio_zeroconf.zeroconf, SERVICE_TYPE, handlers=[self.on_service_state_change]
        )


    # Envíamos un mDNS de despedida.
    async def stop(self):
        if self.browser: self.browser.cancel()
        if self.info and self.aio_zeroconf: await self.aio_zeroconf.async_unregister_service(self.info)
        if self.aio_zeroconf: await self.aio_zeroconf.async_close()