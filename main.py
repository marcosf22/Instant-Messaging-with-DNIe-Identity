import asyncio
import logging
import socket
import sys
from zeroconf import ServiceStateChange
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

# --- CONFIGURACIÓN ---
PORT = 8888
SERVICE_TYPE = "_dni-im._udp.local."

# Configurar logs para ver TODO
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
logger = logging.getLogger("Fixer")

def get_manual_ip():
    """Muestra las IPs disponibles y obliga a elegir la correcta."""
    print("\n--- SELECCIÓN DE TARJETA DE RED ---")
    hostname = socket.gethostname()
    print(f"Host: {hostname}")
    
    # Obtener todas las IPs
    ips = socket.gethostbyname_ex(hostname)[2]
    print("IPs detectadas en este PC:")
    for i, ip in enumerate(ips):
        print(f"  [{i}] {ip}")
    
    idx = input("--> Escribe el número de la IP de tu WiFi/LAN (ej. 0): ")
    try:
        selected_ip = ips[int(idx)]
        print(f"SELECCIONADA: {selected_ip}")
        return selected_ip
    except:
        print("Selección inválida. Usando la primera opción.")
        return ips[0]

class SimpleClient:
    def __init__(self, name, bind_ip):
        self.name = name
        self.bind_ip = bind_ip
        self.aio_zeroconf = None
        self.loop = asyncio.get_running_loop()

    async def start(self):
        print(f"\n[1] Iniciando Servidor UDP en {self.bind_ip}:{PORT}...")
        # BINDING EXPLÍCITO a la IP seleccionada
        try:
            self.transport, _ = await self.loop.create_datagram_endpoint(
                lambda: asyncio.DatagramProtocol(),
                local_addr=(self.bind_ip, PORT)
            )
            print("✅ Servidor UDP Activo.")
        except Exception as e:
            print(f"❌ ERROR FATAL abriendo puerto UDP: {e}")
            return

        print("[2] Iniciando Discovery (mDNS)...")
        self.aio_zeroconf = AsyncZeroconf(interfaces=[self.bind_ip]) # FORZAMOS LA INTERFAZ

        # REGISTRAR SERVICIO
        info = AsyncServiceInfo(
            SERVICE_TYPE,
            f"{self.name}.{SERVICE_TYPE}",
            addresses=[socket.inet_aton(self.bind_ip)],
            port=PORT,
            properties={b'name': self.name.encode()},
            server=f"{self.name}.local."
        )
        await self.aio_zeroconf.async_register_service(info)
        print(f"✅ Anunciando: {self.name}")

        # ESCUCHAR
        self.browser = AsyncServiceBrowser(
            self.aio_zeroconf.zeroconf, 
            SERVICE_TYPE, 
            handlers=[self.on_change]
        )
        print("✅ Escuchando red... (Espera 5 segundos)")

    def on_change(self, zeroconf, service_type, name, state_change):
        if state_change is ServiceStateChange.Added:
            asyncio.ensure_future(self.process_peer(zeroconf, service_type, name))

    async def process_peer(self, zeroconf, service_type, name):
        info = await zeroconf.async_get_service_info(service_type, name)
        if info:
            # Imprimimos SIEMPRE, sin filtros
            addr = socket.inet_ntoa(info.addresses[0])
            print(f"\n[!!!] DETECTADO: {name}")
            print(f"      IP: {addr} | Puerto: {info.port}")
            print(f"      (Si ves esto, la lista funciona)")

    async def stop(self):
        if self.aio_zeroconf:
            await self.aio_zeroconf.async_close()

async def main():
    # 1. Pedir IP Manualmente
    my_ip = get_manual_ip()
    
    # 2. Pedir Nombre
    my_name = input("Nombre de usuario único (ej. Test1): ")
    
    client = SimpleClient(my_name, my_ip)
    
    try:
        await client.start()
        print("\n--- CORRIENDO ---")
        # Bucle infinito simple
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        await client.stop()

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
