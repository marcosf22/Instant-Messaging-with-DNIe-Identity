import asyncio
import logging
import socket
import sys
import random

# Importamos tus módulos (asegúrate de que discovery.py es el último que hicimos)
from discovery import DiscoveryManager
from protocol import ChatProtocol

# Configuración
PORT = 8888
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("DEBUGGER")

class DebugClient:
    def __init__(self, name):
        self.display_name = name
        self.loop = asyncio.get_running_loop()
        
        # 1. Protocolo (Solo para ocupar el puerto y ver si hay conflicto)
        self.protocol = ChatProtocol(self.on_packet)
        self.transport = None
        
        # 2. Discovery con un callback que NO FILTRA NADA
        self.discovery = DiscoveryManager(name, self.on_raw_update)

    async def start(self):
        logger.info(f"--- DEBUGGER INICIADO: {self.display_name} ---")
        logger.info(f"--- Escuchando en 0.0.0.0:{PORT} ---")
        
        try:
            self.transport, _ = await self.loop.create_datagram_endpoint(
                lambda: self.protocol,
                local_addr=('0.0.0.0', PORT)
            )
        except Exception as e:
            logger.error(f"¡ERROR AL ABRIR PUERTO {PORT}! ¿Está ocupado? Error: {e}")
            return

        logger.info("Iniciando servicio de Discovery...")
        await self.discovery.start()

    def on_raw_update(self, action, name, info):
        """Callback crudo: Imprime TODO sin ifs ni returns."""
        print(f"\n[!!!] EVENTO RAW RECIBIDO: {action} -> {name}")
        
        if info:
            print(f"      Puerto: {info.port}")
            print(f"      Server: {info.server}")
            if info.addresses:
                # Convertir todas las IPs encontradas
                ips = [socket.inet_ntoa(addr) for addr in info.addresses]
                print(f"      Direcciones IP: {ips}")
            else:
                print("      [PELIGRO] ¡No viene ninguna IP en el paquete!")
        else:
            print("      (Sin info adicional)")

    def on_packet(self, packet, addr):
        print(f"[RED] Paquete recibido de {addr}")

    async def stop(self):
        await self.discovery.stop()
        if self.transport:
            self.transport.close()

async def main():
    # Generamos un nombre aleatorio para evitar conflictos de "misma identidad"
    rand_id = random.randint(1000, 9999)
    name = f"DebugUser_{rand_id}"
    
    client = DebugClient(name)
    
    try:
        await client.start()
        print("\n--- CORRIENDO (NO TOQUES NADA, SOLO MIRA) ---")
        print(f"--- Soy: {name} ---")
        
        # Bucle infinito simple, sin inputs que bloqueen
        while True:
            await asyncio.sleep(1)
            
    except KeyboardInterrupt:
        print("Parando...")
    finally:
        await client.stop()

if __name__ == "__main__":
    # En Windows a veces hace falta configurar el selector
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
