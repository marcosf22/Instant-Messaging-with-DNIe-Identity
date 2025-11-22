import asyncio
from protocol import ChatProtocol, MSG_HELLO

def packet_handler(packet, addr):
    print(f"\n[RECIBIDO] Desde {addr}")
    print(f" - Tipo: {packet.msg_type}")
    print(f" - CID: {packet.cid}")
    print(f" - Payload (bytes): {packet.payload}")

async def main():
    # 1. Arrancar el servidor en localhost puerto 9999 (para probar)
    loop = asyncio.get_running_loop()
    
    # Creamos la instancia del protocolo
    protocol_instance = ChatProtocol(packet_handler)
    
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: protocol_instance,
        local_addr=('127.0.0.1', 9999)
    )

    # 2. Enviar un mensaje a nosotros mismos
    print("Enviando paquete de prueba...")
    payload_simulado = b'ClaveEfimeraFalsa'
    protocol.send_packet('127.0.0.1', 9999, MSG_HELLO, 101, payload_simulado)

    # Esperar un poco para recibirlo
    await asyncio.sleep(1)
    transport.close()

if __name__ == "__main__":
    asyncio.run(main())