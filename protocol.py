import asyncio
import struct

# Constantes de Tipos de Mensaje
MSG_HELLO = 1
MSG_DATA = 2
MSG_DISCOVERY = 99  # Nuevo tipo para el descubrimiento

class ChatPacket:
    def __init__(self, msg_type, seq, payload):
        self.msg_type = msg_type
        self.seq = seq
        self.payload = payload

class ChatProtocol(asyncio.DatagramProtocol):
    def __init__(self, on_packet_callback):
        self.on_packet = on_packet_callback
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        # 1. FILTRO DE DISCOVERY (Texto Plano)
        # Si el paquete empieza por "DISCOVERY:", lo tratamos como texto simple
        if data.startswith(b"DISCOVERY:"):
            try:
                # Extraemos el nombre: "DISCOVERY:Juan" -> "Juan"
                nombre_usuario = data.decode('utf-8').split(":")[1]
                # Creamos un paquete falso interno para pasárselo al main
                fake_packet = ChatPacket(MSG_DISCOVERY, 0, nombre_usuario)
                self.on_packet(fake_packet, addr)
                return
            except:
                pass # Si falla, intentamos leerlo como binario normal

        # 2. PROTOCOLO BINARIO (Chat Encriptado)
        try:
            # Estructura: Tipo (1 byte) + Secuencia (4 bytes) + Payload (Resto)
            if len(data) < 5: return 
            
            header = data[:5]
            msg_type, seq = struct.unpack("!BI", header)
            payload = data[5:]
            
            packet = ChatPacket(msg_type, seq, payload)
            self.on_packet(packet, addr)
            
        except Exception:
            # Ignoramos paquetes corruptos o basura
            pass

    def send_packet(self, ip, port, msg_type, seq, payload):
        if self.transport:
            # Empaquetamos en binario: ! = Network Endian, B = Unsigned Char, I = Unsigned Int
            header = struct.pack("!BI", msg_type, seq)
            
            # Si el payload es string, lo convertimos a bytes, si ya es bytes, lo dejamos
            if isinstance(payload, str):
                payload = payload.encode()
                
            final_data = header + payload
            self.transport.sendto(final_data, (ip, port))