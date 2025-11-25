import asyncio
import struct

# Tipos de mensaje
MSG_HELLO = 1      # Handshake
MSG_DATA = 2       # Chat
MSG_DISCOVERY = 99 # Discovery
MSG_AUTH = 3       # <--- NUEVO: Paquete de Verificación DNIe

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
        # 1. Discovery
        if data.startswith(b"DISCOVERY:"):
            try:
                nombre = data.decode('utf-8').split(":")[1]
                self.on_packet(ChatPacket(MSG_DISCOVERY, 0, nombre), addr)
                return
            except: pass

        # 2. Binario
        try:
            if len(data) < 5: return 
            header = data[:5]
            msg_type, seq = struct.unpack("!BI", header)
            payload = data[5:]
            self.on_packet(ChatPacket(msg_type, seq, payload), addr)
        except: pass

    def send_packet(self, ip, port, msg_type, seq, payload):
        if self.transport:
            header = struct.pack("!BI", msg_type, seq)
            if isinstance(payload, str): payload = payload.encode()
            final_data = header + payload
            self.transport.sendto(final_data, (ip, port))