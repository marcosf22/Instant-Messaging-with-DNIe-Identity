import asyncio
import struct

# Tipos de mensaje
MSG_HELLO = 1      # Handshake (Intercambio de claves)
MSG_DATA = 2       # Mensaje de Chat
MSG_AUTH = 3       # Verificación DNIe
MSG_DISCOVERY = 99 # Radar

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
        # Discovery (Texto)
        if data.startswith(b"DISCOVERY:"):
            try:
                nombre = data.decode('utf-8', errors='ignore').split(":")[1]
                self.on_packet(ChatPacket(MSG_DISCOVERY, 0, nombre), addr)
                return
            except: pass

        # Binario
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
            if isinstance(payload, str): payload = payload.encode('utf-8')
            try: self.transport.sendto(header + payload, (ip, port))
            except: pass