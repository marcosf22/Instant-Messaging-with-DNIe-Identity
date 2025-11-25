import asyncio
import struct

MSG_HELLO = 1      # Ahora llevará Certificado + Firma + Clave
MSG_DATA = 2
MSG_DISCOVERY = 99

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
        if data.startswith(b"DISCOVERY:"):
            try:
                nombre = data.decode('utf-8').split(":")[1]
                self.on_packet(ChatPacket(MSG_DISCOVERY, 0, nombre), addr)
                return
            except: pass

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