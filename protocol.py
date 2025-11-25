import asyncio, struct


# Códigos de cabecera.
MSG_HELLO = 1      # Handshake
MSG_DATA = 2       # Chat
MSG_AUTH = 3       # Verificación de identidad con DNIe
MSG_ACK = 4        # ACK
MSG_BYE = 5        # Desconexión


# Aquí definimos la estructura de los mensajes.
class ChatPacket:
    def __init__(self, msg_type, seq, payload):
        self.msg_type = msg_type
        self.seq = seq
        self.payload = payload


# Aquí definimos nuestro protocolo (como se envían y reciben los mensajes).
class ChatProtocol(asyncio.DatagramProtocol):
    def __init__(self, on_packet_callback):
        self.on_packet = on_packet_callback
        self.transport = None


    # Nos guardamos la conexión.
    def connection_made(self, transport):
        self.transport = transport


    # Cada vez que entran bytes por la red los procesamos para construir el mensaje. 
    def datagram_received(self, data, addr):
        try:
            if len(data) < 5: return 
            header = data[:5]
            msg_type, seq = struct.unpack("!BI", header)
            payload = data[5:]

            # Creamos el paquete con los valores sacados de los bytes recibidos.
            self.on_packet(ChatPacket(msg_type, seq, payload), addr)
        except: pass


    # Esta función se llama cuando queremos enviar un mensaje a una dirección ip:puerto.
    def send_packet(self, ip, port, msg_type, seq, payload):
        if self.transport:
            header = struct.pack("!BI", msg_type, seq)
            if isinstance(payload, str): payload = payload.encode('utf-8')
            try: self.transport.sendto(header + payload, (ip, port))
            except: pass