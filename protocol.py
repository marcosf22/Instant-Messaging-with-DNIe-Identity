import asyncio
import struct
import logging

# Tipos de mensajes
MSG_HELLO = 0x01  # Inicio de handshake (envío mi clave efímera)
MSG_DATA  = 0x02  # Mensaje de chat cifrado

logger = logging.getLogger("Protocol")

class Packet:
    """
    Clase auxiliar para empaquetar y desempaquetar datos binarios.
    Formato Header: [ TIPO (1 byte) | CID (4 bytes/entero unsigned) ]
    """
    def __init__(self, msg_type, cid, payload):
        self.msg_type = msg_type
        self.cid = cid
        self.payload = payload

    def to_bytes(self):
        # struct.pack('!BI', ...) significa:
        # ! = Network Endian (estándar para redes)
        # B = Unsigned Char (1 byte) -> Tipo
        # I = Unsigned Int (4 bytes) -> CID
        header = struct.pack('!BI', self.msg_type, self.cid)
        return header + self.payload

    @classmethod
    def from_bytes(cls, data):
        if len(data) < 5:
            return None # Paquete corrupto o incompleto
        
        # Desempaquetamos los primeros 5 bytes
        header = data[:5]
        payload = data[5:]
        msg_type, cid = struct.unpack('!BI', header)
        
        return cls(msg_type, cid, payload)

class ChatProtocol(asyncio.DatagramProtocol):
    """
    Maneja el envío y recepción cruda de paquetes UDP.
    No sabe de criptografía, solo de bytes y direcciones IP.
    """
    def __init__(self, on_packet_received):
        self.transport = None
        self.on_packet_received = on_packet_received

    def connection_made(self, transport):
        self.transport = transport
        logger.info(f"Servidor UDP escuchando en: {transport.get_extra_info('sockname')}")

    def datagram_received(self, data, addr):
        """
        Se dispara automáticamente cuando llega algo por la red.
        addr es una tupla (IP, Puerto).
        """
        packet = Packet.from_bytes(data)
        if packet:
            # Pasamos el paquete y la dirección al controlador principal
            self.on_packet_received(packet, addr)
        else:
            logger.warning(f"Paquete corrupto recibido de {addr}")

    def send_packet(self, ip, port, msg_type, cid, payload):
        """
        Construye el paquete y lo envía al destino.
        """
        if self.transport:
            packet = Packet(msg_type, cid, payload)
            data = packet.to_bytes()
            self.transport.sendto(data, (ip, port))
        else:
            logger.error("Error: El transporte no está listo.")

    def error_received(self, exc):
        logger.error(f"Error en el transporte UDP: {exc}")

    def connection_lost(self, exc):
        logger.info("Conexión UDP cerrada.")