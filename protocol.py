import asyncio
import struct

# --- CONSTANTES DE TIPOS DE MENSAJE ---
MSG_HELLO = 1      # Handshake (Intercambio de claves inicial)
MSG_DATA = 2       # Mensaje de texto encriptado
MSG_AUTH = 3       # Verificación de Identidad (Paquete DNIe)
MSG_DISCOVERY = 99 # Señal de descubrimiento (Broadcast)

class ChatPacket:
    """Clase contenedora para pasar los datos limpios al Main"""
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
        # Los paquetes de discovery suelen ser "DISCOVERY:Nombre" en utf-8 raw
        if data.startswith(b"DISCOVERY:"):
            try:
                # Extraemos solo el nombre
                nombre_usuario = data.decode('utf-8', errors='ignore').split(":")[1]
                fake_packet = ChatPacket(MSG_DISCOVERY, 0, nombre_usuario)
                self.on_packet(fake_packet, addr)
                return
            except: 
                pass

        # 2. PROTOCOLO BINARIO ESTÁNDAR
        # Estructura: [TIPO (1 byte)] + [SECUENCIA (4 bytes)] + [PAYLOAD (Resto)]
        try:
            if len(data) < 5: return 
            
            # Desempaquetamos la cabecera (!BI = Network Endian, Unsigned Char, Unsigned Int)
            header = data[:5]
            msg_type, seq = struct.unpack("!BI", header)
            
            # El resto es el payload (puede ser json, bytes encriptados, etc)
            payload = data[5:]
            
            packet = ChatPacket(msg_type, seq, payload)
            self.on_packet(packet, addr)
            
        except Exception:
            # Si llega basura, la ignoramos para no romper el programa
            pass

    def send_packet(self, ip, port, msg_type, seq, payload):
        """Empaqueta y envía datos a una IP/Puerto"""
        if self.transport:
            # Preparamos la cabecera
            header = struct.pack("!BI", msg_type, seq)
            
            # Aseguramos que el payload sean bytes
            if isinstance(payload, str):
                payload = payload.encode('utf-8')
                
            final_data = header + payload
            
            try:
                self.transport.sendto(final_data, (ip, port))
            except Exception as e:
                print(f"Error de transporte al enviar a {ip}: {e}")
