import socket, time

from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser

# Configuración definida en el documento
SERVICE_TYPE = "_dni-im._udp.local."
TARGET_PORT = 443  # El endpoint donde recibiremos los datos 

class MyListener:
    """Clase que maneja los eventos cuando se encuentran otros dispositivos."""

    def remove_service(self, zeroconf, type, name):
        print(f"[-] Servicio desconectado: {name}")

    def update_service(self, zeroconf, type, name):
        pass

    def add_service(self, zeroconf, type, name):
        """Se llama automáticamente cuando se detecta un nuevo peer."""
        info = zeroconf.get_service_info(type, name)
        if info:
            # Convertir la dirección de bytes a string legible (ej. 192.168.1.50)
            address = socket.inet_ntoa(info.addresses[0])
            print(f"[+] ¡Dispositivo Encontrado!")
            print(f"    Nombre: {name}")
            print(f"    IP: {address}")
            print(f"    Puerto Endpoint: {info.port}")
            print(f"    ----------------------------------")

def get_local_ip():
    """Obtiene la IP real de la máquina en la LAN (no 127.0.0.1)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # No es necesario que esta IP sea alcanzable realmente
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def main():
    # 1. Obtener nuestra IP local para anunciarla
    local_ip = get_local_ip()
    print(f"[*] Mi IP Local es: {local_ip}")
    print(f"[*] Iniciando mDNS en {SERVICE_TYPE} apuntando al puerto {TARGET_PORT}...")

    # 2. Configurar el ANUNCIO (Advertising)
    # Preparamos la info que enviaremos a la red: "Aquí estoy, búscame en el puerto 443"
    my_service_name = f"Usuario-{local_ip.replace('.', '-')}.{SERVICE_TYPE}"
    
    info = ServiceInfo(
        SERVICE_TYPE,
        my_service_name,
        addresses=[socket.inet_aton(local_ip)],
        port=TARGET_PORT, # 
        properties={'version': '0.1', 'type': 'dni-client'},
    )

    zeroconf = Zeroconf()
    
    try:
        # Publicamos nuestro servicio
        zeroconf.register_service(info)
        print("[*] Servicio registrado exitosamente. Soy visible para otros.")

        # 3. Configurar el DESCUBRIMIENTO (Browsing)
        # Buscamos a otros que estén anunciando lo mismo
        listener = MyListener()
        browser = ServiceBrowser(zeroconf, SERVICE_TYPE, listener)
        
        print("[*] Escuchando en la red (Presiona Ctrl+C para salir)...\n")
        
        # Mantenemos el script corriendo
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n[*] Deteniendo servicio...")
    finally:
        # Al cerrar, nos des-registramos limpiamente
        zeroconf.unregister_service(info)
        zeroconf.close()

if __name__ == '__main__':
    main()
