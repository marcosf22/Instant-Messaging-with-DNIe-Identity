import socket
import time
import threading
from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser

# --- CONFIGURACIÓN ---
TYPE = "_dni-im._udp.local."
MY_PORT = 443

# Almacén global de pares descubiertos (Diccionario: IP -> Nombre)
# Usamos un diccionario para evitar duplicados
discovered_peers = {} 

class DiscoveryListener:
    def add_service(self, zc, type, name):
        info = zc.get_service_info(type, name)
        if info:
            ip = socket.inet_ntoa(info.addresses[0])
            # Guardamos al peer en nuestra lista global
            if ip not in discovered_peers:
                discovered_peers[ip] = name
                print(f"\n[+] ¡Nuevo usuario encontrado! {name} ({ip})")
                print("Presiona Enter para refrescar el menú...")

    def remove_service(self, zc, type, name):
        # Opcional: Limpiar la lista si se van
        pass
    def update_service(self, zc, type, name): pass

def start_background_discovery():
    """Inicia el proceso de escuchar mDNS en segundo plano."""
    zeroconf = Zeroconf()
    listener = DiscoveryListener()
    browser = ServiceBrowser(zeroconf, TYPE, listener)
    # Retornamos zeroconf para poder cerrarlo al salir
    return zeroconf

def send_hello(target_ip):
    """Envía el mensaje 'Hola' al puerto 443 del objetivo."""
    print(f"[*] Enviando 'Hola' a {target_ip}:443...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        message = "Hola"
        # En el proyecto real, aquí cifrarías el mensaje con Noise
        sock.sendto(message.encode('utf-8'), (target_ip, 443))
        print("[*] Mensaje enviado correctamente.")
    except Exception as e:
        print(f"[!] Error al enviar: {e}")
    finally:
        sock.close()

def main():
    print("--- INICIANDO APP P2P ---")
    
    # 1. Arrancamos el descubrimiento (se queda escuchando en hilos de fondo)
    zc = start_background_discovery()
    
    try:
        while True:
            # Mostramos el menú principal
            print("\n--- USUARIOS DISPONIBLES ---")
            
            # Convertimos el diccionario a una lista indexada para facilitar la selección
            peer_list = list(discovered_peers.items()) # [(ip, name), ...]
            
            if not peer_list:
                print(" (Buscando usuarios en la red...)")
            else:
                for idx, (ip, name) in enumerate(peer_list):
                    print(f" [{idx}] {name} - IP: {ip}")

            print("\n[R]efrescar lista | [S]alir | Escribe el número ID para saludar:")
            selection = input(">> ")

            if selection.lower() == 's':
                break
            elif selection.lower() == 'r':
                continue # Simplemente vuelve a pintar la lista
            elif selection.isdigit():
                idx = int(selection)
                if 0 <= idx < len(peer_list):
                    target_ip = peer_list[idx][0] # Sacamos la IP de la tupla
                    send_hello(target_ip)
                    input("Presiona Enter para continuar...")
                else:
                    print("[!] Selección inválida.")
            else:
                pass

    except KeyboardInterrupt:
        print("\nSaliendo...")
    finally:
        zc.close()

if __name__ == '__main__':
    main()
