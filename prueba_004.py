import socket
import time
import threading
from zeroconf import ServiceInfo, Zeroconf, ServiceBrowser

# --- CONFIGURACIÓN ---
TYPE = "_dni-im._udp.local."
MY_PORT = 443

# Almacén: Diccionario {IP: Nombre}
discovered_peers = {} 

class DiscoveryListener:
    def add_service(self, zc, type, name):
        info = zc.get_service_info(type, name)
        if info:
            ip = socket.inet_ntoa(info.addresses[0])
            if ip not in discovered_peers:
                discovered_peers[ip] = name
                # Nota: Quitamos los prints aquí para no ensuciar el menú
    
    def remove_service(self, zc, type, name): pass
    def update_service(self, zc, type, name): pass

def start_discovery():
    zc = Zeroconf()
    browser = ServiceBrowser(zc, TYPE, DiscoveryListener())
    return zc

def send_msg_to_specific_ip(target_ip, message):
    """
    Aquí está la clave: Esta función recibe UNA sola IP.
    No le importa cuántos usuarios haya en la lista, solo manda a este.
    """
    print(f"\n[->] Enviando '{message}' a {target_ip}:{MY_PORT}...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Enviar datos SOLO a la tupla (IP_DESTINO, 443)
        sock.sendto(message.encode('utf-8'), (target_ip, MY_PORT))
        print("[OK] Paquete enviado.")
    except Exception as e:
        print(f"[X] Error: {e}")
    finally:
        sock.close()

def main():
    print("--- BUSCANDO DISPOSITIVOS (Espera unos segundos) ---")
    zc = start_discovery()
    
    try:
        while True:
            time.sleep(0.5) # Pequeña pausa para no saturar CPU
            
            # 1. Convertimos el diccionario a lista para poder usar índices (0, 1, 2...)
            #    Esto crea una "foto fija" de los usuarios actuales.
            active_targets = list(discovered_peers.items()) # [(ip, nombre), (ip, nombre)]

            print("\n" + "="*40)
            print(f" USUARIOS EN LINEA: {len(active_targets)}")
            print("="*40)
            
            if not active_targets:
                print(" (Escaneando... no se ven usuarios aún)")
            else:
                for index, (ip, name) in enumerate(active_targets):
                    # Mostramos: [0] Nombre (192.168.1.X)
                    print(f" [{index}] {name}  ==> IP: {ip}")

            print("\nOpciones:")
            print(" - Escribe el NÚMERO (0, 1...) para conectar con ese usuario")
            print(" - Escribe 'r' para refrescar")
            print(" - Escribe 's' para salir")
            
            user_input = input("\nTu elección >> ")

            if user_input == 's': break
            if user_input == 'r': continue

            # Lógica de selección
            if user_input.isdigit():
                idx = int(user_input)
                
                # Verificamos que el número exista en la lista
                if 0 <= idx < len(active_targets):
                    
                    # 2. EXTRAEMOS LA IP ESPECÍFICA
                    selected_ip = active_targets[idx][0] 
                    selected_name = active_targets[idx][1]
                    
                    print(f"\nHas seleccionado conectar con: {selected_name}")
                    msg = input("Escribe el mensaje: ")
                    
                    # 3. LLAMAMOS A LA FUNCIÓN DE ENVÍO CON ESA IP
                    send_msg_to_specific_ip(selected_ip, msg)
                    
                    input("\n(Presiona Enter para volver al menú)")
                else:
                    print("\n[!] Número incorrecto.")

    except KeyboardInterrupt:
        pass
    finally:
        zc.close()

if __name__ == '__main__':
    main()