import asyncio, sys, socket, json, os, threading, zlib, struct, uuid, base64, pygame, time

from datetime import datetime
from PIL import Image as PILImage, ImageSequence

# Módulos propios
from crypto import KeyManager, SessionCrypto
from protocol import ChatProtocol, MSG_HELLO, MSG_DATA, MSG_AUTH, MSG_ACK, MSG_BYE
from discovery import DiscoveryManager


# Configuración interfaz.
ANCHO, ALTO = 950, 650 
COLOR_FONDO = (10, 15, 10) 
COLOR_TEXTO = (50, 220, 50)
COLOR_MARCO = (30, 60, 30)

TXT_NORMAL = (200, 255, 200)
TXT_ME     = (220, 255, 220)
TXT_SYS    = (100, 200, 200)
TXT_TIME   = (150, 180, 150)

BUBBLE_ME    = (20, 60, 20)
BUBBLE_OTHER = (30, 30, 35)
BUBBLE_SYS   = (10, 20, 20)

BTN_IDLE    = (20, 40, 20)
BTN_HOVER   = (40, 80, 40)
BTN_ACTIVE  = (0, 100, 0)
BTN_ALERT   = (180, 100, 0)
BTN_VERIFIED= (0, 80, 100)
BTN_OFFLINE = (50, 50, 50)

SESSION_FILE = "sessions.json"

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


# Esta función es para convertirlo en un ejecutable.
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)


# Funciones de la interfaz. El código más "técnico" está a partir de la línea 177 :)

# Función para que el texto no se salga del cuadro de texto de la interfaz.
def wrap_text(text, font, max_width):
    words = text.split(' ')
    lines = []
    current_line = ""
    for word in words:
        test_line = current_line + " " + word if current_line else word
        if font.size(test_line)[0] <= max_width:
            current_line = test_line
        else:
            if current_line:
                lines.append(current_line)
                current_line = ""
            if font.size(word)[0] <= max_width:
                current_line = word
            else:
                for char in word:
                    if font.size(current_line + char)[0] <= max_width:
                        current_line += char
                    else:
                        lines.append(current_line)
                        current_line = char

    if current_line:
        lines.append(current_line)
    return lines


# Función para cargar los gifs.
def load_gif_frames(filepath, size=None):
    frames = []
    if not os.path.exists(filepath): return []
    try:
        pil = PILImage.open(filepath)
        for f in ImageSequence.Iterator(pil):
            fr = f.convert("RGBA")
            py = pygame.image.fromstring(fr.tobytes(), fr.size, fr.mode).convert_alpha()
            if size: py = pygame.transform.scale(py, size)
            frames.append(py)
    except: pass
    return frames


# Función para cargar las imágenes de los personajes.
class CodecCharacterLoader:
    def __init__(self):
        self.chars = {}; self.keys = []
        self.load()
    def load(self):
        f = resource_path(os.path.join("assets", "characters"))
        if not os.path.exists(f): os.makedirs(f, exist_ok=True)
        s = pygame.Surface((150, 200)); s.fill((0,20,0))
        pygame.draw.rect(s, COLOR_MARCO, (0,0,150,200), 2)
        self.chars['default'] = [s]
        for file in os.listdir(f):
            if file.endswith('.gif'):
                frames = load_gif_frames(resource_path(os.path.join(f, file)), (150,200))
                if frames: self.chars[file.split('.')[0].lower()] = frames
        self.keys = sorted(list(self.chars.keys()))
    def get(self, uid):
        if uid in self.chars:
            return self.chars[uid]
        
        if not self.keys: return self.chars['default']
        return self.chars[self.keys[zlib.crc32(str(uid).encode()) % len(self.keys)]]


# Clase que define las funciones de la aplicación.
class AppState:
    def __init__(self):
        self.peers = {}
        self.incoming_ids = []
        self.messages = []
        self.input_text = ""
        self.my_name = "Juan"
        self.target_name = None
        self.target_info = None
        self.status_msg = "EN LOBBY"
        self.talking_timer = {}
        self.sound_queue = []
    

    # Añadimos los mensajes para mostrarlos por pantalla.
    def add_message(self, snd, txt, is_me=False, is_sys=False, mid=None, time_str=None, status='queued'):
        if not time_str: time_str = datetime.now().strftime("%H:%M")
        msg_obj = {
            'id': mid, 'sender': snd, 'text': txt, 
            'is_me': is_me, 'is_sys': is_sys, 'time': time_str, 'status': status
        }
        self.messages.append(msg_obj)
        
        if not is_sys:
            clean_snd = snd.split(" [")[0].strip().lower()
            self.talking_timer[clean_snd] = pygame.time.get_ticks() + 2500
            if not is_me: self.sound_queue.append("msg")
        return msg_obj


    # Función que usamos cuando queremos limpiar la pantalla y vaciar la lista de mensajes.
    def clear_messages(self):
        self.messages = []
        self.talking_timer = {}


    # Función que marca el ACK a un mensaje.
    def mark_ack(self, mid):
        for m in reversed(self.messages):
            if m['id'] == mid: m['status'] = 'ack'; return
            
    # Función que marca el check de enviado de un mensaje.
    def mark_sent(self, mid):
        for m in reversed(self.messages):
            if m['id'] == mid: m['status'] = 'sent'; return

    def is_talking(self, name):
        return name in self.talking_timer and pygame.time.get_ticks() < self.talking_timer[name]
    
    def set_status(self, t): self.status_msg = t


STATE = AppState()
CHARS = None


# Función que obtiene la ip de la red.
def get_best_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: s.connect(('8.8.8.8', 1)); IP = s.getsockname()[0]
    except: IP = '127.0.0.1'
    finally: s.close()
    return IP


# Clase que define a los usuarios y sus funciones.
class ChatClient:
    def __init__(self, name, port):
        self.name = name
        self.port = port
        self.loop = asyncio.get_running_loop()
        self.my_ip = get_best_ip()
        self.key_manager = KeyManager(f"{name}_identity")
        self.sessions = {} 
        self.peers = {}
        self.peer_counter = 0
        self.pending_requests = {}
        self.verified_users = {}
        self.offline_peers = set()
        self.reconnecting_peers = set()
        self.handshake_cooldowns = {}
        self.chat_histories = {} 
        self.message_queue = {} 
        self.protocol = ChatProtocol(self.on_packet)
        self.discovery = DiscoveryManager(name, port, self.update_contacts)


    # Pedimos las claves del DNIe antes de iniciar la interfaz para evitar porblemas de bloqueo.
    def iniciar_dnie_antes_de_gui(self):
        ok = self.key_manager.iniciar_sesion_dnie()
        if ok: self.load_sessions_securely()
        return ok


    # Cambiamos de chat desde la barra de navegación de contactos.
    def switch_chat_view(self, ip, port, name):
        STATE.clear_messages()
        sk = f"{ip}:{port}"
        if sk in self.chat_histories:
            STATE.messages.extend(self.chat_histories[sk])
        STATE.target_info = (ip, port)
        STATE.target_name = name
        
        # Muestra el estado correcto incluso si es offline
        if sk in self.offline_peers:
            STATE.set_status(f"OFFLINE: {name}")
        else:
            STATE.set_status(f"CONECTADO: {name}")


    # Almacenamos los mensajes en el JSON cifrado.
    def save_msg_to_history(self, sk, msg_obj):
        if sk not in self.chat_histories: self.chat_histories[sk] = []
        exists = False
        for m in self.chat_histories[sk]:
            if m['id'] == msg_obj['id']:
                m.update(msg_obj)
                exists = True
                break
        if not exists:
            self.chat_histories[sk].append(msg_obj)
        self.save_sessions_securely() 

    # Función que reintenta la entrega cada 5 segundos si el contacto ha vuelto ONLINE.
    async def retry_worker(self):
        while True:
            now = time.time()
            for sk in list(self.message_queue.keys()):
                if sk in self.offline_peers: continue
                
                queue = self.message_queue[sk]
                if not queue: continue
                
                try: ip, port = sk.split(':'); port = int(port)
                except: continue
                
                if sk not in self.sessions: continue

                for item in queue:
                    if now - item.get('last_try', 0) > 5:
                        try:
                            payload = json.dumps({"id": item['id'], "msg": item['text']})
                            enc = self.sessions[sk].encrypt(payload)
                            self.protocol.send_packet(ip, port, MSG_DATA, 1, enc)
                            
                            item['last_try'] = now
                            
                            if item['status'] == 'queued':
                                item['status'] = 'sent'
                                STATE.mark_sent(item['id'])
                                self.save_msg_to_history(sk, item)
                        except: pass
            await asyncio.sleep(1)


    # Envíamos los mensajes que estén pendientes.
    def flush_queue(self, ip, port):
        sk = f"{ip}:{port}"
        if sk in self.message_queue:
            for m in self.message_queue[sk]: m['last_try'] = 0


    # Función que nos permite agestionar los "reencuentros".
    def update_contacts(self, action, name, info):
        if action == "ADD" and info:
            try:
                ip = socket.inet_ntoa(info.addresses[0])
                port = info.port
                clean = name.split('.')[0]
                if ip == self.my_ip and port == self.port: return

                k = f"{ip}:{port}"
        
                real_display_name = self.verified_users.get(k, clean)

                # OFFLINE -> ONLINE
                if k in self.offline_peers: 
                    self.offline_peers.remove(k)
                    
                    if STATE.target_info == (ip, port):
                        STATE.set_status(f"CONECTADO: {real_display_name}")
                        STATE.target_name = real_display_name
                    
                    if k in self.sessions: self.flush_queue(ip, port)

                # Nuevo contacto.
                exists = False
                for p in self.peers.values():
                    if p['ip'] == ip and p['port'] == port: exists = True
                
                if not exists:
                    pid = self.peer_counter
                    self.peers[pid] = {'ip': ip, 'port': port, 'name': clean}
                    self.peer_counter += 1
                    
                    if k not in self.sessions:
                        STATE.sound_queue.append("contact")
                    else: 
                        self.flush_queue(ip, port)
                
                # Actualizar lista combinada
                self.refresh_peers_list()

                # Auto-reconexión.
                if k in self.sessions:
                    self.perform_background_reconnect(ip, port)
            except: pass
        
        elif action == "REMOVE":
            # Si se va, actualizamos para que salga como offline (si estaba guardado)
            self.refresh_peers_list()


    # Combina los contactos online (Discovery) con los guardados (Offline) para la barra lateral.
    def refresh_peers_list(self):
        combined = self.peers.copy()
        
        # ID inicial ficticio para offline
        fake_id = 50000 

        for sk in self.sessions:
            try:
                ip, port_str = sk.split(':')
                port = int(port_str)
                
                # Si ya está en la lista de peers online, lo saltamos
                is_online = False
                for p in combined.values():
                    if p['ip'] == ip and p['port'] == port:
                        is_online = True; break
                
                if not is_online:
                    name = self.verified_users.get(sk, f"User {port}")
                    combined[fake_id] = {'ip': ip, 'port': port, 'name': name}
                    fake_id += 1
            except: pass
        
        STATE.peers = combined


    # Saludo que hacemos cuando reconectamos con un contacto existente para no hacer el handshake otra vez.
    def perform_background_reconnect(self, ip, port):
        try:
            sess_key = f"{ip}:{port}"
            s = self.sessions[sess_key]
            mk = s.get_public_bytes()
            self.protocol.send_packet(ip, port, MSG_HELLO, 0, mk)

            self.send_verification(ip, port)
        except: pass


    # Cargamos la claves establecidas con el contacto anteriormente y restauramos sus mensajes.
    def load_sessions_securely(self):
        if not os.path.exists(SESSION_FILE): return
        try:
            with open(SESSION_FILE, 'r') as f: wrapper = json.load(f)
            b64_data = wrapper.get("content", "")
            if not b64_data: return
            encrypted_bytes = base64.b64decode(b64_data)
            json_plain = self.key_manager.decrypt_disk_data(encrypted_bytes)
            if not json_plain: return
            
            data = json.loads(json_plain)
            c = 0
            for sk, entry in data.items():
                hex_key = entry if isinstance(entry, str) else entry.get('key')
                s = SessionCrypto() 
                try: 
                    s.load_secret(hex_key)
                    self.sessions[sk] = s
                    c += 1
                    # Marcamos offline por defecto al cargar
                    self.offline_peers.add(sk)

                    if isinstance(entry, dict):
                        self.chat_histories[sk] = entry.get('history', [])
                        if 'queue' in entry: self.message_queue[sk] = entry['queue']

                        vname = entry.get('verified_name')
                        self.verified_users[sk] = vname if vname else ""
                except: pass
            
            if c > 0: 
                STATE.add_message("SYS", f"{c} chats recuperados.", True)
                self.refresh_peers_list()
        except: pass


    # Guardamos las claves y los mensajes con nuestros contactos.
    def save_sessions_securely(self):
        export_data = {}
        for sk, s in self.sessions.items():
            if s.export_secret():
                q = []
                if sk in self.message_queue:
                     for m in self.message_queue[sk]:
                         q.append({'id': m['id'], 'text': m['text'], 'status': m['status']})

                export_data[sk] = {
                    'key': s.export_secret(),
                    'history': self.chat_histories.get(sk, []),
                    'queue': q,
                    'verified_name': self.verified_users.get(sk, "") 
                }
        try: 
            json_plain = json.dumps(export_data)
            encrypted_bytes = self.key_manager.encrypt_disk_data(json_plain)
            if not encrypted_bytes: return
            b64_data = base64.b64encode(encrypted_bytes).decode('utf-8')
            wrapper = {"content": b64_data}
            with open(SESSION_FILE, 'w') as f: json.dump(wrapper, f, indent=4)
        except: pass


    # Activamos el transporte en el puerto seleccionado.
    async def start(self):
        self.transport, _ = await self.loop.create_datagram_endpoint(
            lambda: self.protocol, local_addr=("0.0.0.0", self.port), allow_broadcast=True
        )
        await self.discovery.start()
        self.loop.create_task(self.retry_worker())


    # Cerramos el transporte y envíamos un mensaje de que estamos OFFLINE.
    async def stop(self):
        for k in self.sessions:
            try:
                ip, p = k.split(":")
                for _ in range(5):
                    self.protocol.send_packet(ip, int(p), MSG_BYE, 0, b"")
            except: pass
        await self.discovery.stop()


    # Esta función envía un mensaje de verificación de identidad.
    def send_verification(self, ip=None, port=None):
        target_ip, target_port = ip, port
        
        if not target_ip:
             if STATE.target_info: 
                 target_ip, target_port = STATE.target_info
             else: 
                 return STATE.add_message("SYS", "Conecta primero.", True)
        
        threading.Thread(target=self._firmar_y_enviar, args=(target_ip, target_port), daemon=True).start()


    # Esta función permite al otro extremo verificar nuestra identidad.
    def _firmar_y_enviar(self, ip, port):
        # time.sleep(1.5)
        try:
            key_sess = f"{ip}:{port}"
            if key_sess not in self.sessions: return

            clave_pub = self.sessions[key_sess].get_public_bytes()
            cert, firma = self.key_manager.firmar_handshake(clave_pub)
            if not cert: return
            payload = struct.pack("!I", len(cert)) + cert + \
                      struct.pack("!I", len(firma)) + firma + \
                      clave_pub
            
            enc = self.sessions[key_sess].encrypt(payload.decode('latin1'))
            self.loop.call_soon_threadsafe(self.protocol.send_packet, ip, port, MSG_AUTH, 0, enc)

        except Exception as e: 
            STATE.add_message("SYS", f"Error DNIe: {e}", True)


    # Esta función es la clave xd.
    # Aqui es donde procesamos los mensajes en función de su cabecera.
    def on_packet(self, pkt, addr):
        ip, port = addr
        sk = f"{ip}:{port}"

        # Paquetes de handshake.
        if pkt.msg_type == MSG_HELLO:

            # Si el remitente está está en nuestra lista le devolvemos el HELLO.
            if sk in self.sessions:
                try:
                    self.sessions[sk].compute_secret(pkt.payload)
                    self.save_sessions_securely()
                    self.flush_queue(ip, port)
                    
                    # Acabamos de recibir el HELLO (respuesta), enviamos nuestra identidad.
                    self.send_verification(ip, port)

                    last_time = self.handshake_cooldowns.get(sk, 0)
                    now = time.time()
                    if now - last_time > 5:
                        mk = self.sessions[sk].get_public_bytes()
                        self.protocol.send_packet(ip, port, MSG_HELLO, 0, mk)
                        self.handshake_cooldowns[sk] = now
                except: pass
                return

            # Si está en pendientes notificamos al usuario por pantalla para que lo acepte (si quiere).
            if sk not in self.pending_requests:
                self.pending_requests[sk] = pkt.payload
                name = f"{ip}:{port}"
                pid = -1
                for p, d in self.peers.items():
                    if d['ip']==ip and d['port']==port: name, pid = d['name'], p
                if pid != -1 and pid not in STATE.incoming_ids: STATE.incoming_ids.append(pid)
                STATE.sound_queue.append("call")
                if not STATE.target_info:
                    STATE.add_message("SYS", f"[!] LLAMADA DE: {name}", True)

        # Paquetes de chat.
        elif pkt.msg_type == MSG_DATA:
            if sk in self.sessions:
                try:
                    dec = self.sessions[sk].decrypt(pkt.payload)
                    data = json.loads(dec)
                    msg_text, msg_id = data.get("msg", ""), data.get("id", "")
                    
                    snd = self.verified_users.get(sk, sk)
                    if snd == sk:
                        for p in self.peers.values():
                            if p['ip']==ip and p['port']==port: snd = p['name']
                    
                    msg_obj = {
                        'id': msg_id, 'sender': snd, 'text': msg_text, 
                        'is_me': False, 'is_sys': False, 'time': datetime.now().strftime("%H:%M"), 'status': 'received'
                    }
                    self.save_msg_to_history(sk, msg_obj)

                    if STATE.target_info == (ip, port):
                        STATE.add_message(snd, msg_text, mid=msg_id)
                    
                    ack = json.dumps({"id": msg_id})
                    enc_ack = self.sessions[sk].encrypt(ack)
                    self.protocol.send_packet(ip, port, MSG_ACK, 0, enc_ack)
                except:
                    del self.sessions[sk]
                    self.reconnecting_peers.add(sk)
                    self.connect_manual(ip, port, "RECONNECT")
            else: 
                self.reconnecting_peers.add(sk)
                self.connect_manual(ip, port, "RECONNECT")

        # Mensaje de tipo ACK.
        elif pkt.msg_type == MSG_ACK:
            if sk in self.sessions:
                try:
                    dec = self.sessions[sk].decrypt(pkt.payload)
                    d = json.loads(dec)
                    mid = d.get("id")
                    if mid:
                        STATE.mark_ack(mid)
                        
                        if sk in self.message_queue:
                            self.message_queue[sk] = [m for m in self.message_queue[sk] if m['id'] != mid]
                            if not self.message_queue[sk]: del self.message_queue[sk]

                        if sk in self.chat_histories:
                            for m in reversed(self.chat_histories[sk]):
                                if m['id'] == mid: m['status'] = 'ack'; break
                        self.save_sessions_securely()
                except: pass

        # Mensaje que nos avisa que el contacto pasa a estar OFFLINE.
        elif pkt.msg_type == MSG_BYE:
            if sk not in self.offline_peers:
                self.offline_peers.add(sk)
                self.refresh_peers_list() # Refresca lista para mostrarlo offline
                if STATE.target_info == (ip, port):
                    STATE.set_status(f"OFFLINE: {STATE.target_name}")

        # Mensaje para verificar la identidad del remitente.
        elif pkt.msg_type == MSG_AUTH:
            if sk in self.sessions:
                try:
                    dec = self.sessions[sk].decrypt(pkt.payload).encode('latin1')
                    o=0; lc=struct.unpack("!I", dec[o:o+4])[0]; o+=4
                    cert=dec[o:o+lc]; o+=lc
                    ls=struct.unpack("!I", dec[o:o+4])[0]; o+=4
                    sig=dec[o:o+ls]; o+=ls
                    pk=dec[o:] 
                    v, cn = self.key_manager.verificar_handshake(pk, cert, sig)
                    if v:
                        STATE.sound_queue.append("open")
                        STATE.add_message("SYS", f">> DNIe VERIFICADO: {cn}", True)
                        self.verified_users[sk] = f"{cn} [OK]"
                        self.save_sessions_securely()
                        
                        self.refresh_peers_list() # Actualizar nombre con [OK]

                        if STATE.target_info == (ip, port):
                            STATE.target_name = self.verified_users[sk]
                            STATE.set_status(f"CONECTADO: {STATE.target_name}")
                    else: STATE.add_message("SYS", "XXX FIRMA FALSA XXX", True)
                except: pass


    # Función que nos permite conectarnos a un usuario que no tenemos en nuestra lsita de contactos.
    def connect_manual(self, ip, port, name="Unknown"):
        sk = f"{ip}:{port}"
        if sk in self.sessions:
            real = self.verified_users.get(sk, name)
            if sk in self.offline_peers: self.offline_peers.remove(sk)
            self.switch_chat_view(ip, port, real)
            self.flush_queue(ip, port)
            return

        STATE.clear_messages()
        STATE.add_message("SYS", f"--> INICIANDO HANDSHAKE: {name}...", True)
        s = SessionCrypto()
        self.sessions[sk] = s
        mk = s.get_public_bytes()
        self.handshake_cooldowns[sk] = time.time()
        for _ in range(3): self.protocol.send_packet(ip, port, MSG_HELLO, 0, mk)
        STATE.target_info = (ip, port)
        STATE.target_name = name
        STATE.set_status(f"LLAMANDO A {name}...")


    # Función que nos permite devolver el handshake que alguien ha iniciado con nosotros.
    def accept_connection(self, pid):
        if pid not in STATE.peers: return
        t = STATE.peers[pid]
        ip, port, name = t['ip'], t['port'], t['name']
        sk = f"{ip}:{port}"

        # Si ya teníamos sesión (offline clickeado), conectamos directo
        if sk in self.sessions and sk not in self.pending_requests:
            self.connect_manual(ip, port, name)
            return

        if sk not in self.pending_requests: return
        
        STATE.clear_messages()
        STATE.add_message("SYS", "ESTABLECIENDO CIFRADO...", True)
        s = SessionCrypto()
        self.sessions[sk] = s
        s.compute_secret(self.pending_requests[sk])
        mk = s.get_public_bytes()
        self.handshake_cooldowns[sk] = time.time()
        for _ in range(3): self.protocol.send_packet(ip, port, MSG_HELLO, 0, mk)
        del self.pending_requests[sk]
        if pid in STATE.incoming_ids: STATE.incoming_ids.remove(pid)
        
        self.switch_chat_view(ip, port, name)
        self.save_sessions_securely()
        
        # Acabamos de establecer conexión, enviamos nuestra identidad.
        self.send_verification(ip, port)

        STATE.add_message(self.name, f">> CANAL SEGURO ESTABLECIDO.", True)


    # Función para enviar mensajes.
    def send_msg(self, text):
        if STATE.target_info: 
            ip, port = STATE.target_info
            sk = f"{ip}:{port}"
            
            # ID aleatorio generado para un mensaje.
            mid = str(uuid.uuid4())[:8]
            
            # Si está OFFLINE, lo guardamos en cola.
            if sk in self.offline_peers:
                if sk not in self.message_queue: self.message_queue[sk] = []
                
                msg_data = {
                    'id': mid, 'sender': self.name, 'text': text, 
                    'is_me': True, 'is_sys': False, 'time': datetime.now().strftime("%H:%M"), 'status': 'queued'
                }
                self.message_queue[sk].append(msg_data)
            
                STATE.add_message(self.name, text, True, mid=mid, status='queued')
                self.save_msg_to_history(sk, msg_data)
                self.save_sessions_securely()
                return

            # Si está ONLINE, lo enviamos.
            try:
                pl = json.dumps({"id": mid, "msg": text})
                enc = self.sessions[sk].encrypt(pl)
                self.protocol.send_packet(ip, port, MSG_DATA, 1, enc)
                m_obj = STATE.add_message(self.name, text, True, mid=mid)
                self.save_msg_to_history(sk, m_obj)
            except: pass


    # Si escribimos /verify, permitimos a nuestro contacto verificar nuestra identidad.
    # Si escribimos /leave, salimos.
    def process_command(self, text):
        if text == "/verify": self.send_verification()
        elif text == "/leave":
            STATE.target_info = None
            STATE.set_status("LOBBY")
            STATE.clear_messages()
            STATE.add_message("SYS", "VUELTA AL LOBBY.", True)
        elif STATE.target_info: self.send_msg(text)

# Clase que estructura toda la interfaz.
class CodecDisplay:
    def __init__(self, size):
        self.bg_frames = load_gif_frames(resource_path("assets/codec_background.gif"), (ANCHO, 350))
        if not self.bg_frames: self.bg_frames=[pygame.Surface((ANCHO, 350))]
        self.frame_idx = 0
        self.active_buttons = []
        self.scroll_y = 0 
        try: pygame.mixer.init(); self.snd = {
            "call": pygame.mixer.Sound(resource_path("assets/call.mp3")), "msg": pygame.mixer.Sound(resource_path("assets/mensaje.mp3")),
            "contact": pygame.mixer.Sound(resource_path("assets/contact.mp3")), "open": pygame.mixer.Sound(resource_path("assets/call.mp3"))
        }
        except: self.snd = {}

    def update(self):
        self.frame_idx = (self.frame_idx + 1) % len(self.bg_frames)
        if STATE.sound_queue:
            s = STATE.sound_queue.pop(0)
            if s in self.snd: self.snd[s].play()


    # Función para hacer scroll en el chat.
    def handle_scroll(self, event):
        if event.type == pygame.MOUSEWHEEL:
            self.scroll_y += event.y * 20
            if self.scroll_y < 0: self.scroll_y = 0


    # Función que muestra por pantalla toda la información.
    def draw(self, screen, font, font_ui, client):
        screen.fill(COLOR_FONDO)
        screen.blit(self.bg_frames[self.frame_idx], (0, 20))
        screen.blit(font_ui.render(STATE.status_msg, True, COLOR_TEXTO), (20, 5))
        
        my_clean = STATE.my_name.split(" [")[0].strip().lower()
        self._draw_face(screen, my_clean, 675, 30)
        
        if STATE.target_name: 
            tg_clean = STATE.target_name.split(" [")[0].strip().lower()
            self._draw_face(screen, tg_clean, 130, 30)

        h_chat = 360; y_base = 238
        sidebar = pygame.Rect(30, y_base, 200, h_chat)
        chat_disp = pygame.Rect(240, y_base, 680, h_chat - 50) 
        input_area = pygame.Rect(240, y_base + h_chat - 40, 680, 40)

        pygame.draw.rect(screen, (0,15,0), sidebar); pygame.draw.rect(screen, COLOR_MARCO, sidebar, 2)
        y_btn = sidebar.top + 10
        self.active_buttons = []
        
        # Muestra la lista de usuarios (AHORA INCLUYE OFFLINE).
        for pid, d in STATE.peers.items():
            sk = f"{d['ip']}:{d['port']}"
            is_verif = "[OK]" in (client.verified_users.get(sk) or "")
            is_in = pid in STATE.incoming_ids
            is_off = sk in client.offline_peers
            is_conn = False
            if STATE.target_info: is_conn = (STATE.target_info[0] == d['ip'] and STATE.target_info[1] == d['port'])

            col = BTN_OFFLINE if is_off else (BTN_VERIFIED if is_verif else (BTN_ALERT if is_in else (BTN_ACTIVE if is_conn else BTN_IDLE)))
            r = pygame.Rect(sidebar.left+5, y_btn, 190, 30)
            pygame.draw.rect(screen, col, r); pygame.draw.rect(screen, COLOR_MARCO, r, 1)
            lbl = f"{d['name'][:9]}"; 
            if is_verif: lbl += " [OK]"
            screen.blit(font.render(lbl, True, COLOR_TEXTO), (r.x+5, r.y+5))
            self.active_buttons.append((r, pid))
            y_btn += 35

        # Aquí gestionamos la mecánica del chat.
        pygame.draw.rect(screen, (0,20,0), chat_disp); pygame.draw.rect(screen, COLOR_MARCO, chat_disp, 3)
        screen.set_clip(chat_disp)
        
        total_h = 0
        msg_dims = []
        for m in STATE.messages:
            if m['is_sys']: h = 30
            else:
                lines = wrap_text(m['text'], font, chat_disp.width - 120)
                h = (len(lines) * 20) + 30 
                
                if m['is_me']:
                    st = m['status']
                    tick = "o" if st=='queued' else ("√" if st=='sent' else "√√")
                    tm = f"{m['time']} [{tick}]"
                else: tm = m['time']
                
                last_w = font.size(lines[-1])[0] if lines else 0
                if last_w + font.size(tm)[0] + 40 > chat_disp.width - 120:
                    h += 20 
            msg_dims.append(h)
            total_h += h + 10

        if total_h > chat_disp.height:
            max_scroll = total_h - chat_disp.height + 20
            if self.scroll_y > max_scroll: self.scroll_y = max_scroll
        else: self.scroll_y = 0

        current_y = chat_disp.bottom - 10 + self.scroll_y
        
        for i in range(len(STATE.messages)-1, -1, -1):
            m = STATE.messages[i]
            h_bub = msg_dims[i]
            y_bub = current_y - h_bub
            
            if y_bub > chat_disp.bottom: current_y -= (h_bub + 10); continue
            if current_y < chat_disp.top: break

            if m['is_sys']:
                lines = wrap_text(m['text'], font, chat_disp.width - 40)
                sy = y_bub + 5
                for l in lines:
                    txt = font.render(l, True, TXT_SYS)
                    screen.blit(txt, (chat_disp.centerx - txt.get_width()//2, sy))
                    sy += 20
            else:
                if m['is_me']: bg, col, align = BUBBLE_ME, TXT_ME, "right"
                else: bg, col, align = BUBBLE_OTHER, TXT_NORMAL, "left"

                full = m['text']
                
                if m['is_me']:
                    st = m['status']
                    tick = "o" if st=='queued' else ("√" if st=='sent' else "√√")
                    tm = f"{m['time']} [{tick}]"
                else: tm = m['time']

                lines = wrap_text(full, font, chat_disp.width - 120)
                
                txt_w = max([font.size(l)[0] for l in lines] + [10])
                tm_w = font.size(tm)[0]
                w_bub = max(txt_w, tm_w) + 40 

                if align == "right": x_bub = chat_disp.right - w_bub - 15
                elif align == "left": x_bub = chat_disp.left + 15
                else: x_bub = chat_disp.centerx - w_bub//2

                r_bub = pygame.Rect(x_bub, y_bub, w_bub, h_bub)
                pygame.draw.rect(screen, bg, r_bub, border_radius=10)
                
                ty = r_bub.y + 10
                for l in lines:
                    screen.blit(font.render(l, True, col), (r_bub.x+10, ty)); ty += 20
                
                t_surf = font.render(tm, True, TXT_TIME)
                screen.blit(t_surf, (r_bub.right - t_surf.get_width()-15, r_bub.bottom-17))

            current_y -= (h_bub + 10)

        screen.set_clip(None)

        pygame.draw.rect(screen, (0,15,0), input_area); pygame.draw.rect(screen, COLOR_MARCO, input_area, 2)
        cursor = "_" if (pygame.time.get_ticks() // 500) % 2 == 0 else ""
        full_in = f"> {STATE.input_text}{cursor}"
        in_lines = wrap_text(full_in, font, input_area.width - 20)
        yt = input_area.bottom - 25
        for l in reversed(in_lines):
            if yt < input_area.top: break
            screen.blit(font.render(l, True, TXT_NORMAL), (input_area.x+10, yt))
            yt -= 18

    # Función para dibujar las caras de los personajes.
    def _draw_face(self, screen, name, x, y):
        clean_name = name.split(" [")[0].lower().strip()
        
        frames = CHARS.get(clean_name)
        
        is_talking = STATE.is_talking(clean_name)

        idx = (pygame.time.get_ticks()//100) % len(frames) if is_talking else 0
        screen.blit(frames[idx], (x, y))


# Main que ejecuta el programa.
async def main():
    if len(sys.argv) > 1: name = sys.argv[1]
    else: name = input("Introduce tu nombre: ")
    if len(sys.argv) > 2: port = int(sys.argv[2])
    else: 
        try: port = int(input("Puerto (por defecto 8888): "))
        except: port = 8888

    STATE.my_name = name
    client = ChatClient(name, port)
    if not client.iniciar_dnie_antes_de_gui(): return

    await client.start()
    pygame.init()
    screen = pygame.display.set_mode((ANCHO, ALTO))
    pygame.display.set_caption(f"MGS CODEC - Puerto {port}")
    global CHARS; CHARS = CodecCharacterLoader()
    
    font = pygame.font.SysFont("consolas", 16)
    font_ui = pygame.font.SysFont("impact", 20)
    gui = CodecDisplay(screen.get_size())
    
    running = True
    while running:
        for e in pygame.event.get():
            if e.type == pygame.QUIT: running = False
            if e.type == pygame.MOUSEWHEEL: gui.handle_scroll(e)
            if e.type == pygame.KEYDOWN:
                if e.key == pygame.K_RETURN:
                    if STATE.input_text: client.process_command(STATE.input_text); STATE.input_text = ""; gui.scroll_y = 0
                elif e.key == pygame.K_BACKSPACE: STATE.input_text = STATE.input_text[:-1]
                else: STATE.input_text += e.unicode
            if e.type == pygame.MOUSEBUTTONDOWN:
                if e.button == 1:
                    for r, pid in gui.active_buttons:
                        if r.collidepoint(e.pos):
                            # Click en un contacto (ONLINE u OFFLINE)
                            if pid in STATE.incoming_ids: client.accept_connection(pid)
                            else: 
                                if pid in STATE.peers:
                                    t = STATE.peers[pid]
                                    client.connect_manual(t['ip'], t['port'], t['name'])
        gui.update(); gui.draw(screen, font, font_ui, client)
        pygame.display.flip(); await asyncio.sleep(0.01)

    await client.stop()
    client.save_sessions_securely()
    pygame.quit()

if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: pass