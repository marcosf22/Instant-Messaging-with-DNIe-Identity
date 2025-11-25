import asyncio
import sys
import socket
import json
import os
import zlib
import pygame
from datetime import datetime
from PIL import Image as PILImage, ImageSequence

# --- IMPORTAMOS TU LIBRERÍA DE SEGURIDAD Y PROTOCOLO ---
from crypto import KeyManager, SessionCrypto
from protocol import ChatProtocol, MSG_HELLO, MSG_DATA, MSG_DISCOVERY

# --- CONFIGURACIÓN VISUAL Y DE RED ---
ANCHO, ALTO = 950, 650 
COLOR_FONDO = (0, 10, 0) 
COLOR_TEXTO = (50, 220, 50)      
COLOR_TEXTO_YO = (150, 255, 150)
COLOR_MARCO = (20, 100, 20)
COLOR_SYS   = (50, 150, 150)

# Colores para botones
BTN_IDLE    = (0, 40, 0)
BTN_HOVER   = (0, 70, 0)
BTN_ACTIVE  = (0, 100, 0)
BTN_ALERT   = (180, 100, 0)

PORT = 7777 # Usamos 7777 para la GUI como pediste
SESSION_FILE = "sessions.json"

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# ==========================================
# 1. UTILIDADES VISUALES
# ==========================================

def wrap_text(text, font, max_width):
    words = text.split(' ')
    lines = []
    current_line = ""
    for word in words:
        test_line = current_line + " " + word if current_line else word
        w, _ = font.size(test_line)
        if w <= max_width:
            current_line = test_line
        else:
            if current_line: lines.append(current_line)
            current_line = ""
            w_word, _ = font.size(word)
            if w_word <= max_width:
                current_line = word
            else:
                for char in word:
                    test = current_line + char
                    if font.size(test)[0] <= max_width: current_line = test
                    else: lines.append(current_line); current_line = char
    if current_line: lines.append(current_line)
    return lines

def load_gif_frames(filepath, size=None):
    frames = []
    if not os.path.exists(filepath): return []
    try:
        pil_img = PILImage.open(filepath)
        for frame in ImageSequence.Iterator(pil_img):
            frame_rgba = frame.convert("RGBA")
            data = frame_rgba.tobytes()
            py_img = pygame.image.fromstring(data, frame_rgba.size, frame_rgba.mode).convert_alpha()
            if size:
                py_img = pygame.transform.scale(py_img, size)
            frames.append(py_img)
    except Exception as e:
        print(f"⚠️ Error cargando GIF {filepath}: {e}")
    return frames

class CodecCharacterLoader:
    def __init__(self):
        self.characters = {} 
        self.sorted_keys = [] 
        self.load_characters()

    def load_characters(self):
        char_folder = os.path.join("assets", "characters")
        if not os.path.exists(char_folder):
            os.makedirs(char_folder, exist_ok=True)
            self.create_default_fallback()
            return

        files = [f for f in os.listdir(char_folder) if f.lower().endswith('.gif')]
        files.sort() 

        for filename in files:
            name = filename.split('.')[0].lower()
            path = os.path.join(char_folder, filename)
            frames = load_gif_frames(path, size=(150, 200))
            if frames:
                self.characters[name] = frames

        self.sorted_keys = list(self.characters.keys())
        self.sorted_keys.sort()
        
        if not self.characters: self.create_default_fallback()

    def create_default_fallback(self):
        s = pygame.Surface((150, 200))
        s.fill((0, 40, 0))
        pygame.draw.rect(s, COLOR_TEXTO, (0,0,150,200), 2)
        self.characters['default'] = [s]

    def get_frames(self, unique_id):
        if not self.sorted_keys: return self.characters.get('default', [])
        try: val = zlib.crc32(str(unique_id).encode())
        except: val = 0
        index = val % len(self.sorted_keys)
        return self.characters[self.sorted_keys[index]]

# ==========================================
# 2. ESTADO GLOBAL
# ==========================================
class AppState:
    def __init__(self):
        self.peers = {}         
        self.incoming_ids = [] 
        self.messages = []      
        self.input_text = ""
        self.my_name = "Snake"
        self.target_name = None 
        self.status_msg = "EN LOBBY - Esperando..."
        self.talking_timer = {} 
        self.sound_queue = []   

    def add_message(self, sender, text, is_me=False, is_sys=False):
        timestamp = datetime.now().strftime("%H:%M")
        self.messages.append({
            'sender': sender, 'text': text, 
            'is_me': is_me, 'is_sys': is_sys, 'time': timestamp
        })
        if not is_sys:
            self.talking_timer[sender] = pygame.time.get_ticks() + 2500
            if not is_me: self.sound_queue.append("msg")

    def is_talking(self, user_name):
        return user_name in self.talking_timer and pygame.time.get_ticks() < self.talking_timer[user_name]

    def set_status(self, txt):
        self.status_msg = txt

STATE = AppState()
CHARS = None 

# ==========================================
# 3. LÓGICA DE RED (ACTUALIZADA CON TU NUEVO MAIN_V1)
# ==========================================
def get_best_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 1)) 
        IP = s.getsockname()[0]
    except: IP = '127.0.0.1'
    finally: s.close()
    return IP

class ChatClient:
    def __init__(self, name):
        self.name = name
        self.loop = asyncio.get_running_loop()
        self.my_ip = get_best_ip()
        
        try:
            parts = self.my_ip.split('.')
            self.broadcast_addr = f"{parts[0]}.{parts[1]}.{parts[2]}.255"
        except: self.broadcast_addr = "255.255.255.255"

        print(f"--> Mi IP: {self.my_ip}")

        try:
            self.key_manager = KeyManager(f"{name}_identity")
        except Exception as e:
            STATE.add_message("SYS", f"Error Crypto: {e}", is_sys=True)
            sys.exit(1)

        self.sessions = {}        
        self.peers = {}           
        self.peer_counter = 0     
        self.target_ip = None     
        self.pending_requests = {} 

        self.protocol = ChatProtocol(self.on_packet)
        self.transport = None
        self.load_sessions_from_disk()

    # --- PERSISTENCIA ---
    def load_sessions_from_disk(self):
        if not os.path.exists(SESSION_FILE): return
        try:
            with open(SESSION_FILE, 'r') as f:
                saved_data = json.load(f)
            count = 0
            for ip, hex_key in saved_data.items():
                session = SessionCrypto(self.key_manager.static_private)
                try:
                    session.load_secret(hex_key)
                    self.sessions[ip] = session
                    count += 1
                except: pass
            if count > 0: STATE.add_message("SYS", f"💾 {count} sesiones recuperadas.", is_sys=True)
        except: pass

    def save_sessions_to_disk(self):
        data = {}
        for ip, session in self.sessions.items():
            k = session.export_secret()
            if k: data[ip] = k
        try:
            with open(SESSION_FILE, 'w') as f: json.dump(data, f, indent=4)
        except: pass

    async def start(self):
        print(f"--- CHAT INICIADO EN {PORT} ---")
        self.transport, _ = await self.loop.create_datagram_endpoint(
            lambda: self.protocol, local_addr=("0.0.0.0", PORT), allow_broadcast=True
        )
        self.loop.create_task(self.beacon_loop())

    async def beacon_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try: sock.bind((self.my_ip, 0))
        except: pass
        msg = f"DISCOVERY:{self.name}".encode()
        while True:
            try: sock.sendto(msg, (self.broadcast_addr, PORT))
            except: pass
            await asyncio.sleep(3)

    # --- PAQUETES (Lógica del nuevo main_v1) ---
    def on_packet(self, packet, addr):
        ip = addr[0]
        if ip == self.my_ip: return 

        # 1. DISCOVERY
        if packet.msg_type == MSG_DISCOVERY:
            # En el nuevo main_v1, el payload es texto puro
            try:
                # El discovery original mandaba bytes. Si tu protocolo dice que es texto:
                if isinstance(packet.payload, bytes):
                    name = packet.payload.decode('utf-8', errors='ignore')
                else:
                    name = str(packet.payload)
            except: name = "Unknown"

            known_ips = [p['ip'] for p in self.peers.values()]
            if ip not in known_ips:
                 pid = self.peer_counter
                 self.peers[pid] = {'ip': ip, 'port': PORT, 'name': name}
                 self.peer_counter += 1
                 # ACTUALIZAR ESTADO VISUAL
                 STATE.peers = self.peers.copy()
                 if not self.target_ip:
                     STATE.sound_queue.append("contact")
                     STATE.add_message("SYS", f"Nuevo contacto: [{pid}] {name}", is_sys=True)
            return

        # 2. HANDSHAKE (HELLO)
        elif packet.msg_type == MSG_HELLO:
            # Caso A: Ya tenemos sesión (Somos el que inició la conexión y recibe respuesta)
            if ip in self.sessions:
                try:
                    self.sessions[ip].perform_handshake(packet.payload, True)
                    self.save_sessions_to_disk()
                    
                    # Sonido de éxito
                    STATE.sound_queue.append("open") 
                    STATE.add_message("SYS", f"✅ CONEXIÓN COMPLETADA CON {ip}", is_sys=True)
                except: pass
                return

            # Caso B: Nueva petición entrante (Somos el receptor)
            if ip not in self.pending_requests:
                self.pending_requests[ip] = packet.payload
                
                name, pid_found = ip, -1
                for pid, d in self.peers.items():
                    if d['ip'] == ip: name, pid_found = d['name'], pid
                
                # Activar botón parpadeante
                if pid_found != -1 and pid_found not in STATE.incoming_ids:
                    STATE.incoming_ids.append(pid_found)

                STATE.sound_queue.append("call")
                STATE.add_message("SYS", f"🔔 Solicitud de {name}. Pulsa ACCEPT.", is_sys=True)

        # 3. DATA
        elif packet.msg_type == MSG_DATA:
            if ip in self.sessions:
                try:
                    msg = self.sessions[ip].decrypt(packet.payload)
                    name = ip
                    for p in self.peers.values():
                        if p['ip'] == ip: name = p['name']
                    
                    STATE.add_message(name, msg, is_me=False)
                except:
                    STATE.add_message("SYS", f"♻️ Clave vieja falló con {ip}. Renegociando...", is_sys=True)
                    del self.sessions[ip]
                    self.save_sessions_to_disk()
                    self.connect_manual(ip) # Intentamos reconectar automáticamente
            else:
                STATE.add_message("SYS", f"⚠️ Mensaje ilegible de {ip}. Reconectando...", is_sys=True)
                self.connect_manual(ip)

    # --- ACCIONES MANUALES (Adaptadas a GUI) ---
    def connect_manual(self, ip_target, name_target="Desconocido"):
        if ip_target in self.sessions:
            self.target_ip, STATE.target_name = ip_target, name_target
            STATE.set_status(f"CONECTADO (SECURE): {name_target}")
            STATE.add_message("SYS", "✅ Usando clave guardada. Chat listo.", is_sys=True)
            return

        STATE.add_message("SYS", f"--> Enviando solicitud a {ip_target}...", is_sys=True)
        session = SessionCrypto(self.key_manager.static_private)
        self.sessions[ip_target] = session
        
        try:
            mk = session.get_ephemeral_public_bytes()
            for _ in range(3): 
                self.protocol.send_packet(ip_target, PORT, MSG_HELLO, 0, mk)
            
            self.target_ip, STATE.target_name = ip_target, name_target
            STATE.set_status(f"ESPERANDO A: {name_target}")
        except Exception as e:
            STATE.add_message("SYS", f"❌ Error: {e}", is_sys=True)
            del self.sessions[ip_target]

    def accept_connection(self, peer_id):
        if peer_id not in self.peers: return 
        ip = self.peers[peer_id]['ip']
        name = self.peers[peer_id]['name']

        if ip not in self.pending_requests: 
            STATE.add_message("SYS", "⚠️ No hay solicitud.", is_sys=True)
            return
        
        STATE.add_message("SYS", f"✅ Aceptando a {name}...", is_sys=True)
        session = SessionCrypto(self.key_manager.static_private)
        self.sessions[ip] = session
        try:
            session.perform_handshake(self.pending_requests[ip], True)
            mk = session.get_ephemeral_public_bytes()
            for _ in range(3): 
                self.protocol.send_packet(ip, PORT, MSG_HELLO, 0, mk)
            
            self.target_ip = ip
            STATE.target_name = name
            del self.pending_requests[ip]
            
            if peer_id in STATE.incoming_ids:
                STATE.incoming_ids.remove(peer_id)
                
            self.save_sessions_to_disk()
            
            STATE.set_status(f"CONECTADO CON: {name}")
            STATE.sound_queue.append("open")
            STATE.add_message("SYS", f"✨ CONEXIÓN ESTABLECIDA.", is_sys=True)
        except Exception as e: 
            STATE.add_message("SYS", f"❌ Error: {e}", is_sys=True)

    def send_chat(self, text):
        if self.target_ip and self.target_ip in self.sessions:
            try:
                enc = self.sessions[self.target_ip].encrypt(text)
                self.protocol.send_packet(self.target_ip, PORT, MSG_DATA, 1, enc)
                STATE.add_message(self.name, text, is_me=True)
            except: pass
        else: STATE.add_message("SYS", "⛔ No conectado.", is_sys=True)

    # --- PROCESAR COMANDOS DE TEXTO ---
    def process_command(self, text):
        if text.startswith("/connect"):
            parts = text.split()
            if len(parts) > 1 and parts[1].isdigit():
                pid = int(parts[1])
                if pid in self.peers: 
                    self.connect_manual(self.peers[pid]['ip'], self.peers[pid]['name'])
            return

        if text.startswith("/accept"):
            parts = text.split()
            if len(parts) > 1 and parts[1].isdigit(): self.accept_connection(int(parts[1]))
            return
            
        if text == "/leave":
            self.disconnect_current()
            return

        if self.target_ip: 
            self.send_chat(text)
        else: 
            STATE.add_message("SYS", "⛔ No conectado. Usa la lista o /connect", is_sys=True)

    def disconnect_current(self):
        if self.target_ip:
             STATE.add_message("SYS", f"🔌 Desconectado de {STATE.target_name}.", is_sys=True)
             self.target_ip = None
             STATE.target_name = None
             STATE.set_status("DESCONECTADO - LOBBY")

# ==========================================
# 4. INTERFAZ GRÁFICA
# ==========================================
class CodecDisplay:
    def __init__(self, size):
        self.size = size
        self.bg_frames = []
        self.bg_current_frame_idx = 0
        self.bg_frame_time = 0
        self.active_buttons = [] 
        self.load_assets()

    def load_assets(self):
        self.bg_frames = load_gif_frames("assets/codec_background.gif", size=(ANCHO, 350)) 
        if not self.bg_frames:
            f = pygame.Surface((ANCHO, 350)); f.fill((10, 30, 10)); self.bg_frames = [f]
        try: 
            pygame.mixer.init()
            self.sounds = {
                "call": pygame.mixer.Sound("assets/call.mp3"),
                "contact": pygame.mixer.Sound("assets/call.mp3"), 
                "msg": pygame.mixer.Sound("assets/call.mp3"),
                "open": pygame.mixer.Sound("assets/call.mp3") 
            }
            if os.path.exists("assets/open.mp3"):
                self.sounds["open"] = pygame.mixer.Sound("assets/open.mp3")
            for s in self.sounds.values(): s.set_volume(0.3)
        except: self.sounds = {}

    def update(self, dt):
        self.bg_frame_time += dt
        if self.bg_frame_time > 0.08: 
            self.bg_current_frame_idx = (self.bg_current_frame_idx + 1) % len(self.bg_frames)
            self.bg_frame_time = 0
        if STATE.sound_queue:
            snd = STATE.sound_queue.pop(0)
            if snd in self.sounds: self.sounds[snd].play()

    def handle_event(self, event, client):
        if event.type == pygame.MOUSEBUTTONDOWN:
            if event.button == 1: # Clic izquierdo
                mx, my = event.pos
                for rect, pid, status in self.active_buttons:
                    if rect.collidepoint(mx, my):
                        if status == "INCOMING":
                            client.accept_connection(pid)
                        elif status == "IDLE":
                            # Buscamos nombre
                            name = "Desconocido"
                            if pid in STATE.peers: name = STATE.peers[pid]['name']
                            client.connect_manual(STATE.peers[pid]['ip'], name)

    def draw(self, screen, font_chat, font_ui):
        screen.fill(COLOR_FONDO)
        self.active_buttons = [] 
        
        # FONDO
        screen.blit(self.bg_frames[self.bg_current_frame_idx], (0, 20))
        screen.blit(font_ui.render(STATE.status_msg, True, COLOR_TEXTO), (20, 5))

        # PERSONAJES
        self.draw_character(screen, STATE.my_name, 675, 30)
        if STATE.target_name: self.draw_character(screen, STATE.target_name, 130, 30)

        # LAYOUT
        margen_x = 30
        altura_base = 238
        altura_total = 340
        ancho_sidebar = 200
        gap = 10
        
        sidebar_rect = pygame.Rect(margen_x, altura_base, ancho_sidebar, altura_total)
        chat_x = margen_x + ancho_sidebar + gap
        chat_width = ANCHO - chat_x - margen_x
        chat_rect = pygame.Rect(chat_x, altura_base, chat_width, altura_total)

        # SIDEBAR
        pygame.draw.rect(screen, (0, 15, 0), sidebar_rect)
        pygame.draw.rect(screen, COLOR_MARCO, sidebar_rect, 2)
        screen.blit(font_ui.render("FREQ LIST", True, COLOR_MARCO), (sidebar_rect.left + 10, sidebar_rect.top + 10))
        pygame.draw.line(screen, COLOR_MARCO, (sidebar_rect.left, sidebar_rect.top + 35), (sidebar_rect.right, sidebar_rect.top + 35), 1)

        y_btn = sidebar_rect.top + 45
        if not STATE.peers:
            screen.blit(font_chat.render("Scanning...", True, (30, 80, 30)), (sidebar_rect.left + 10, y_btn))
        else:
            mx, my = pygame.mouse.get_pos()
            for pid, data in STATE.peers.items():
                name = data['name']
                is_target = (name == STATE.target_name)
                is_incoming = (pid in STATE.incoming_ids)
                
                btn_rect = pygame.Rect(sidebar_rect.left + 5, y_btn, ancho_sidebar - 10, 30)
                
                bg_col = BTN_IDLE
                txt_col = COLOR_TEXTO
                label = "CALL"
                status = "IDLE"

                if is_target and "CONECTADO" in STATE.status_msg:
                    bg_col = BTN_ACTIVE
                    txt_col = (150, 255, 150)
                    label = "LINKED 🔐"
                    status = "CONNECTED"
                elif is_incoming:
                    if (pygame.time.get_ticks() // 500) % 2 == 0:
                        bg_col = BTN_ALERT
                        txt_col = (0, 0, 0)
                    label = "ACCEPT !"
                    status = "INCOMING"
                elif btn_rect.collidepoint(mx, my):
                    bg_col = BTN_HOVER
                    txt_col = (200, 255, 200)

                pygame.draw.rect(screen, bg_col, btn_rect)
                pygame.draw.rect(screen, COLOR_MARCO, btn_rect, 1)
                
                name_surf = font_chat.render(f"[{pid}] {name[:10]}", True, txt_col)
                screen.blit(name_surf, (btn_rect.left + 5, btn_rect.centery - 9))
                
                act_surf = font_chat.render(label, True, txt_col if not is_incoming or bg_col == BTN_IDLE else (0,0,0))
                screen.blit(act_surf, (btn_rect.right - act_surf.get_width() - 5, btn_rect.centery - 9))

                self.active_buttons.append((btn_rect, pid, status))
                y_btn += 35

        # CHAT
        pygame.draw.rect(screen, (0, 20, 0), chat_rect)
        pygame.draw.rect(screen, COLOR_MARCO, chat_rect, 3)
        screen.blit(pygame.font.Font(None, 20).render("ENCRYPTED TRANSMISSION", True, COLOR_MARCO), (chat_rect.right - 180, chat_rect.top + 5))

        screen.set_clip(chat_rect)
        y_off = chat_rect.bottom - 45
        for m in reversed(STATE.messages):
            sender = "SYSTEM" if m['is_sys'] else m['sender']
            full = f"<{sender} {m['time']}> {m['text']}"
            for line in reversed(wrap_text(full, font_chat, chat_rect.width - 30)):
                col = COLOR_SYS if m['is_sys'] else (COLOR_TEXTO_YO if m['is_me'] else COLOR_TEXTO)
                surf = font_chat.render(line, True, col)
                y_off -= 22
                if y_off < chat_rect.top + 15: break
                screen.blit(surf, (chat_rect.left + 15, y_off))
            y_off -= 8 
            if y_off < chat_rect.top + 15: break
        screen.set_clip(None)

        # INPUT
        pygame.draw.line(screen, COLOR_MARCO, (chat_rect.left, chat_rect.bottom - 35), (chat_rect.right, chat_rect.bottom - 35), 2)
        cur = "_" if (pygame.time.get_ticks() // 500) % 2 == 0 else ""
        screen.blit(font_chat.render(f"> {STATE.input_text}{cur}", True, COLOR_TEXTO_YO), (chat_rect.left + 15, chat_rect.bottom - 28))

    def draw_character(self, screen, name, x, y):
        frames = CHARS.get_frames(name)
        img = frames[(pygame.time.get_ticks()//120)%len(frames)] if STATE.is_talking(name) else frames[0]
        screen.blit(img, (x, y))

# ==========================================
# 5. MAIN ASYNC LOOP
# ==========================================
async def main_loop(client):
    pygame.init()
    screen = pygame.display.set_mode((ANCHO, ALTO))
    pygame.display.set_caption("MGS SECURE LINK - TACTICAL")
    global CHARS
    CHARS = CodecCharacterLoader() 
    font_chat = pygame.font.SysFont("consolas", 18)
    font_ui = pygame.font.SysFont("impact", 20)
    gui = CodecDisplay(screen.get_size())
    clock = pygame.time.Clock()
    
    STATE.add_message("SYS", "Codec activo. Buscando frecuencias...", is_sys=True)

    running = True
    while running:
        dt = clock.tick(60) / 1000.0
        for e in pygame.event.get():
            if e.type == pygame.QUIT: 
                client.save_sessions_to_disk()
                running = False
            
            gui.handle_event(e, client)

            if e.type == pygame.KEYDOWN:
                if e.key == pygame.K_RETURN:
                    if STATE.input_text.strip(): client.process_command(STATE.input_text.strip())
                    STATE.input_text = ""
                elif e.key == pygame.K_BACKSPACE: STATE.input_text = STATE.input_text[:-1]
                else: 
                    if len(STATE.input_text)<200 and e.unicode.isprintable(): STATE.input_text+=e.unicode
        
        gui.update(dt)
        gui.draw(screen, font_chat, font_ui)
        pygame.display.flip()
        await asyncio.sleep(0.01)
    pygame.quit()

async def main():
    if len(sys.argv) > 1: name = sys.argv[1]
    else: name = input("Nombre de Agente: ")
    STATE.my_name = name
    client = ChatClient(name)
    await client.start()
    await main_loop(client)

if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: pass