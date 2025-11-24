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
# (Asegúrate de que crypto.py y protocol.py están en la misma carpeta)
from crypto import KeyManager, SessionCrypto
from protocol import ChatProtocol, MSG_HELLO, MSG_DATA, MSG_DISCOVERY

# --- CONFIGURACIÓN VISUAL Y DE RED ---
ANCHO, ALTO = 950, 650 
COLOR_FONDO = (0, 10, 0) 
COLOR_TEXTO = (50, 220, 50)      
COLOR_TEXTO_YO = (150, 255, 150)
COLOR_MARCO = (20, 100, 20)
COLOR_SYS   = (50, 150, 150)

PORT = 7777 
SESSION_FILE = "sessions.json"

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# ==========================================
# 1. UTILIDADES VISUALES (WRAPPER, GIFS, CHARACTERS)
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
# 2. ESTADO GLOBAL (PUENTE RED <-> UI)
# ==========================================
class AppState:
    def __init__(self):
        self.peers = {}         
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
# 3. LÓGICA DE RED (CORE DE MAIN_V1 ADAPTADO)
# ==========================================
def get_best_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try: s.connect(('8.8.8.8', 1)); IP = s.getsockname()[0]
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

    def load_sessions_from_disk(self):
        if not os.path.exists(SESSION_FILE): return
        try:
            with open(SESSION_FILE, 'r') as f: saved_data = json.load(f)
            count = 0
            for ip, hex_key in saved_data.items():
                session = SessionCrypto(self.key_manager.static_private)
                try:
                    session.load_secret(hex_key)
                    self.sessions[ip] = session
                    count += 1
                except: pass
            if count > 0: STATE.add_message("SYS", f"💾 {count} sesiones cargadas.", is_sys=True)
        except: pass

    def save_sessions_to_disk(self):
        data = {}
        for ip, s in self.sessions.items():
            k = s.export_secret()
            if k: data[ip] = k
        try:
            with open(SESSION_FILE, 'w') as f: json.dump(data, f, indent=4)
        except: pass

    async def start(self):
        self.transport, _ = await self.loop.create_datagram_endpoint(
            lambda: self.protocol, local_addr=("0.0.0.0", PORT), allow_broadcast=True
        )
        self.loop.create_task(self.beacon_loop())

    async def beacon_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try: sock.bind((self.my_ip, 0))
        except: pass
        msg = f"DISCOVERY:{self.name}".encode('utf-8')
        while True:
            try: sock.sendto(msg, (self.broadcast_addr, PORT))
            except: pass
            await asyncio.sleep(3)

    def on_packet(self, packet, addr):
        ip = addr[0]
        if ip == self.my_ip: return 

        if packet.msg_type == MSG_DISCOVERY:
            nombre = packet.payload
            known_ips = [p['ip'] for p in self.peers.values()]
            if ip not in known_ips:
                 pid = self.peer_counter
                 self.peers[pid] = {'ip': ip, 'name': nombre}
                 self.peer_counter += 1
                 STATE.peers = self.peers.copy()
                 if not self.target_ip:
                     STATE.sound_queue.append("contact")
                     STATE.add_message("SYS", f"Detectado: [{pid}] {nombre}", is_sys=True)
            return

        if packet.msg_type == MSG_HELLO:
            if ip in self.sessions: return
            if ip not in self.pending_requests:
                self.pending_requests[ip] = packet.payload
                name, pid_found = ip, "?"
                for pid, d in self.peers.items():
                    if d['ip'] == ip: name, pid_found = d['name'], pid
                STATE.sound_queue.append("call")
                STATE.add_message("SYS", f"📞 LLAMADA DE {name} (ID {pid_found}). '/accept {pid_found}'", is_sys=True)

        elif packet.msg_type == MSG_DATA:
            if ip in self.sessions:
                try:
                    msg = self.sessions[ip].decrypt(packet.payload)
                    name = ip
                    for p in self.peers.values():
                        if p['ip'] == ip: name = p['name']
                    STATE.add_message(name, msg, is_me=False)
                except: STATE.add_message("SYS", f"⚠️ Error desencriptando msg de {ip}", is_sys=True)
            else: STATE.add_message("SYS", f"⚠️ Mensaje ilegible de {ip}.", is_sys=True)

    def process_command(self, text):
        if text.startswith("/connect"):
            parts = text.split()
            if len(parts) > 1 and parts[1].isdigit():
                pid = int(parts[1])
                if pid in self.peers: self.connect_manual(self.peers[pid]['ip'], self.peers[pid]['name'])
                else: STATE.add_message("SYS", "❌ ID incorrecto", is_sys=True)
            else: STATE.add_message("SYS", "⚠️ Uso: /connect <ID>", is_sys=True)
            return

        if text.startswith("/accept"):
            parts = text.split()
            if len(parts) > 1 and parts[1].isdigit(): self.accept_connection(int(parts[1]))
            else: STATE.add_message("SYS", "⚠️ Uso: /accept <ID>", is_sys=True)
            return

        if text == "/leave":
            self.target_ip = None
            STATE.target_name = None
            STATE.set_status("DESCONECTADO - LOBBY")
            STATE.add_message("SYS", "🔌 Desconectado.", is_sys=True)
            return

        if text == "/list":
            STATE.add_message("SYS", "--- CONTACTOS ---", is_sys=True)
            for pid, d in self.peers.items():
                s = " [🔐]" if d['ip'] in self.sessions else ""
                STATE.add_message("SYS", f"[{pid}] {d['name']} {s}", is_sys=True)
            return

        if self.target_ip: self.send_chat(text)
        else: STATE.add_message("SYS", "⛔ No conectado. Usa /connect <ID>", is_sys=True)

    def connect_manual(self, ip_target, name_target):
        if ip_target in self.sessions:
            self.target_ip, STATE.target_name = ip_target, name_target
            STATE.set_status(f"CONECTADO (SECURE): {name_target}")
            STATE.add_message("SYS", f"✅ Sesión restaurada con {name_target}", is_sys=True)
            return

        STATE.add_message("SYS", f"⏳ Llamando a {name_target}...", is_sys=True)
        session = SessionCrypto(self.key_manager.static_private)
        self.sessions[ip_target] = session
        my_key = session.get_ephemeral_public_bytes()
        for _ in range(3): self.protocol.send_packet(ip_target, PORT, MSG_HELLO, 0, my_key)
        self.target_ip, STATE.target_name = ip_target, name_target
        STATE.set_status(f"ESPERANDO A: {name_target}")

    def accept_connection(self, peer_id):
        if peer_id not in self.peers: return
        ip = self.peers[peer_id]['ip']
        if ip not in self.pending_requests: return
        
        try:
            session = SessionCrypto(self.key_manager.static_private)
            self.sessions[ip] = session
            session.perform_handshake(self.pending_requests[ip], is_initiator=True)
            my_key = session.get_ephemeral_public_bytes()
            for _ in range(3): self.protocol.send_packet(ip, PORT, MSG_HELLO, 0, my_key)
            
            self.target_ip = ip
            STATE.target_name = self.peers[peer_id]['name']
            del self.pending_requests[ip]
            self.save_sessions_to_disk()
            STATE.set_status(f"CONECTADO CON: {STATE.target_name}")
            STATE.sound_queue.append("open")
            STATE.add_message("SYS", f"✨ Enlace seguro establecido.", is_sys=True)
        except Exception as e: STATE.add_message("SYS", f"❌ Error: {e}", is_sys=True)

    def send_chat(self, text):
        if self.target_ip in self.sessions:
            try:
                enc = self.sessions[self.target_ip].encrypt(text)
                self.protocol.send_packet(self.target_ip, PORT, MSG_DATA, 1, enc)
                STATE.add_message(self.name, text, is_me=True)
            except: pass

# ==========================================
# 4. INTERFAZ GRÁFICA (CODEC DISPLAY)
# ==========================================
class CodecDisplay:
    def __init__(self, size):
        self.size, self.bg_frames = size, []
        self.bg_current_frame_idx = 0
        self.bg_frame_time = 0
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

    def draw(self, screen, font_chat, font_ui):
        screen.fill(COLOR_FONDO)
        screen.blit(self.bg_frames[self.bg_current_frame_idx], (0, 20))
        screen.blit(font_ui.render(STATE.status_msg, True, COLOR_TEXTO), (20, 5))

        self.draw_character(screen, STATE.my_name, 675, 30)
        if STATE.target_name: self.draw_character(screen, STATE.target_name, 130, 30)

        chat_rect = pygame.Rect(50, 238, ANCHO - 100, 340)
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
    pygame.display.set_caption("MGS SECURE LINK")
    global CHARS
    CHARS = CodecCharacterLoader() 
    font_chat = pygame.font.SysFont("consolas", 18)
    font_ui = pygame.font.SysFont("impact", 20)
    gui = CodecDisplay(screen.get_size())
    clock = pygame.time.Clock()
    
    STATE.add_message("SYS", "Codec activo. '/list' para contactos.", is_sys=True)

    running = True
    while running:
        dt = clock.tick(60) / 1000.0
        for e in pygame.event.get():
            if e.type == pygame.QUIT: 
                client.save_sessions_to_disk()
                running = False
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
    name = sys.argv[1] if len(sys.argv) > 1 else input("Nombre de Agente: ")
    STATE.my_name = name
    client = ChatClient(name)
    await client.start()
    await main_loop(client)

if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: pass