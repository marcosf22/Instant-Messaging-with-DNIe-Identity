import asyncio
import sys
import socket
import json
import os
import threading
import zlib
import struct
import pygame
from datetime import datetime
from PIL import Image as PILImage, ImageSequence

# Módulos propios
from crypto import KeyManager, SessionCrypto
from protocol import ChatProtocol, MSG_HELLO, MSG_DATA, MSG_DISCOVERY, MSG_AUTH

# Configuración
ANCHO, ALTO = 950, 650 
COLOR_FONDO = (0, 10, 0) 
COLOR_TEXTO = (50, 220, 50)      
COLOR_TEXTO_YO = (150, 255, 150)
COLOR_MARCO = (20, 100, 20)
COLOR_SYS   = (50, 150, 150)

BTN_IDLE    = (0, 40, 0)
BTN_HOVER   = (0, 70, 0)
BTN_ACTIVE  = (0, 100, 0)
BTN_ALERT   = (180, 100, 0)
BTN_VERIFIED = (218, 165, 32)

PORT = 8888
SESSION_FILE = "sessions.json"

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# --- UTILIDADES ---
def wrap_text(text, font, max_width):
    words = text.split(' ')
    lines = []
    current = ""
    for w in words:
        test = current + " " + w if current else w
        if font.size(test)[0] <= max_width: current = test
        else:
            if current: lines.append(current)
            current = w
    if current: lines.append(current)
    return lines

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

class CodecCharacterLoader:
    def __init__(self):
        self.chars = {}; self.keys = []
        self.load()
    def load(self):
        f = os.path.join("assets", "characters")
        if not os.path.exists(f): os.makedirs(f, exist_ok=True)
        s = pygame.Surface((150, 200)); s.fill((0,20,0))
        pygame.draw.rect(s, COLOR_TEXTO, (0,0,150,200), 2)
        self.chars['default'] = [s]
        for file in os.listdir(f):
            if file.endswith('.gif'):
                frames = load_gif_frames(os.path.join(f, file), (150,200))
                if frames: self.chars[file.split('.')[0].lower()] = frames
        self.keys = sorted(list(self.chars.keys()))
    def get(self, uid):
        if not self.keys: return self.chars['default']
        return self.chars[self.keys[zlib.crc32(str(uid).encode()) % len(self.keys)]]

class AppState:
    def __init__(self):
        self.peers = {}
        self.incoming_ids = []
        self.messages = []
        self.input_text = ""
        self.my_name = "Snake"
        self.target_name = None
        self.status_msg = "EN LOBBY"
        self.talking_timer = {}
        self.sound_queue = []
    def add_message(self, snd, txt, is_me=False, is_sys=False):
        t = datetime.now().strftime("%H:%M")
        self.messages.append({'sender': snd, 'text': txt, 'is_me': is_me, 'is_sys': is_sys, 'time': t})
        if not is_sys:
            self.talking_timer[snd] = pygame.time.get_ticks() + 2500
            if not is_me: self.sound_queue.append("msg")
    def is_talking(self, name):
        return name in self.talking_timer and pygame.time.get_ticks() < self.talking_timer[name]
    def set_status(self, t): self.status_msg = t

STATE = AppState()
CHARS = None

# --- RED ---
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
        self.broadcast_addr = "255.255.255.255"
        self.key_manager = KeyManager(f"{name}_identity")
        self.sessions = {}
        self.peers = {}
        self.peer_counter = 0
        self.target_ip = None
        self.pending_requests = {}
        self.verified_users = {}
        self.protocol = ChatProtocol(self.on_packet)
        self.load_sessions_from_disk()

    def iniciar_dnie_antes_de_gui(self):
        return self.key_manager.iniciar_sesion_dnie()

    def load_sessions_from_disk(self):
        if not os.path.exists(SESSION_FILE): return
        try:
            with open(SESSION_FILE, 'r') as f: d = json.load(f)
            c = 0
            for ip, hx in d.items():
                s = SessionCrypto() # ARREGLADO: Sin argumentos
                try: s.load_secret(hx); self.sessions[ip] = s; c += 1
                except: pass
            if c > 0: STATE.add_message("SYS", f"💾 {c} sesiones cargadas.", True)
        except: pass

    def save_sessions_to_disk(self):
        d = {ip: s.export_secret() for ip, s in self.sessions.items() if s.export_secret()}
        try: 
            with open(SESSION_FILE, 'w') as f: json.dump(d, f, indent=4)
        except: pass

    async def start(self):
        self.transport, _ = await self.loop.create_datagram_endpoint(
            lambda: self.protocol, local_addr=("0.0.0.0", PORT), allow_broadcast=True
        )
        self.loop.create_task(self.beacon_loop())

    async def beacon_loop(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try: s.bind((self.my_ip, 0))
        except: pass
        msg = f"DISCOVERY:{self.name}".encode()
        while True:
            try: s.sendto(msg, (self.broadcast_addr, PORT))
            except: pass
            await asyncio.sleep(3)

    def send_verification(self):
        if not self.target_ip: return STATE.add_message("SYS", "⛔ Conecta primero.", True)
        STATE.add_message("SYS", "💳 Firmando...", True)
        threading.Thread(target=self._firmar_y_enviar, daemon=True).start()

    def _firmar_y_enviar(self):
        try:
            # ARREGLADO: Usamos get_public_bytes
            clave_pub = self.sessions[self.target_ip].get_public_bytes() 
            cert, firma = self.key_manager.firmar_handshake(clave_pub)
            if not cert: return
            
            payload = struct.pack("!I", len(cert)) + cert + \
                      struct.pack("!I", len(firma)) + firma + \
                      clave_pub
            
            enc = self.sessions[self.target_ip].encrypt(payload.decode('latin1'))
            self.loop.call_soon_threadsafe(self.protocol.send_packet, self.target_ip, PORT, MSG_AUTH, 0, enc)
            STATE.add_message("SYS", "📤 Identidad enviada.", True)
        except Exception as e: STATE.add_message("SYS", f"❌ Error DNIe: {e}", True)

    def on_packet(self, pkt, addr):
        ip = addr[0]
        if ip == self.my_ip: return

        if pkt.msg_type == MSG_DISCOVERY:
            n = pkt.payload.decode('utf-8', 'ignore') if isinstance(pkt.payload, bytes) else str(pkt.payload)
            if ip not in [p['ip'] for p in self.peers.values()]:
                pid = self.peer_counter; self.peers[pid] = {'ip': ip, 'name': n}; self.peer_counter += 1
                STATE.peers = self.peers.copy()
                if not self.target_ip: 
                    STATE.sound_queue.append("contact")
                    STATE.add_message("SYS", f"Radar: {n}", True)

        elif pkt.msg_type == MSG_HELLO:
            if ip in self.sessions:
                try:
                    self.sessions[ip].compute_secret(pkt.payload) # Renegociar
                    self.save_sessions_to_disk()
                    STATE.sound_queue.append("open")
                    STATE.add_message("SYS", f"✅ CONEXIÓN OK: {ip}", True)
                except: pass
            elif ip not in self.pending_requests:
                self.pending_requests[ip] = pkt.payload
                name = ip
                for d in self.peers.values(): 
                    if d['ip'] == ip: name = d['name']
                
                pid_found = -1
                for pid, d in self.peers.items():
                    if d['ip'] == ip: pid_found = pid
                if pid_found != -1 and pid_found not in STATE.incoming_ids:
                    STATE.incoming_ids.append(pid_found)

                STATE.sound_queue.append("call")
                STATE.add_message("SYS", f"🔔 LLAMADA DE {name}", True)

        elif pkt.msg_type == MSG_DATA:
            if ip in self.sessions:
                try:
                    msg = self.sessions[ip].decrypt(pkt.payload)
                    sender = self.verified_users.get(ip, ip)
                    if sender == ip: 
                        for p in self.peers.values(): 
                            if p['ip'] == ip: sender = p['name']
                    STATE.add_message(sender, msg)
                except:
                    del self.sessions[ip]
                    self.connect_manual(ip)
            else: self.connect_manual(ip)

        elif pkt.msg_type == MSG_AUTH:
            if ip in self.sessions:
                try:
                    dec = self.sessions[ip].decrypt(pkt.payload).encode('latin1')
                    off = 0
                    l_c = struct.unpack("!I", dec[off:off+4])[0]; off+=4
                    cert = dec[off:off+l_c]; off+=l_c
                    l_s = struct.unpack("!I", dec[off:off+4])[0]; off+=4
                    sig = dec[off:off+l_s]; off+=l_s
                    pk = dec[off:] 
                    
                    valid, cn = self.key_manager.verificar_handshake(pk, cert, sig)
                    if valid:
                        STATE.sound_queue.append("open")
                        STATE.add_message("SYS", f"✅ DNIe VERIFICADO: {cn}", True)
                        self.verified_users[ip] = f"{cn} [✓]"
                        if self.target_ip == ip:
                            STATE.target_name = self.verified_users[ip]
                            STATE.set_status(f"CONECTADO: {STATE.target_name}")
                    else: STATE.add_message("SYS", f"❌ FIRMA FALSA", True)
                except: pass

    def connect_manual(self, ip, name="Unknown"):
        if ip in self.sessions:
            real = self.verified_users.get(ip, name)
            self.target_ip, STATE.target_name = ip, real
            STATE.set_status(f"CONECTADO: {real}")
            STATE.add_message("SYS", "Retomando chat.", True)
            return

        STATE.add_message("SYS", f"--> Llamando a {name}...", True)
        # ARREGLADO: Sin argumentos
        s = SessionCrypto()
        self.sessions[ip] = s
        
        # ARREGLADO: get_public_bytes
        mk = s.get_public_bytes()
        
        for _ in range(3): self.protocol.send_packet(ip, PORT, MSG_HELLO, 0, mk)
        self.target_ip, STATE.target_name = ip, name
        STATE.set_status(f"LLAMANDO A {name}...")

    def accept_connection(self, pid):
        if pid not in self.peers: return
        ip = self.peers[pid]['ip']
        name = self.peers[pid]['name']
        if ip not in self.pending_requests: return
        
        STATE.add_message("SYS", "Conectando...", True)
        # ARREGLADO: Sin argumentos
        s = SessionCrypto()
        self.sessions[ip] = s
        s.compute_secret(self.pending_requests[ip])
        
        # ARREGLADO: get_public_bytes
        mk = s.get_public_bytes()
        
        for _ in range(3): self.protocol.send_packet(ip, PORT, MSG_HELLO, 0, mk)
        
        del self.pending_requests[ip]
        if pid in STATE.incoming_ids: STATE.incoming_ids.remove(pid)
        self.save_sessions_to_disk()
        self.target_ip = ip
        STATE.target_name = name
        STATE.set_status(f"CONECTADO: {name}")
        STATE.sound_queue.append("open")

    def send_msg(self, text):
        if self.target_ip: 
            try:
                enc = self.sessions[self.target_ip].encrypt(text)
                self.protocol.send_packet(self.target_ip, PORT, MSG_DATA, 1, enc)
                STATE.add_message(self.name, text, True)
            except: pass

    def process_command(self, text):
        if text == "/verify": self.send_verification()
        elif text == "/leave":
            self.target_ip = None
            STATE.set_status("LOBBY")
            STATE.add_message("SYS", "Desconectado.", True)
        elif self.target_ip: self.send_msg(text)

class CodecDisplay:
    def __init__(self, size):
        self.bg_frames = load_gif_frames("assets/codec_background.gif", (ANCHO, 350))
        if not self.bg_frames: self.bg_frames=[pygame.Surface((ANCHO, 350))]
        self.frame_idx = 0
        self.active_buttons = []
        try: pygame.mixer.init(); self.snd = {
            "call": pygame.mixer.Sound("assets/call.mp3"),
            "msg": pygame.mixer.Sound("assets/call.mp3"),
            "contact": pygame.mixer.Sound("assets/call.mp3"),
            "open": pygame.mixer.Sound("assets/open.mp3")
        }
        except: self.snd = {}

    def update(self):
        self.frame_idx = (self.frame_idx + 1) % len(self.bg_frames)
        if STATE.sound_queue:
            s = STATE.sound_queue.pop(0)
            if s in self.snd: self.snd[s].play()

    def draw(self, screen, font, font_ui, client):
        screen.fill(COLOR_FONDO)
        screen.blit(self.bg_frames[self.frame_idx], (0, 20))
        screen.blit(font_ui.render(STATE.status_msg, True, COLOR_TEXTO), (20, 5))
        self._draw_face(screen, STATE.my_name, 675, 30)
        if STATE.target_name: self._draw_face(screen, STATE.target_name, 130, 30)

        h_chat, y_base = 340, 238
        sidebar = pygame.Rect(30, y_base, 200, h_chat)
        chat = pygame.Rect(240, y_base, 680, h_chat)

        pygame.draw.rect(screen, (0,15,0), sidebar); pygame.draw.rect(screen, COLOR_MARCO, sidebar, 2)
        y_btn = sidebar.top + 10
        self.active_buttons = []
        
        for pid, d in STATE.peers.items():
            is_verif = "[✓]" in client.verified_users.get(d['ip'], "")
            is_in = pid in STATE.incoming_ids
            is_conn = client.target_ip == d['ip']
            col = BTN_VERIFIED if is_verif else (BTN_ALERT if is_in else (BTN_ACTIVE if is_conn else BTN_IDLE))
            
            r = pygame.Rect(sidebar.left+5, y_btn, 190, 30)
            pygame.draw.rect(screen, col, r)
            pygame.draw.rect(screen, COLOR_MARCO, r, 1)
            
            lbl = f"{d['name'][:9]}"
            if is_verif: lbl += " [✓]"
            screen.blit(font.render(lbl, True, COLOR_TEXTO), (r.x+5, r.y+5))
            
            label = "LINKED" if is_conn else ("ACCEPT" if is_in else ("SECURE" if is_verif else "CALL"))
            s_lbl = font.render(label, True, (0,0,0) if is_in or is_verif else COLOR_MARCO)
            screen.blit(s_lbl, (r.right - s_lbl.get_width()-5, r.y+5))
            
            self.active_buttons.append((r, pid))
            y_btn += 35

        pygame.draw.rect(screen, (0,20,0), chat); pygame.draw.rect(screen, COLOR_MARCO, chat, 3)
        screen.set_clip(chat)
        y = chat.bottom - 40
        for m in reversed(STATE.messages):
            col = COLOR_SYS if m['is_sys'] else (COLOR_TEXTO_YO if m['is_me'] else COLOR_TEXTO)
            txt = f"<{m['sender']}> {m['text']}"
            for l in reversed(wrap_text(txt, font, chat.width-20)):
                screen.blit(font.render(l, True, col), (chat.x+10, y))
                y -= 20
                if y < chat.top: break
            if y < chat.top: break
        screen.set_clip(None)
        screen.blit(font.render(f"> {STATE.input_text}_", True, COLOR_TEXTO_YO), (chat.x+10, chat.bottom - 30))

    def _draw_face(self, screen, name, x, y):
        clean_name = name.split(" [")[0].lower()
        frames = CHARS.get(clean_name)
        idx = (pygame.time.get_ticks()//100) % len(frames) if STATE.is_talking(clean_name) else 0
        screen.blit(frames[idx], (x, y))

async def main():
    if len(sys.argv) > 1: name = sys.argv[1]
    else: name = input("Nombre: ")
    STATE.my_name = name
    
    client = ChatClient(name)
    if not client.iniciar_dnie_antes_de_gui(): return

    await client.start()

    pygame.init()
    screen = pygame.display.set_mode((ANCHO, ALTO))
    pygame.display.set_caption("MGS CODEC")
    
    global CHARS
    CHARS = CodecCharacterLoader()
    font = pygame.font.SysFont("consolas", 16)
    font_ui = pygame.font.SysFont("impact", 20)
    gui = CodecDisplay(screen.get_size())
    clock = pygame.time.Clock()

    running = True
    while running:
        for e in pygame.event.get():
            if e.type == pygame.QUIT: running = False
            if e.type == pygame.KEYDOWN:
                if e.key == pygame.K_RETURN:
                    if STATE.input_text: client.process_command(STATE.input_text)
                    STATE.input_text = ""
                elif e.key == pygame.K_BACKSPACE: STATE.input_text = STATE.input_text[:-1]
                else: STATE.input_text += e.unicode
            if e.type == pygame.MOUSEBUTTONDOWN:
                for r, pid in gui.active_buttons:
                    if r.collidepoint(e.pos):
                        if pid in STATE.incoming_ids: client.accept_connection(pid)
                        else: client.connect_manual(client.peers[pid]['ip'], client.peers[pid]['name'])

        gui.update()
        gui.draw(screen, font, font_ui, client)
        pygame.display.flip()
        await asyncio.sleep(0.01)

    client.save_sessions_to_disk()
    pygame.quit()

if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: pass