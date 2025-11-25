import asyncio
import sys
import socket
import json
import os
import zlib
import struct
import pygame
from datetime import datetime
from PIL import Image as PILImage, ImageSequence

# --- MÓDULOS PROPIOS ---
from crypto import KeyManager, SessionCrypto
from protocol import ChatProtocol, MSG_HELLO, MSG_DATA, MSG_DISCOVERY, MSG_AUTH

# --- CONFIGURACIÓN VISUAL ---
ANCHO, ALTO = 950, 650 
COLOR_FONDO = (0, 10, 0) 
COLOR_TEXTO = (50, 220, 50)      
COLOR_TEXTO_YO = (150, 255, 150)
COLOR_MARCO = (20, 100, 20)
COLOR_SYS   = (50, 150, 150)

# ESTADOS DE LOS BOTONES
BTN_IDLE    = (0, 40, 0)        # Estado normal (Para llamar)
BTN_HOVER   = (0, 70, 0)        # Ratón encima
BTN_ACTIVE  = (0, 100, 0)       # Ya conectado
BTN_ALERT   = (180, 100, 0)     # ¡LLAMADA ENTRANTE! (Naranja)
BTN_VERIFIED = (218, 165, 32)   # Verificado DNIe (Dorado)

PORT = 8888
SESSION_FILE = "sessions.json"

if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# ==========================================
# 1. UTILIDADES GRÁFICAS
# ==========================================
def wrap_text(text, font, max_width):
    words = text.split(' ')
    lines = []
    current_line = ""
    for word in words:
        test_line = current_line + " " + word if current_line else word
        w, _ = font.size(test_line)
        if w <= max_width: current_line = test_line
        else:
            if current_line: lines.append(current_line)
            current_line = word
    if current_line: lines.append(current_line)
    return lines

def load_gif_frames(filepath, size=None):
    frames = []
    if not os.path.exists(filepath): return []
    try:
        pil_img = PILImage.open(filepath)
        for frame in ImageSequence.Iterator(pil_img):
            frame_rgba = frame.convert("RGBA")
            py_img = pygame.image.fromstring(frame_rgba.tobytes(), frame_rgba.size, frame_rgba.mode).convert_alpha()
            if size: py_img = pygame.transform.scale(py_img, size)
            frames.append(py_img)
    except: pass
    return frames

class CodecCharacterLoader:
    def __init__(self):
        self.characters = {}
        self.sorted_keys = []
        self.load_characters()

    def load_characters(self):
        char_folder = os.path.join("assets", "characters")
        if not os.path.exists(char_folder): os.makedirs(char_folder, exist_ok=True)
        
        # Default fallback
        s = pygame.Surface((150, 200)); s.fill((0, 20, 0))
        pygame.draw.rect(s, COLOR_TEXTO, (0,0,150,200), 2)
        self.characters['default'] = [s]

        for f in os.listdir(char_folder):
            if f.endswith('.gif'):
                name = f.split('.')[0].lower()
                frames = load_gif_frames(os.path.join(char_folder, f), size=(150, 200))
                if frames: self.characters[name] = frames
        
        self.sorted_keys = sorted(list(self.characters.keys()))

    def get_frames(self, unique_id):
        if not self.sorted_keys: return self.characters['default']
        try: val = zlib.crc32(str(unique_id).encode())
        except: val = 0
        return self.characters[self.sorted_keys[val % len(self.sorted_keys)]]

# ==========================================
# 2. ESTADO GLOBAL DE LA APP
# ==========================================
class AppState:
    def __init__(self):
        self.peers = {}         
        self.incoming_ids = []  # Lista de IDs que nos están llamando
        self.messages = []      
        self.input_text = ""
        self.my_name = "Snake"
        self.target_name = None 
        self.status_msg = "EN LOBBY - Esperando..."
        self.talking_timer = {} 
        self.sound_queue = []   

    def add_message(self, sender, text, is_me=False, is_sys=False):
        timestamp = datetime.now().strftime("%H:%M")
        self.messages.append({'sender': sender, 'text': text, 'is_me': is_me, 'is_sys': is_sys, 'time': timestamp})
        if not is_sys:
            self.talking_timer[sender] = pygame.time.get_ticks() + 2500
            if not is_me: self.sound_queue.append("msg")

    def is_talking(self, user_name):
        return user_name in self.talking_timer and pygame.time.get_ticks() < self.talking_timer[user_name]

    def set_status(self, txt): self.status_msg = txt

STATE = AppState()
CHARS = None 

# ==========================================
# 3. LOGICA DE CHAT (BACKEND)
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
        self.broadcast_addr = "255.255.255.255"
        
        try: self.key_manager = KeyManager(f"{name}_identity")
        except: sys.exit(1)

        self.sessions = {}        
        self.peers = {}           
        self.peer_counter = 0     
        self.target_ip = None     
        self.pending_requests = {} 
        self.verified_users = {} 

        self.protocol = ChatProtocol(self.on_packet)
        self.load_sessions_from_disk()

    # --- DNIe PREVIO ---
    def iniciar_dnie_antes_de_gui(self):
        print("\n🔐 INICIANDO SISTEMA DE SEGURIDAD DNIe...")
        if self.key_manager.iniciar_sesion_dnie():
            print("✅ DNIe Listo. Abriendo Interfaz...")
            return True
        else:
            print("❌ Fallo en DNIe. Abriendo sin firma...")
            return False

    # --- PERSISTENCIA ---
    def load_sessions_from_disk(self):
        if not os.path.exists(SESSION_FILE): return
        try:
            with open(SESSION_FILE, 'r') as f: saved_data = json.load(f)
            count = 0
            for ip, hex_key in saved_data.items():
                s = SessionCrypto(self.key_manager.static_private) # type: ignore
                try: s.load_secret(hex_key); self.sessions[ip] = s; count += 1
                except: pass
            if count > 0: STATE.add_message("SYS", f"💾 {count} sesiones cargadas.", is_sys=True)
        except: pass

    def save_sessions_to_disk(self):
        d = {ip: s.export_secret() for ip, s in self.sessions.items() if s.export_secret()}
        try: 
            with open(SESSION_FILE, 'w') as f: json.dump(d, f, indent=4)
        except: pass

    # --- RED ---
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

    # --- VERIFICACIÓN ---
    def send_verification(self):
        if not self.target_ip: return STATE.add_message("SYS", "⛔ Conecta primero.", is_sys=True)
        STATE.add_message("SYS", "💳 Firmando con DNIe...", is_sys=True)
        threading.Thread(target=self._firmar_y_enviar, daemon=True).start()

    def _firmar_y_enviar(self):
        try:
            clave_pub = self.sessions[self.target_ip].get_public_bytes() 
            cert, firma = self.key_manager.firmar_handshake(clave_pub)
            if not cert: return

            payload = struct.pack("!I", len(cert)) + cert + \
                      struct.pack("!I", len(firma)) + firma + \
                      clave_pub
            
            enc = self.sessions[self.target_ip].encrypt(payload.decode('latin1'))
            self.loop.call_soon_threadsafe(self.protocol.send_packet, self.target_ip, PORT, MSG_AUTH, 0, enc)
            STATE.add_message("SYS", "📤 Identidad enviada.", is_sys=True)
        except Exception as e:
            STATE.add_message("SYS", f"❌ Error DNIe: {e}", is_sys=True)

    # --- RECEPCIÓN ---
    def on_packet(self, pkt, addr):
        ip = addr[0]
        if ip == self.my_ip: return

        # DISCOVERY
        if pkt.msg_type == MSG_DISCOVERY:
            name = pkt.payload.decode('utf-8', 'ignore') if isinstance(pkt.payload, bytes) else str(pkt.payload)
            if ip not in [p['ip'] for p in self.peers.values()]:
                pid = self.peer_counter; self.peers[pid] = {'ip': ip, 'name': name}; self.peer_counter += 1
                STATE.peers = self.peers.copy()
                if not self.target_ip: 
                    STATE.sound_queue.append("contact")
                    STATE.add_message("SYS", f"Radar: {name}", is_sys=True)

        # HELLO (Handshake / Llamada)
        elif pkt.msg_type == MSG_HELLO:
            if ip in self.sessions:
                try:
                    self.sessions[ip].perform_handshake(pkt.payload, True)
                    self.save_sessions_to_disk()
                    STATE.sound_queue.append("open")
                    STATE.add_message("SYS", f"✅ CONEXIÓN OK: {ip}", is_sys=True)
                except: pass
            elif ip not in self.pending_requests:
                self.pending_requests[ip] = pkt.payload
                # BUSCAR ID PARA MARCARLO EN ROJO (INCOMING)
                pid_found = -1
                for pid, d in self.peers.items():
                    if d['ip'] == ip: pid_found = pid
                
                if pid_found != -1 and pid_found not in STATE.incoming_ids:
                    STATE.incoming_ids.append(pid_found)

                STATE.sound_queue.append("call")
                STATE.add_message("SYS", f"🔔 LLAMADA DE {ip}. ¡PULSA EL BOTÓN!", is_sys=True)

        # DATA
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

        # AUTH
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
                        STATE.add_message("SYS", f"✅ DNIe VERIFICADO: {cn}", is_sys=True)
                        self.verified_users[ip] = f"{cn} [✓]"
                        if self.target_ip == ip:
                            STATE.target_name = self.verified_users[ip]
                            STATE.set_status(f"CONECTADO: {STATE.target_name}")
                    else:
                        STATE.add_message("SYS", f"❌ FIRMA FALSA", is_sys=True)
                except: pass

    # --- ACCIONES CLICABLES ---
    def connect_manual(self, ip, name="Unknown"):
        """Llamar a alguien (Click en botón verde)"""
        if ip in self.sessions:
            real = self.verified_users.get(ip, name)
            self.target_ip, STATE.target_name = ip, real
            STATE.set_status(f"CONECTADO: {real}")
            STATE.add_message("SYS", "Retomando chat.", is_sys=True)
            return

        STATE.add_message("SYS", f"--> Llamando a {name}...", is_sys=True)
        s = SessionCrypto(self.key_manager.static_private) # type: ignore
        self.sessions[ip] = s
        mk = s.get_ephemeral_public_bytes()
        for _ in range(3): self.protocol.send_packet(ip, PORT, MSG_HELLO, 0, mk)
        self.target_ip, STATE.target_name = ip, name
        STATE.set_status(f"LLAMANDO A {name}...")

    def accept_connection(self, pid):
        """Aceptar llamada (Click en botón naranja)"""
        if pid not in self.peers: return
        ip = self.peers[pid]['ip']
        name = self.peers[pid]['name']

        if ip not in self.pending_requests: return
        
        STATE.add_message("SYS", "Conectando...", is_sys=True)
        s = SessionCrypto(self.key_manager.static_private) # type: ignore
        self.sessions[ip] = s
        s.perform_handshake(self.pending_requests[ip], True)
        mk = s.get_ephemeral_public_bytes()
        for _ in range(3): self.protocol.send_packet(ip, PORT, MSG_HELLO, 0, mk)
        
        del self.pending_requests[ip]
        # QUITAR DE LA LISTA DE LLAMADAS ENTRANTES
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
            STATE.add_message("SYS", "Desconectado.", is_sys=True)
        elif self.target_ip: self.send_msg(text)

# ==========================================
# 4. INTERFAZ DE USUARIO (FRONTEND)
# ==========================================
class CodecDisplay:
    def __init__(self, size):
        self.bg_frames = load_gif_frames("assets/codec_background.gif", size=(ANCHO, 350))
        if not self.bg_frames:
            s = pygame.Surface((ANCHO, 350)); s.fill((10,30,10)); self.bg_frames=[s]
        self.frame_idx = 0
        # Lista de zonas clickables: [(Rect, PID, TIPO_ACCION)]
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

        # Caras
        self._draw_face(screen, STATE.my_name, 675, 30)
        if STATE.target_name: self._draw_face(screen, STATE.target_name, 130, 30)

        # Layout
        h_chat = 340
        y_base = 238
        sidebar = pygame.Rect(30, y_base, 200, h_chat)
        chat = pygame.Rect(240, y_base, 680, h_chat)

        # --- DIBUJAR LISTA DE CONTACTOS (BOTONES) ---
        pygame.draw.rect(screen, (0,15,0), sidebar)
        pygame.draw.rect(screen, COLOR_MARCO, sidebar, 2)
        
        y_btn = sidebar.top + 10
        self.active_buttons = [] # Reiniciamos zonas clickables
        mx, my = pygame.mouse.get_pos()
        
        for pid, d in STATE.peers.items():
            # Determinar color y estado del botón
            is_verif = "[✓]" in client.verified_users.get(d['ip'], "")
            is_incoming = pid in STATE.incoming_ids # ¿Nos está llamando?
            is_connected = (client.target_ip == d['ip'])

            col = BTN_IDLE
            label = "CALL"
            
            if is_connected:
                col = BTN_ACTIVE
                label = "LINKED"
            elif is_incoming:
                # Parpadeo Naranja
                if (pygame.time.get_ticks() // 500) % 2 == 0: col = BTN_ALERT
                else: col = (100, 50, 0)
                label = "ACCEPT !"
            elif is_verif:
                col = BTN_VERIFIED
                label = "SECURE"
            
            # Rectángulo del botón
            rect = pygame.Rect(sidebar.left+5, y_btn, 190, 30)
            
            # Hover Effect
            if rect.collidepoint(mx, my) and not is_incoming and not is_connected:
                col = BTN_HOVER

            pygame.draw.rect(screen, col, rect)
            pygame.draw.rect(screen, COLOR_MARCO, rect, 1)
            
            # Texto Nombre
            lbl_name = f"{d['name'][:9]}"
            screen.blit(font.render(lbl_name, True, COLOR_TEXTO), (rect.x+5, rect.y+5))
            
            # Texto Estado (Derecha)
            lbl_stat = font.render(label, True, (0,0,0) if is_incoming or is_verif else COLOR_MARCO)
            screen.blit(lbl_stat, (rect.right - lbl_stat.get_width() - 5, rect.y+5))
            
            # Guardamos botón para detectar clic luego
            self.active_buttons.append((rect, pid))
            y_btn += 35

        # --- CHAT ---
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

        # Input
        screen.blit(font.render(f"> {STATE.input_text}_", True, COLOR_TEXTO_YO), (chat.x+10, chat.bottom - 30))

    def _draw_face(self, screen, name, x, y):
        clean_name = name.split(" [")[0].lower()
        frames = CHARS.get_frames(clean_name)
        idx = (pygame.time.get_ticks()//100) % len(frames) if STATE.is_talking(clean_name) else 0
        screen.blit(frames[idx], (x, y))

# ==========================================
# 5. BUCLE PRINCIPAL (GESTIÓN DE CLICS)
# ==========================================
async def main():
    if len(sys.argv) > 1: name = sys.argv[1]
    else: name = input("Nombre de Agente: ")
    STATE.my_name = name
    
    client = ChatClient(name)
    
    # 1. PEDIR PIN ANTES DE ABRIR VENTANA
    client.iniciar_dnie_antes_de_gui()

    await client.start()

    pygame.init()
    screen = pygame.display.set_mode((ANCHO, ALTO))
    pygame.display.set_caption("MGS CODEC - DNIe SECURE")
    
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
            
            # ESCRIBIR
            if e.type == pygame.KEYDOWN:
                if e.key == pygame.K_RETURN:
                    if STATE.input_text: client.process_command(STATE.input_text)
                    STATE.input_text = ""
                elif e.key == pygame.K_BACKSPACE: STATE.input_text = STATE.input_text[:-1]
                else: STATE.input_text += e.unicode
            
            # --- GESTIÓN DE CLICS EN BOTONES ---
            if e.type == pygame.MOUSEBUTTONDOWN:
                if e.button == 1: # Clic Izquierdo
                    for rect, pid in gui.active_buttons:
                        if rect.collidepoint(e.pos):
                            # LÓGICA DE CLIC INTELIGENTE
                            
                            # A) Si nos están llamando (Está en la lista de incoming) -> ACEPTAR
                            if pid in STATE.incoming_ids:
                                client.accept_connection(pid)
                            
                            # B) Si no estamos conectados con él -> LLAMAR
                            else:
                                peer_ip = client.peers[pid]['ip']
                                peer_name = client.peers[pid]['name']
                                
                                # Solo llamar si no estamos ya conectados a esa IP
                                if client.target_ip != peer_ip:
                                    client.connect_manual(peer_ip, peer_name)

        gui.update()
        gui.draw(screen, font, font_ui, client)
        pygame.display.flip()
        await asyncio.sleep(0.01)

    client.save_sessions_to_disk()
    pygame.quit()

if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: pass
