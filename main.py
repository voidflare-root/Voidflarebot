import telebot
import httpx
import socket
import threading
import os # <--- Railway variables ke liye zaruri hai
from telebot import types

# --- CONFIG ---
# Agar Railway Variables mein 'Token' naam ka variable hai toh wo use hoga, 
# nahi toh niche wala hardcoded token use hoga.
HARDCODED_TOKEN = '8623848974:AAEBWQvMrCewfYBmby0QKKMq9M9kVx4AD5U'
API_TOKEN = os.getenv('Token', HARDCODED_TOKEN)

bot = telebot.TeleBot(API_TOKEN)

# --- GLOBAL SETTINGS ---
TIMEOUT = 5
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
TUNABLE_SERVERS = ["Cloudflare", "CloudFront", "Google", "Fastly", "Bunny", "Tengine", "Sucuri", "Gcore", "Imperva", "Tencent"]
NON_TUNABLE_IPS = ["23.", "49.", "184."]

# ================= HELPER FUNCTIONS =================

def get_ip(domain):
    try:
        domain = domain.strip().replace("http://", "").replace("https://", "").split('/')[0]
        return socket.gethostbyname(domain)
    except:
        return None

def check_ports(ip):
    open_ports = []
    test_ports = [80, 443, 8080, 8888, 2052, 2082, 2086, 2087, 2095, 2096]
    for port in test_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        if sock.connect_ex((ip, port)) == 0:
            open_ports.append(str(port))
        sock.close()
    return open_ports

def get_server_info(domain):
    domain = domain.strip().replace("http://", "").replace("https://", "").split('/')[0]
    try:
        with httpx.Client(verify=False, timeout=TIMEOUT) as client:
            r = client.get(f"https://{domain}", follow_redirects=True)
            server = r.headers.get("Server", "Unknown")
            headers_str = str(r.headers).lower()
            
            detected_cdn = "Unknown"
            for s in TUNABLE_SERVERS:
                if s.lower() in server.lower() or s.lower() in headers_str:
                    detected_cdn = s
                    break
            return r.status_code, server, detected_cdn
    except:
        return 0, "No Response", "Unknown"

def generate_ssh_payload(domain, cdn):
    if cdn == "Cloudflare":
        return f"GET / HTTP/1.1[crlf]Host: {domain}[crlf]Upgrade: websocket[crlf]Connection: Upgrade[crlf][crlf]"
    elif cdn == "CloudFront":
        return f"GET / HTTP/1.1[crlf]Host: {domain}[crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf]X-Amz-Cf-Id: tunnel-req[crlf][crlf]"
    elif cdn == "Google":
        return f"CONNECT {domain}:443 HTTP/1.1[crlf]Host: {domain}[crlf]X-Forwarded-For: 8.8.8.8[crlf][crlf]"
    else:
        return f"GET / HTTP/1.1[crlf]Host: {domain}[crlf]Proxy-Connection: Keep-Alive[crlf][crlf]"

# ================= KEYBOARDS =================

def main_menu():
    markup = types.ReplyKeyboardMarkup(row_width=2, resize_keyboard=True)
    markup.add('📂 Domain File Scanner', '⚡ TCP/HTTP Scanner')
    markup.add('🔍 CDN Finder', '🎯 Tunable Checker')
    markup.add('🌐 Subdomain Finder', '❌ Exit')
    markup.add('➕ More')
    return markup

def more_menu():
    markup = types.ReplyKeyboardMarkup(row_width=1, resize_keyboard=True)
    markup.add('📄 Single Domain Scan', '🔙 Back to Menu')
    return markup

# ================= STEP HANDLERS =================

def step_file_scan(message):
    if not message.document:
        bot.send_message(message.chat.id, "❌ Error: Please upload a .txt file.")
        return
    file_info = bot.get_file(message.document.file_id)
    content = bot.download_file(file_info.file_path).decode("utf-8").splitlines()
    bot.send_message(message.chat.id, f"⏳ Scanning {len(content)} domains... Please wait.")
    
    results = ""
    for d in content[:15]:
        code, server, _ = get_server_info(d)
        results += f"🌐 `{d.strip()}` | `{code}` | `{server}`\n"
    bot.send_message(message.chat.id, results if results else "No results found.", parse_mode='Markdown')

def step_tcp_scan(message):
    host = message.text.strip()
    ip = get_ip(host)
    if not ip:
        bot.send_message(message.chat.id, "❌ Error: Host resolve nahi ho raha.")
        return
    bot.send_message(message.chat.id, f"⚙️ Scanning ports for {host}...")
    ports = check_ports(ip)
    code, server, _ = get_server_info(host)
    res = (f"⚡ *Advanced Scan Result*\n\n"
           f"🌐 *Host:* `{host}`\n"
           f"📍 *IP:* `{ip}`\n"
           f"🚥 *Status:* `{code}`\n"
           f"🖥 *Server:* `{server}`\n"
           f"🔌 *Open Ports:* `{', '.join(ports) if ports else 'All Closed'}`")
    bot.send_message(message.chat.id, res, parse_mode='Markdown')

def step_cdn_finder(message):
    host = message.text.strip()
    _, server, cdn = get_server_info(host)
    bot.send_message(message.chat.id, f"🔍 *CDN Info*\n\n🌐 *Host:* {host}\n📦 *CDN:* `{cdn}`\n🖥 *Server:* `{server}`", parse_mode='Markdown')

def step_tunable(message):
    host = message.text.strip()
    ip = get_ip(host)
    if not ip:
        bot.send_message(message.chat.id, "❌ Error: Host resolve nahi ho raha.")
        return
    _, server, cdn = get_server_info(host)
    is_ip_ok = not any(ip.startswith(p) for p in NON_TUNABLE_IPS)
    is_cdn_ok = cdn != "Unknown"
    if is_ip_ok and is_cdn_ok:
        payload = generate_ssh_payload(host, cdn)
        msg = (f"✅ *STATUS: TUNNABLE*\n\n"
               f"🎯 *Host:* `{host}`\n"
               f"📍 *IP:* `{ip}`\n"
               f"📦 *CDN:* `{cdn}`\n\n"
               f"🚀 *Payload (SSH):*\n`{payload}`")
    else:
        msg = f"❌ *STATUS: NON-TUNNABLE*\n\n🎯 *Host:* {host}\n⚠️ *Reason:* Server ({cdn}) or IP range not supported."
    bot.send_message(message.chat.id, msg, parse_mode='Markdown')

def step_subdomain(message):
    domain = message.text.strip()
    common_subs = ['www', 'mail', 'api', 'dev', 'blog', 'cdn', 'whm', 'cpanel', 'webmail', 'vps']
    bot.send_message(message.chat.id, f"🔎 Searching subdomains for `{domain}`...", parse_mode='Markdown')
    found = []
    for sub in common_subs:
        target = f"{sub}.{domain}"
        if get_ip(target): found.append(target)
    if found:
        bot.send_message(message.chat.id, "✅ *Subdomains Found:*\n\n" + "\n".join(found))
    else:
        bot.send_message(message.chat.id, "❌ No subdomains found.")

# ================= MAIN ROUTER =================

@bot.message_handler(commands=['start'])
def start_cmd(message):
    bot.send_message(message.chat.id, "🔥 *VoidFlare v1.1 Online*\nSelect a tool:", 
                     parse_mode='Markdown', reply_markup=main_menu())

@bot.message_handler(func=lambda m: True)
def main_router(message):
    choice = message.text
    if choice == '📂 Domain File Scanner':
        msg = bot.send_message(message.chat.id, "📤 Upload `.txt` file:")
        bot.register_next_step_handler(msg, step_file_scan)
    elif choice == '⚡ TCP/HTTP Scanner':
        msg = bot.send_message(message.chat.id, "🎯 Enter Host:")
        bot.register_next_step_handler(msg, step_tcp_scan)
    elif choice == '🔍 CDN Finder':
        msg = bot.send_message(message.chat.id, "🌐 Enter Host:")
        bot.register_next_step_handler(msg, step_cdn_finder)
    elif choice == '🎯 Tunable Checker':
        msg = bot.send_message(message.chat.id, "🎯 Enter Host:")
        bot.register_next_step_handler(msg, step_tunable)
    elif choice == '🌐 Subdomain Finder':
        msg = bot.send_message(message.chat.id, "🔎 Enter Domain:")
        bot.register_next_step_handler(msg, step_subdomain)
    elif choice == '➕ More':
        bot.send_message(message.chat.id, "🛠 *More Tools*", reply_markup=more_menu(), parse_mode='Markdown')
    elif choice == '📄 Single Domain Scan':
        msg = bot.send_message(message.chat.id, "⌨️ Enter Host Name:")
        bot.register_next_step_handler(msg, step_tcp_scan)
    elif choice == '🔙 Back to Menu':
        bot.send_message(message.chat.id, "🔙 Back", reply_markup=main_menu())
    elif choice == '❌ Exit':
        bot.send_message(message.chat.id, "👋 Bye!", reply_markup=types.ReplyKeyboardRemove())

# RUN
if __name__ == "__main__":
    print("Bot is starting...")
    bot.infinity_polling()
