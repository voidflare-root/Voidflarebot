import os
import re
import socket
import httpx
import telebot
from bs4 import BeautifulSoup
from telebot import types

# ================= CONFIG =================
API_TOKEN = os.getenv("Token", "PASTE_NEW_BOT_TOKEN_HERE")
bot = telebot.TeleBot(API_TOKEN)

TIMEOUT = 12
RESULTS = {}

# ================= MENU =================
def main_menu():
    markup = types.ReplyKeyboardMarkup(row_width=2, resize_keyboard=True)
    markup.add("🌐 Subdomain Finder", "⚡ TCP/HTTP Scanner")
    markup.add("🔍 CDN Finder", "❌ Exit")
    return markup

# ================= HELPERS =================
def clean_domain(domain):
    domain = domain.lower().strip()
    domain = domain.replace("https://", "").replace("http://", "")
    domain = domain.split("/")[0].split(":")[0]
    return domain

def is_valid_domain(domain):
    return re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", domain) is not None

def get_ip(host):
    try:
        return socket.gethostbyname(host)
    except:
        return "No IP"

def get_server_info(domain):
    try:
        with httpx.Client(verify=False, timeout=TIMEOUT) as client:
            r = client.get(f"https://{domain}", follow_redirects=True)
            server = r.headers.get("Server", "Unknown")
            return r.status_code, server
    except:
        return 0, "No Response"

# ================= SUBDOMAIN SOURCES =================
def crtsh(domain):
    found = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = httpx.get(url, timeout=TIMEOUT)
        if r.status_code == 200:
            for item in r.json():
                for sub in item.get("name_value", "").split("\n"):
                    sub = sub.lower().replace("*.", "").strip()
                    if sub.endswith(domain):
                        found.add(sub)
    except:
        pass
    return found

def hackertarget(domain):
    found = set()
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        r = httpx.get(url, timeout=TIMEOUT)
        for line in r.text.splitlines():
            sub = line.split(",")[0].strip().lower()
            if sub.endswith(domain):
                found.add(sub)
    except:
        pass
    return found

def rapiddns(domain):
    found = set()
    try:
        url = f"https://rapiddns.io/subdomain/{domain}?full=1"
        r = httpx.get(url, timeout=TIMEOUT)
        soup = BeautifulSoup(r.text, "html.parser")
        text = soup.get_text("\n")
        pattern = rf"[a-zA-Z0-9._-]+\.{re.escape(domain)}"
        for sub in re.findall(pattern, text):
            found.add(sub.lower().replace("*.", "").strip())
    except:
        pass
    return found

def alienvault(domain):
    found = set()
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        r = httpx.get(url, timeout=TIMEOUT)
        data = r.json()
        for item in data.get("passive_dns", []):
            sub = item.get("hostname", "").lower().strip()
            if sub.endswith(domain):
                found.add(sub)
    except:
        pass
    return found

def common_bruteforce(domain):
    words = [
        "www", "mail", "api", "dev", "test", "beta", "admin", "panel",
        "cpanel", "webmail", "cdn", "vpn", "ssh", "ftp", "m", "app",
        "blog", "shop", "store", "support", "help", "login", "portal",
        "dashboard", "server", "host", "cloud", "static", "assets"
    ]
    found = set()
    for word in words:
        sub = f"{word}.{domain}"
        if get_ip(sub) != "No IP":
            found.add(sub)
    return found

def find_all_subdomains(domain):
    all_subs = set()

    sources = [
        crtsh,
        hackertarget,
        rapiddns,
        alienvault,
        common_bruteforce
    ]

    for source in sources:
        all_subs.update(source(domain))

    final = []
    for sub in sorted(all_subs):
        ip = get_ip(sub)
        final.append((sub, ip))

    return final

# ================= BUTTONS =================
def result_buttons(domain):
    markup = types.InlineKeyboardMarkup()
    markup.add(
        types.InlineKeyboardButton("👁 View", callback_data=f"view|{domain}"),
        types.InlineKeyboardButton("⬇️ Download", callback_data=f"download|{domain}")
    )
    return markup

# ================= SCANNERS =================
def step_subdomain(message):
    domain = clean_domain(message.text)

    if not is_valid_domain(domain):
        bot.send_message(message.chat.id, "❌ Sahi domain bhejo.\nExample: `example.com`", parse_mode="Markdown")
        return

    msg = bot.send_message(
        message.chat.id,
        f"🔎 Searching subdomains...\n🌐 `{domain}`",
        parse_mode="Markdown"
    )

    results = find_all_subdomains(domain)

    if not results:
        bot.edit_message_text("❌ No subdomains found.", message.chat.id, msg.message_id)
        return

    RESULTS[domain] = results

    filename = f"{domain}_subdomains.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"Domain: {domain}\n")
        f.write(f"Total Subdomains: {len(results)}\n\n")
        for sub, ip in results:
            f.write(f"{sub} | {ip}\n")

    bot.edit_message_text(
        f"✅ Scan Complete!\n\n"
        f"🌐 Domain: `{domain}`\n"
        f"📌 Total Found: `{len(results)}`\n\n"
        f"Button choose karo:",
        message.chat.id,
        msg.message_id,
        parse_mode="Markdown",
        reply_markup=result_buttons(domain)
    )

def step_tcp_scan(message):
    host = clean_domain(message.text)
    ip = get_ip(host)
    code, server = get_server_info(host)

    res = (
        f"⚡ *TCP/HTTP Scan*\n\n"
        f"🌐 Host: `{host}`\n"
        f"📍 IP: `{ip}`\n"
        f"🚥 Status: `{code}`\n"
        f"🖥 Server: `{server}`"
    )
    bot.send_message(message.chat.id, res, parse_mode="Markdown")

def step_cdn_finder(message):
    host = clean_domain(message.text)
    code, server = get_server_info(host)

    cdn = "Unknown"
    text = server.lower()

    for name in ["cloudflare", "cloudfront", "fastly", "google", "bunny", "sucuri", "gcore", "imperva"]:
        if name in text:
            cdn = name.title()
            break

    bot.send_message(
        message.chat.id,
        f"🔍 *CDN Info*\n\n🌐 Host: `{host}`\n📦 CDN: `{cdn}`\n🖥 Server: `{server}`",
        parse_mode="Markdown"
    )

# ================= CALLBACK =================
@bot.callback_query_handler(func=lambda call: True)
def callback(call):
    try:
        action, domain = call.data.split("|")
    except:
        return

    if domain not in RESULTS:
        bot.answer_callback_query(call.id, "Result expired. Scan again.")
        return

    if action == "view":
        text = f"👁 Subdomains for {domain}\n\n"
        for sub, ip in RESULTS[domain][:60]:
            text += f"{sub} | {ip}\n"

        if len(RESULTS[domain]) > 60:
            text += f"\n...and {len(RESULTS[domain]) - 60} more. Download full file."

        bot.send_message(call.message.chat.id, text[:4000])

    elif action == "download":
        filename = f"{domain}_subdomains.txt"

        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"Domain: {domain}\n")
            f.write(f"Total Subdomains: {len(RESULTS[domain])}\n\n")
            for sub, ip in RESULTS[domain]:
                f.write(f"{sub} | {ip}\n")

        with open(filename, "rb") as file:
            bot.send_document(call.message.chat.id, file, caption="⬇️ Full subdomain result file")

    bot.answer_callback_query(call.id)

# ================= START =================
@bot.message_handler(commands=["start"])
def start_cmd(message):
    bot.send_message(
        message.chat.id,
        "🔥 *VoidFlare Subdomain Bot Online*\n\nSelect a tool:",
        parse_mode="Markdown",
        reply_markup=main_menu()
    )

@bot.message_handler(func=lambda m: True)
def main_router(message):
    choice = message.text

    if choice == "🌐 Subdomain Finder":
        msg = bot.send_message(message.chat.id, "🔎 Enter Domain:\nExample: `example.com`", parse_mode="Markdown")
        bot.register_next_step_handler(msg, step_subdomain)

    elif choice == "⚡ TCP/HTTP Scanner":
        msg = bot.send_message(message.chat.id, "🎯 Enter Host:")
        bot.register_next_step_handler(msg, step_tcp_scan)

    elif choice == "🔍 CDN Finder":
        msg = bot.send_message(message.chat.id, "🌐 Enter Host:")
        bot.register_next_step_handler(msg, step_cdn_finder)

    elif choice == "❌ Exit":
        bot.send_message(message.chat.id, "👋 Bye!", reply_markup=types.ReplyKeyboardRemove())

    else:
        bot.send_message(message.chat.id, "Menu se option select karo.", reply_markup=main_menu())

# ================= RUN =================
if __name__ == "__main__":
    print("Bot is starting...")
    bot.infinity_polling(timeout=60, long_polling_timeout=60)
