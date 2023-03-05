import os, json
from logging import getLogger
from datetime import datetime, timedelta
from asgiref.sync import sync_to_async
from models import (Base, 
                    Users, 
                    Offers, 
                    Guests, 
                    UsersOffersLink, 
                    V2Ray)
from asyncio import sleep
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from utils import (generate_trojan_str, 
                   generate_password, 
                   TrojanBackend, 
                   VmessBackend)
from telegram import (Update, 
                      ReplyKeyboardMarkup)
from telegram.ext import (
    Application,
    PicklePersistence,
    ConversationHandler,
    ContextTypes,
    CommandHandler,
    MessageHandler,
    filters,
)


logger = getLogger(__name__)
token = os.environ.get("BOT_TOKEN")
bot_name = "vpn_bot only"
DB_PATH = "/root/telbot/data.db"
DOMAINS = ["whitelli.tk", "blackelli.duckdns.org"]
engine = create_engine(f"sqlite+pysqlite:///{DB_PATH}", echo=True)
Session = sessionmaker(bind=engine)
AUTH, GUEST_MENU, PRO, PRO_MENU = map(chr, range(4))
LOGIN, GUEST = map(chr, range(4, 6))
PROTOCOL, CONF_TYPE, START = map(chr, range(6, 9))
FILE_EXT_MAPPING = {
    "vmess": {
        "android": ["npv4"],
        "ios": ["inpv"]
    },
    "vless": {
        "android": ["npv4"],
        "ios": ["inpv"]
    },
    "ssh": {
        "android": ["npv4", "ehi"],
        "ios": ["inpv"]
    }
}
auth_keyboard = [["Login", "Guest", "Clients"]]
guest_keyboard = [["Free Server", "Back"]]
pro_keyboard = [["List Servers", "Account Status", "Logout"]]
pro_servers_conf_type_keyboard = [["File (Android)", "File (IOS)", "URL", "Raw"]]
ssh_clients_keyboard = [["HTTP Injector", "HTTP Injector (Lite)", "NapsternetV"]]
v2ray_clients = [["V2RayNG", "NapsternetV"]]
auth_markup = ReplyKeyboardMarkup(keyboard=auth_keyboard, resize_keyboard=True)



async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    reply_text = (
        f"Hi {update.effective_user.first_name}! My name is {bot_name}. "
        "You can either buy a pro account by contacting @admin, and use it, "
        "or you can use our free server with a limited quota of 1gb per month."
    )
    await update.message.reply_text(reply_text, reply_markup=auth_markup)
    return AUTH


async def auth(update: Update, context: ContextTypes.DEFAULT_TYPE):
    answer = update.message.text.lower()
    match answer:
        case "login":
            reply_text = (
                f"Dear {update.effective_user.first_name}\n" "Enter your login code: "
            )
            cancel_markup = ReplyKeyboardMarkup([["Cancel"]],
                                                resize_keyboard=True)
            await update.message.reply_text(reply_text,
                                            reply_markup=cancel_markup)
            return LOGIN
        case "guest":
            reply_text = (
                "Our free tier consists of a single server and a single protocol, "
                "namely Trojan, that will have a limited share of 1 gigabytes per month.\n"
                "You can contact our sales manager @admin to buy a pro account."
            )
            await update.message.reply_text(
                reply_text,
                reply_markup=ReplyKeyboardMarkup(
                    keyboard=guest_keyboard,
                    resize_keyboard=True
                ),
            )
            return GUEST_MENU
        case "clients":
            await update.message.reply_chat_action("upload_document")
            await update.message.reply_document("/root/telbot/HTTPInjector5.9.1.apk")
            await update.message.reply_chat_action("upload_document")
            await update.message.reply_document("/root/telbot/NapsternetV53.0.0.apk")
            reply_text = (
                f"Hi {update.effective_user.first_name}! My name is {bot_name}. "
                "You can either buy a pro account by contacting @admin, and use it, "
                "or you can use our free server with a limited quota of 1gb per month."
            )
            await update.message.reply_text(reply_text, reply_markup=auth_markup)
            return START


async def login(update: Update, context: ContextTypes.DEFAULT_TYPE):
    login_code = update.message.text
    if login_code.lower() == "cancel":
        reply_text = (
            f"Hi {update.effective_user.first_name}! My name is {bot_name}. "
            "You can either buy a pro account by contacting @admin, and use it, "
            "or you can use our free server with a limited quota of 1gb per month."
        )
        await update.message.reply_text(reply_text, reply_markup=auth_markup)
        return AUTH
    results = Session().query(Users).filter(Users.login_code==login_code)
    if results.count() != 0:
        results.all().update({Users.is_authenticated: True})
        await update.message.reply_text("Congratualations! You're logged in now.")
        return PRO
    else:
        await update.message.reply_text(
            "Nice try but sorry buddy. This token is not valid."
        )
        return START


async def guest_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    username = update.effective_user.username
    match update.message.text.lower():
        case "free server":
            tr = TrojanBackend()
            vmess = VmessBackend()
            guest_qs = Session().query(Guests).filter(Guests.username==username)
            
            if guest_qs.count() == 0:
                guest = Guests(username=username, started_at=datetime.now().date())
                
                await sync_to_async(tr.create_user)(
                    username, (password := generate_password(username)), quota=10**9
                )
                await sync_to_async(vmess.new_user)(username)
                await update.message.reply_text("Creating Vmess Account...")
                await update.message.reply_chat_action("typing")
                await sleep(3)
            
            else:
                if datetime.now().date() - guest.started_at >= timedelta(days=30):
                    quota = tr.retrieve("users", "username", username)
                    await sync_to_async(tr.update_data)(
                        "users", "username", username, "quota", quota[0][3] + 10**6
                    )
                
                vmess_traffic = vmess.usage(username)["total"]
                if vmess_traffic > 10**9:
                    vmess.delete_user(username)
                        
            await update.message.reply_text(
                "Note that newly created accounts will be "
                "activated in about 30seconds."
            )
            await update.message.reply_text(
                "Copy these URLs and paste them into your client:\n"
            )
            await update.message.reply_text(
                generate_trojan_str(password)
            )
            vmess = VmessBackend()
            await update.message.reply_text(
                vmess.generate_link(username, "whiteelli.tk", 443)
            )
        case "back":
            pass
    
    return AUTH
        
        
async def pro(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Welcome to your dashboard. "
                                    "How can i help you today?",
                                    reply_markup=ReplyKeyboardMarkup(keyboard=pro_keyboard,
                                                                     resize_keyboard=True))
    return PRO_MENU
        

async def pro_menu(update: Update, context:ContextTypes.DEFAULT_TYPE):
    username = update.effective_user.username
    user = Session().query(Users).filter(Users.username==username).first()
    match update.message.text.lower():
        case "logout":
            (
                Session()
                .query(Users)
                .filter(Users.username==username)
                .update({"is_authenticated": False})
            )
            await update.message.reply_text("You are logged out now.")
            return AUTH
        case "list servers":
            services = [*(
                Session()
                .query(Offers)
                .filter(UsersOffersLink.offer_id==Offers.id,
                        UsersOffersLink.user_id==user.id)
                .values("name")
            )]
            
            keyboard_rules = []
            if "ssh" in services:
                keyboard_rules.append("SSH")
            if "trojan_v2ray" in services:
                keyboard_rules.extend(["Trojan", "VMESS", "VLESS"])
            
            reply_text = "Choose your desired protocol: "
            await update.message.reply_text(reply_text, 
                                            reply_markup=ReplyKeyboardMarkup(
                                                keyboard=[keyboard_rules],
                                                resize_keyboard=True
                                                )
                                           )
            return PROTOCOL
        
        case "account status":
            ...
            

async def protocol(update: Update, context: ContextTypes.DEFAULT_TYPE):
    conf_rules = ["URL", "Raw"]
    reply_text = ("You chose %s. Now choose the format in which "
                  "you want your configuration:")
    
    match (choice:=update.message.text).lower():
        case "ssh":
            conf_rules.remove("URL")
            conf_rules.append("File (Android)", "File (IOS)")
        case "vless" | "vmess":
            conf_rules.append("File (Android)", "File (IOS)")
            conf_rules.remove("Raw")
        
    await update.message.reply_text(reply_text % (choice,),
                                    reply_markup=ReplyKeyboardMarkup(keyboard=[conf_rules],
                                                                     resize_keyboard=True))
    update.message.pin()
    return CONF_TYPE


async def conf_type(update: Update, context: ContextTypes.DEFAULT_TYPE):
    pref_protocol = (
        (pinned:=update.message.pinned_message).text.lower()
        if pinned is not None
        else "trojan"
    )
    username = update.effective_user.username
    match update.message.text.lower():
        case "file (android)":
            # pref_map = FILE_EXT_MAPPING[pref_protocol]
            # exts = pref_map["android"]
            # files = [
            #     f"/root/telbot/configs/{domain}.{ext}"
            #     for domain, ext in product(DOMAINS, exts)
            # ]
            # for file in files:
            #     update.message.reply_document(open(file, "rb"))
            # reply_text = (
            #     "You can use the file ending with 'npv4' in 'NapsternetV', "
            #     "and the file ending in 'ehi' in 'HTTP Injector'."
            # )
            # update.message.reply_text(reply_text)
            await update.message.reply_text("Unfortunately we don't currently support "
                                            "file-based configs, but it will be added soon.")
        case "file (ios)":
            # pref_map = FILE_EXT_MAPPING[pref_protocol]
            # exts = pref_map["ios"]
            # files = [
            #     f"/root/telbot/configs/{domain}.{ext}"
            #     for domain, ext in product(DOMAINS, exts)
            # ]
            # for file in files:
            #     update.message.reply_document(open(file, "rb"))
            # reply_text = (
            #     "You can use the file ending with 'inpv' in 'NapsternetV'."
            # )
            # update.message.reply_text(reply_text)
            await update.message.reply_text("Unfortunately we don't currently support "
                                            "file-based configs, but it will be added soon.")
        case "url":
            if pref_protocol == "trojan":
                password = generate_password(username)
                tr = TrojanBackend()
                tr.create_user(
                    username=username,
                    password=password,
                )
                for domain in DOMAINS:
                    await update.message.reply_text(
                            generate_trojan_str(
                                password=password,
                                domain=domain,
                                name=f"MMS_{domain}"
                            )
                        )
            elif pref_protocol in ["vmess", "vless"]:
                result = Session().query(V2Ray).filter(V2Ray.username==username,
                                                       V2Ray.protocol==pref_protocol).first()
                await update.message.reply_text(result.link)
        case "raw":
            if pref_protocol == "trojan":
                reply_text = [
                    {
                        "host address": domain,
                        "port": 443,
                        "tls": "tls",
                        "network": "tcp",
                        "password": generate_password(username),
                        "sni": domain
                    }
                    for domain in DOMAINS
                ]
                reply_text = ", ".join([json.dumps(i) for i in reply_text])
                await update.message.reply_text(reply_text)
            elif protocol == "ssh":
                reply_text = [
                    {
                        "host address": domain,
                        "port": 22,
                        "username": username,
                        "password": generate_password(username)
                    }
                    for domain in DOMAINS
                ]
                reply_text = ", ".join([json.dumps(i) for i in reply_text])
                await update.message.reply_text(reply_text)
    return PRO
            


def main():
    Base.metadata.create_all(engine)
    print("[+] Database is up to date. Running the app...")

    application = (
        Application.builder()
        .token(token)
        .persistence(PicklePersistence("telegram_vpn_bot"))
        .build()
    )

    conv_handler = ConversationHandler(
        entry_points=[CommandHandler("start", start)],
        allow_reentry=True,
        states={
            START: [
                MessageHandler(filters.ALL, start)
            ],
            AUTH: [
                MessageHandler(filters.Regex("^(Login|Guest|Clients)$"), auth),
                MessageHandler(filters.ALL, start)
            ],
            LOGIN: [
                MessageHandler(filters.TEXT, login)
            ],
            GUEST_MENU: [
                MessageHandler(filters.Regex("^(Free Server|Back)$"), guest_menu)
            ],
            PRO: [
                MessageHandler(filters.Regex("^(List Servers|Account Status|Logout)$"),
                               pro)
            ],
            PRO_MENU: [
                MessageHandler(filters.Regex("^(SSH|Trojan|VMESS|VLESS)$"),
                               pro_menu)
            ],
            CONF_TYPE: [
                MessageHandler(filters.Regex(r"^(File \(Android\)|File \(IOS\)|URL|Raw)$"),
                               protocol)
            ],
        },
        name="telegram_bot",
        persistent=False,
        fallbacks=[MessageHandler(filters.Regex("^.*$"), start)]
    )
    application.add_handler(conv_handler)
    print("[+] The bot is all up.")
    application.run_polling()


if __name__ == "__main__":
    main()
