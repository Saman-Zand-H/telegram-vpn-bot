import random, string
from functools import wraps
from telegram import Update
from telegram.ext import ContextTypes
from codecs import encode
from logging import getLogger
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Users
    
    
def login_required(function):
    @wraps(function)
    async def wrapper(update: Update, context: ContextTypes):
        username = update.effective_user.username
        engine = create_engine("sqlite+pysqlite:////root/telbot/data.db")
        Session = sessionmaker(bind=engine)()
        user = Session.query(Users).filter(Users.username==username)
        if user.scalar():
            return await function(update, context)
        await update.message.reply_text("You must be logged in for this!")
        return chr(0)
    return wrapper


def random_str(length=7):
    return "".join(random.choices(string.ascii_letters, k=length))


def generate_password(username: str):
    digit = [str(ord(i) + 13) for i in username]
    return f"{username.lower()}{''.join(digit)}{encode(username.lower(), 'rot13')}"


def generate_trojan_str(password, domain="whiteelli.tk", port=443, name="FreeConf"):
    return (
        f"trojan://{password}@{domain}:{port}?"
        "security=tls&headerType=none&type=tcp&"
        f"sni={domain}#{name}"
    )
    

def trunc_number(number:int):
    pref_val = len(str(number)) // 3
    match pref_val:
        case 0:
            return f"{number}"
        case 1:
            return f"{number}K"
        case 2:
            return f"{number}M"
        case 3:
            return f"{number}G" 
        case 4:
            return f"{number} T"
        case _:
            return f"{number}"


logger = getLogger(__name__)
