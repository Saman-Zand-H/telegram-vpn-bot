from telegram import Update, ReplyKeyboardMarkup, User as TelUser
from telegram.constants import ParseMode
from telegram.ext import (Application,
                          MessageHandler,
                          CommandHandler,
                          PicklePersistence,
                          filters,
                          ConversationHandler,
                          ContextTypes)
from itertools import combinations
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .models import Admins, Users, Offers
from .utils import is_admin, random_str, generate_password
from .backends import SSHBackend, TrojanBackend, VmessBackend
import os, re
from logging import getLogger

logger = getLogger(__name__)
token = os.environ.get("ADMIN_BOT_TOKEN")
bot_name = "mms admin bot".title()
DB_PATH = "/root/telbot/data.db"
engine = create_engine(f"sqlite+pysqlite:////{DB_PATH}", echo=True)
Session = sessionmaker(bind=engine)()
AUTH, HOME, NEW, DELETE, LIST = [chr(i) for i in range(5)]
NEW_USERNAME, NEW_QUOTA, NEW_DESCRIPTION, NEW_OFFERS = [chr(i) for i in range(5, 9)]


async def auth(update: Update, context: ContextTypes.DEFAULT_TYPE):
    username = update.effective_user.username
    user_qs = Session.query(Admins.username).filter(username==username)
    if user_qs.scalar():
        keyboards = [
            ["New User", "Delete User", "List Users"]
        ]
        update.message.reply_text(
            f"Hello my dear {update.effective_user.name}. "
            "What can i serve you?",
            reply_markup=ReplyKeyboardMarkup(keyboards, 
                                             resize_keyboard=True)
        )
        return HOME
    await update.message.reply_text("What the fuck are you doing here?! "
                                    "You're not supposed to be here. Yo. Bitch!")
    return AUTH
    
@is_admin
async def home(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ans = update.message.text.lower()
    match ans:
        case 'new user':
            message_txt = (
                "Ok look, you must provide me these values: \n"
                "telegram username of this user, "
                "quota of this user, "
                "an optional description for this user, "
                "and user's offers. The offers will be shown to you "
                "and you must select them."
            )
            await update.message.reply_text(message_txt)
            
            await update.message.reply_text(
                "Starting with username in the format @username: ")
            
            return NEW_USERNAME
            
        case 'delete user':
            await update.message.reply_text("Eww someone made you angry? give me the username: ")
            return DELETE
            
        case 'list users':
            return LIST
    

@is_admin
async def new_username(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ans = update.message.text.lower()
    admin = update.effective_user.username
    if not TelUser(username=ans[:1]).id:
        await update.message.reply_text("Invalid username. Please try again.")
    await update.message.reply_text("Username found! Now give us the quota in gbs: ")
    context.user_data[f"{admin}:new_username"] = ans
    return NEW_QUOTA


@is_admin
async def new_quota(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ans = int(update.message.text)
    admin = update.effective_user.username
    context.user_data[f"{admin}:new_quota"] = ans
    await update.message.reply_text("Fine! Now you can optionally provide me a description: ")
    return NEW_DESCRIPTION


@is_admin
async def new_description(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ans = update.message.text.lower()
    admin = update.effective_user.username
    context.user_data[f"{admin}:new_description"] = ans
    
    offers = Session.query(Offers.name).all()
    offers_keyboard = []
    for i in range(len(offers)):
        offers_item = []
        for j in combinations(offers, i+1):
            offers_item.append(" - ".join(j))
        offers_keyboard.append(offers_item)
    
    await update.message.reply_text("Now this is the last stage. Choose the offers for this user: ",
                                    reply_markup=ReplyKeyboardMarkup(offers_keyboard,
                                                                     resize_keyboard=True))
    return NEW_OFFERS


@is_admin
async def new_offers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    ans = update.message.text
    admin = update.effective_user.username
    context.user_data[f"{admin}:new_offers"] = ans
    await update.message.reply_text("Perfect! Now just wait...")
    return NEW
    

@is_admin
async def new_account(update: Update, context: ContextTypes.DEFAULT_TYPE):
    admin = update.effective_user.username
    username = context.user_data.pop(f"{admin}:new_username", "").lower()
    quota = context.user_data.pop(f"{admin}:new_quota", "")
    description = context.user_data.pop(f"{admin}:new_description", "")
    offers = context.user_data.pop(f"{admin}:new_offers", "").split(" - ")
    password = generate_password(username)
    
    if "ssh" in offers:
        backend = SSHBackend()
        backend.new_user(username, password)
    
    if "trojan" in " ".join(offers):
        backend = TrojanBackend()
        backend.create_user(username, password, description, quota, 2)
        
    if "v2ray" in " ".join(offers):
        backend = VmessBackend()
        backend.new_user(username)
    
    login_code = random_str()
    new_user = Users(username=username, 
                     quota=quota, 
                     description=description,
                     login_code=login_code)
    for offer in offers:
        of = Offers(name=offer)
        of.users.add(new_user)
        new_user.offers.add(of)
        Session.add(of)
    Session.add(new_user)
    Session.commit()
    
    await update.message.reply_text("User was created successfully. Here's the login code:")
    await update.message.reply_text(f"```{login_code}```",
                                    parse_mode=ParseMode.MARKDOWN)
    return AUTH
    

@is_admin
async def delete(update: Update, context: ContextTypes.DEFAULT_TYPE):
    answer = update.message.text
    if not TelUser(username=answer).id:
        await update.message.reply_text("Sorry this user doesn't exist.")
        return AUTH
    
    await update.message.reply_text("Deleting the user...")
    
    Session.query(Users).filter(Users.username==answer.lower()).delete()
    tr = TrojanBackend()
    vmess = VmessBackend()
    ssh = SSHBackend()
    
    if tr.user_exists(answer.lower()):
        tr.update_data("users", "username", answer.lower(), "quota", 1)
        
    if vmess.user_exists(answer.lower()):
        vmess.delete_user(answer.lower())
        
    if ssh.user_exists(answer.lower()):
        ssh.delete_user(answer.lower())
    
    await update.message.reply_text("Done! Going back to homepage...")
    return AUTH


@is_admin
async def list_users(update: Update, context: ContextTypes.DEFAULT_TYPE):
    qs = Session.query(Users.username, Users.login_code).all()
    await update.message.reply_text("The following is a list of all the users: ")
    for i in qs:
        await update.message.reply_chat_action("typing")
        await update.message.reply_text(f"{i.tuple()[0]}: {i.tuple()[1]}")
    await update.message.reply_text("Here you go! ")
    return AUTH
    

if __name__ == "__main__":
    application = (
        Application.builder()
        .token(token)
        .persistence(PicklePersistence("mms_admin_per"))
        .build()
    )
    
    conv_handler = ConversationHandler(
        entry_points=[MessageHandler(filters.Regex("New User|Delete User|List Users"), auth)],
        states={
            HOME: [MessageHandler(filters.Regex("New User|Delete User|List Users"), home)],
            LIST: [MessageHandler(filters.ALL, list_users)],
            NEW_USERNAME: [MessageHandler(filters.Regex(r"^(@(\d|\w)+)"), new_username)],
            NEW_QUOTA: [MessageHandler(filters.Regex(r"\d+"), new_quota)],
            NEW_OFFERS: [MessageHandler(filters.Regex(r"(\s|\d|\w)+"), new_offers)],
            NEW: [MessageHandler(filters.ALL, new_account)],
            DELETE: [MessageHandler(filters.Regex(r"^(@(\d|\w)+)"), delete)],
            NEW_DESCRIPTION: [MessageHandler(filters.ALL, new_description)],
        },
        persistent=True,
        name="mms_admin",
        fallbacks=[MessageHandler(filters.ALL, auth)]
    )
