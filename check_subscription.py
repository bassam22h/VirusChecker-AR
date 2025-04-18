import os
import logging
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes, CallbackQueryHandler

# إعداد التسجيل
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# قراءة متغيرات البيئة (تدعم قنوات متعددة مفصولة بفواصل)
CHANNELS_USERNAMES = [username.strip("@") for username in os.environ.get("CHANNELS_USERNAMES", "").split(",") if username.strip()]
CHANNELS_LINKS = [link.strip() for link in os.environ.get("CHANNELS_LINKS", "").split(",") if link.strip()]
BOT_USERNAME = os.environ.get("BOT_USERNAME", "").strip("@")

async def check_subscription(user_id: int, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """التحقق من اشتراك المستخدم في جميع القنوات المطلوبة"""
    if not CHANNELS_USERNAMES:
        logger.warning("لم يتم تعيين CHANNELS_USERNAMES في متغيرات البيئة")
        return True
    
    for channel in CHANNELS_USERNAMES:
        try:
            member = await context.bot.get_chat_member(chat_id=f"@{channel}", user_id=user_id)
            if member.status not in ["member", "administrator", "creator"]:
                return False
        except Exception as e:
            logger.error(f"خطأ في التحقق من القناة @{channel}: {str(e)}")
            return False
    return True

async def send_subscription_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """إرسال رسالة طلب الاشتراك في القنوات"""
    buttons = []
    
    # أزرار الاشتراك لكل قناة
    for i, (username, link) in enumerate(zip(CHANNELS_USERNAMES, CHANNELS_LINKS), start=1):
        channel_link = link or f"https://t.me/{username}"
        buttons.append([InlineKeyboardButton(f"القناة {i}: @{username}", url=channel_link)])
    
    # زر التحقق
    buttons.append([InlineKeyboardButton("تم الاشتراك في كل القنوات ✅", callback_data="check_subscription")])
    
    reply_markup = InlineKeyboardMarkup(buttons)
    
    message_text = (
        "⚠️ يرجى الاشتراك في كل القنوات التالية:\n\n" +
        "\n".join(f"- @{username}" for username in CHANNELS_USERNAMES) +
        "\n\nبعد الاشتراك في كل القنوات، اضغط على زر 'تم الاشتراك'"
    )
    
    if update.callback_query:
        await update.callback_query.edit_message_text(text=message_text, reply_markup=reply_markup)
    else:
        await update.message.reply_text(text=message_text, reply_markup=reply_markup)

async def subscription_check_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالجة ضغط زر التحقق من الاشتراك"""
    query = update.callback_query
    await query.answer()
    
    if await check_subscription(query.from_user.id, context):
        await query.edit_message_text("شكراً لاشتراكك! يمكنك الآن استخدام البوت 🎉")
        return True
    else:
        await send_subscription_message(update, context)
        return False

async def check_subscription_middleware(update: Update, context: ContextTypes.DEFAULT_TYPE, next_handler):
    """وسيط للتحقق من الاشتراك قبل تنفيذ أي أمر"""
    # استثناء الأوامر التي لا تتطلب اشتراكاً
    if update.effective_message and update.effective_message.text in ['/start', '/help']:
        return await next_handler(update, context)
    
    # التحقق من الاشتراك
    if not await check_subscription(update.effective_user.id, context):
        await send_subscription_message(update, context)
        return
    
    return await next_handler(update, context)

def setup_subscription_handlers(application):
    """إعداد معالجات الاشتراك"""
    application.add_handler(CallbackQueryHandler(
        subscription_check_handler,
        pattern="^check_subscription$"
    ))
