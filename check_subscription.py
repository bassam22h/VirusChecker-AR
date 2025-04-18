import os
import logging
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ContextTypes,
    CallbackQueryHandler,
    MessageHandler,
    filters
)

# إعداد التسجيل
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# قراءة متغيرات البيئة
CHANNEL_USERNAME = os.environ.get("CHANNEL_USERNAME", "").strip("@")
CHANNEL_LINK = os.environ.get("CHANNEL_LINK", "")
BOT_USERNAME = os.environ.get("BOT_USERNAME", "").strip("@")

async def check_subscription(user_id: int, context: ContextTypes.DEFAULT_TYPE) -> bool:
    """التحقق من اشتراك المستخدم في القناة"""
    try:
        if not CHANNEL_USERNAME:
            logger.warning("لم يتم تعيين CHANNEL_USERNAME في متغيرات البيئة")
            return True
            
        member = await context.bot.get_chat_member(
            chat_id=f"@{CHANNEL_USERNAME}",
            user_id=user_id
        )
        return member.status in ["member", "administrator", "creator"]
    except Exception as e:
        logger.error(f"خطأ في التحقق من الاشتراك: {str(e)}")
        return False

async def send_subscription_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """إرسال رسالة طلب الاشتراك"""
    keyboard = [
        [InlineKeyboardButton("اشترك في القناة", url=CHANNEL_LINK or f"https://t.me/{CHANNEL_USERNAME}")],
        [InlineKeyboardButton("تم الاشتراك ✅", callback_data="check_subscription")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    message_text = (
        "⚠️ يرجى الاشتراك في قناتنا أولاً\n\n"
        "لتتمكن من استخدام البوت، يجب أن تكون مشتركاً في قناتنا:\n"
        f"@{CHANNEL_USERNAME}\n\n"
        "بعد الاشتراك، اضغط على زر 'تم الاشتراك' للتحقق"
    )
    
    if update.callback_query:
        await update.callback_query.edit_message_text(
            text=message_text,
            reply_markup=reply_markup
        )
    else:
        await update.message.reply_text(
            text=message_text,
            reply_markup=reply_markup
        )

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
