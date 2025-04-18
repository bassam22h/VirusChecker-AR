import os
import requests
from flask import Flask, request
from telegram import Bot, Update
from telegram.ext import Dispatcher, CommandHandler, MessageHandler, filters, CallbackContext

# إعدادات من متغيرات البيئة
BOT_TOKEN = os.getenv("BOT_TOKEN")
VIRUSTOTAL_API_KEY = os.getenv("VT_API_KEY")
WEBHOOK_URL = os.getenv("WEBHOOK_URL")

# تيليجرام بوت
bot = Bot(BOT_TOKEN)
app = Flask(__name__)

# Dispatcher
dispatcher = Dispatcher(bot=bot, update_queue=None, workers=4)

def start(update: Update, context: CallbackContext):
    welcome_message = """مرحبًا بك في **حارس الروابط**!

أنا بوت متخصص في فحص الروابط والتأكد من سلامتها باستخدام خدمة VirusTotal.

فقط أرسل أي رابط، وسأقوم بتحليله وأخبرك إن كان:
- ضارًا (قد يسرق بياناتك أو يصيب جهازك)
- مشبوهًا (نشاط مريب غير مؤكد)
- آمنًا
- أو غير معروف بعد

احمِ نفسك قبل الضغط على أي رابط!"""
    update.message.reply_text(welcome_message, parse_mode="Markdown")

def check_url(update: Update, context: CallbackContext):
    url = update.message.text
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    data = {
        "url": url
    }
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)

    if response.status_code == 200:
        analysis_id = response.json()["data"]["id"]
        result = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
        analysis = result.json()

        stats = analysis["data"]["attributes"]["stats"]
        total = stats["malicious"] + stats["suspicious"] + stats["undetected"] + stats["harmless"]

        reply = f"""**نتيجة فحص الرابط:**

- ضار: {stats['malicious']}  
(قد يحتوي على فيروسات، برمجيات تجسس، أو صفحات احتيال لسرقة بياناتك.)

- مشبوه: {stats['suspicious']}  
(نشاط غير مؤكد وقد يكون خطرًا. يُنصح بالحذر.)

- آمن: {stats['harmless']}  
(لا توجد مؤشرات تهديد.)

- غير معروف: {stats['undetected']}  
(لم يتم اكتشاف أي نشاط مريب حتى الآن.)

- المجموع الكلي: {total}
"""

        # إضافة التحذير في حال وجود تهديد
        if stats['malicious'] > 0 or stats['suspicious'] > 0:
            reply += "\n⚠️ **تحذير: هذا الرابط قد يشكل خطرًا على بياناتك وجهازك!**"

        update.message.reply_text(reply, parse_mode="Markdown")
    else:
        update.message.reply_text("حدث خطأ أثناء الفحص. الرجاء المحاولة لاحقًا.")

# Handlers
dispatcher.add_handler(CommandHandler("start", start))
dispatcher.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, check_url))

# Webhook endpoint
@app.route(f'/{BOT_TOKEN}', methods=['POST'])
def webhook():
    update = Update.de_json(request.get_json(force=True), bot)
    dispatcher.process_update(update)
    return "ok", 200

# تعيين Webhook
@app.route('/setwebhook', methods=['GET'])
def set_webhook():
    webhook_url = f"{WEBHOOK_URL}/{BOT_TOKEN}"
    success = bot.set_webhook(url=webhook_url)
    if success:
        return f"تم تعيين Webhook: {webhook_url}", 200
    else:
        return "فشل تعيين Webhook", 400

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=10000)
