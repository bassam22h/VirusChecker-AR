import os
import requests
import asyncio
from flask import Flask, request
from telegram import Update, Bot
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# اقرأ المتغيرات من بيئة Render
BOT_TOKEN = os.environ.get("BOT_TOKEN")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
WEBHOOK_URL = os.environ.get("WEBHOOK_URL")

# إعداد البوت
application = Application.builder().token(BOT_TOKEN).build()
bot = Bot(BOT_TOKEN)

# نص ترحيبي
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "مرحبًا بك في بوت فحص الروابط الضارة!\n\n"
        "أرسل لي أي رابط، وسأفحصه لك عبر VirusTotal وأعطيك النتيجة."
    )

# فحص الرابط
async def check_link(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = update.message.text.strip()
    if not url.startswith("http"):
        await update.message.reply_text("من فضلك أرسل رابطًا صحيحًا يبدأ بـ https:// أو http://")
        return

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    params = {'url': url}

    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=params)

    if response.status_code != 200:
        await update.message.reply_text("حدث خطأ أثناء إرسال الرابط للتحليل. حاول لاحقًا.")
        return

    analysis_id = response.json()["data"]["id"]

    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    result_response = requests.get(analysis_url, headers=headers)

    if result_response.status_code != 200:
        await update.message.reply_text("تعذر جلب نتيجة الفحص. حاول لاحقًا.")
        return

    result_data = result_response.json()
    stats = result_data["data"]["attributes"]["stats"]
    malicious = stats["malicious"]

    if malicious > 0:
        await update.message.reply_text(
            f"تم فحص الرابط:\n{url}\n\n"
            f"نتيجة الفحص:\n"
            f"- خطير: {malicious} جهة حددته كمضر.\n\n"
            "**تحذير:** هذا الرابط قد يؤدي إلى برامج ضارة، فيروسات، أو محاولات تصيّد. لا تقم بفتحه."
        )
    else:
        await update.message.reply_text(
            f"تم فحص الرابط:\n{url}\n\n"
            "الرابط آمن حاليًا وفقًا لفحص VirusTotal."
        )

# إعداد الأوامر والمستمع
application.add_handler(CommandHandler("start", start))
application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, check_link))

# تهيئة Webhook بشكل Async
async def setup_webhook():
    await bot.set_webhook(url=f"{WEBHOOK_URL}/{BOT_TOKEN}")
    print(f"تم تعيين Webhook بنجاح: {WEBHOOK_URL}/{BOT_TOKEN}")

# تشغيل البوت مع Webhook
if __name__ == '__main__':
    asyncio.run(setup_webhook())
    application.run_webhook(
        listen="0.0.0.0",
        port=10000,
        webhook_url=f"{WEBHOOK_URL}/{BOT_TOKEN}"
    )
