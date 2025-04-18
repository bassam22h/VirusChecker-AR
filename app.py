import os
import requests
from telegram import Update, Bot
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

import asyncio

BOT_TOKEN = os.environ.get("BOT_TOKEN")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
WEBHOOK_URL = os.environ.get("WEBHOOK_URL")

application = Application.builder().token(BOT_TOKEN).build()
bot = Bot(BOT_TOKEN)

# أمر /start
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "مرحبًا بك في بوت فحص الروابط!\n\n"
        "أرسل لي أي رابط الآن، وسأفحصه لك باستخدام VirusTotal."
    )

# أمر فحص الروابط
async def check_link(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = update.message.text.strip()
    if not url.startswith("http"):
        await update.message.reply_text("أرسل رابطًا يبدأ بـ http أو https.")
        return

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    params = {'url': url}

    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=params)

    if response.status_code != 200:
        await update.message.reply_text("حدث خطأ أثناء الفحص. حاول لاحقًا.")
        return

    analysis_id = response.json()["data"]["id"]

    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    result_response = requests.get(analysis_url, headers=headers)

    if result_response.status_code != 200:
        await update.message.reply_text("تعذر جلب النتيجة. حاول لاحقًا.")
        return

    result_data = result_response.json()
    stats = result_data["data"]["attributes"]["stats"]
    malicious = stats["malicious"]

    if malicious > 0:
        await update.message.reply_text(
            f"تم فحص الرابط:\n{url}\n\n"
            f"عدد التحذيرات: {malicious}\n"
            "**تحذير:** قد يكون هذا الرابط خطيرًا أو يحتوي على برمجيات خبيثة."
        )
    else:
        await update.message.reply_text(
            f"تم فحص الرابط:\n{url}\n\n"
            "لا توجد تحذيرات حاليًا — الرابط آمن حسب VirusTotal."
        )

# إعداد الهاندلرز
application.add_handler(CommandHandler("start", start))
application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, check_link))

# Main function
async def main():
    await bot.set_webhook(url=f"{WEBHOOK_URL}/{BOT_TOKEN}")
    print(f"تم تعيين Webhook بنجاح: {WEBHOOK_URL}/{BOT_TOKEN}")
    await application.start()
    await application.updater.start_webhook(
        listen="0.0.0.0",
        port=10000,
        url_path=BOT_TOKEN
    )
    await application.updater.idle()

# تشغيل البوت
if __name__ == '__main__':
    asyncio.run(main())
