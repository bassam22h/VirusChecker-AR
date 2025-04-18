import os
import requests
from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
    ContextTypes
)

BOT_TOKEN = os.environ.get("BOT_TOKEN")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
WEBHOOK_URL = os.environ.get("WEBHOOK_URL")

# إنشاء التطبيق
application = Application.builder().token(BOT_TOKEN).build()

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

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
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

# تشغيل البوت
def main():
    # يمكنك استخدام webhook أو polling حسب احتياجاتك
    
    # الخيار 1: استخدام webhook (مفضل لـ Render)
    application.run_webhook(
        listen="0.0.0.0",
        port=10000,
        url_path=BOT_TOKEN,
        webhook_url=f"{WEBHOOK_URL}/{BOT_TOKEN}"
    )
    
    # الخيار 2: استخدام polling (للتجربة المحلية)
    # application.run_polling()

if __name__ == '__main__':
    main()
