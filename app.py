import os
import re
import requests
from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
    ContextTypes,
    CallbackContext
)

BOT_TOKEN = os.environ.get("BOT_TOKEN")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
WEBHOOK_URL = os.environ.get("WEBHOOK_URL")

# إنشاء التطبيق
application = Application.builder().token(BOT_TOKEN).build()

def extract_url(text: str) -> str:
    """استخراج الروابط من النص باستخدام تعبير منتظم"""
    url_pattern = re.compile(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    )
    match = url_pattern.search(text)
    return match.group(0) if match else None

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالجة أمر /start"""
    welcome_msg = """
🔍 *مرحبًا بك في بوت فحص الروابط المتقدم!*

يمكنني فحص أي رابط لكشف التهديدات المحتملة باستخدام قاعدة بيانات VirusTotal الشاملة.

📌 *كيفية الاستخدام:*
1. أرسل لي أي رابط مباشرة
2. انتظر حتى أحصل على نتائج الفحص
3. سأرسل لك تقريرًا مفصلًا عن حالة الرابط

⚠️ *تحذير:* لا تعتمد على البوت كليًا للأمان الرقمي، فهو أداة مساعدة فقط.
"""
    await update.message.reply_text(welcome_msg, parse_mode='Markdown')

async def analyze_url(url: str) -> dict:
    """تحليل الرابط باستخدام VirusTotal API"""
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    # Step 1: Submit URL for analysis
    submit_url = "https://www.virustotal.com/api/v3/urls"
    response = requests.post(
        submit_url,
        headers=headers,
        data={"url": url},
        timeout=10
    )
    
    if response.status_code != 200:
        raise Exception("فشل في إرسال الرابط للفحص")
    
    analysis_id = response.json()["data"]["id"]
    
    # Step 2: Get analysis results
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    result_response = requests.get(analysis_url, headers=headers, timeout=10)
    
    if result_response.status_code != 200:
        raise Exception("فشل في الحصول على نتائج الفحص")
    
    return result_response.json()

def generate_report(result_data: dict, original_url: str) -> str:
    """إنشاء تقرير مفصل عن نتائج الفحص"""
    attributes = result_data["data"]["attributes"]
    stats = attributes["stats"]
    results = attributes["results"]
    
    malicious = stats["malicious"]
    suspicious = stats["suspicious"]
    harmless = stats["harmless"]
    undetected = stats["undetected"]
    
    # تحضير قائمة بالتهديدات المكتشفة
    threats = []
    for engine, result in results.items():
        if result["category"] in ["malicious", "suspicious"]:
            threats.append(
                f"• *{engine}*: {result['result']} ({result['category']})"
            )
    
    # بناء الرسالة
    report = f"🔎 *نتيجة فحص الرابط:*\n{original_url}\n\n"
    
    if malicious > 0 or suspicious > 0:
        report += "⚠️ *تحذير!* تم اكتشاف تهديدات:\n\n"
        report += f"• 🚨 ضار: {malicious} محرك\n"
        report += f"• 🟡 مشبوه: {suspicious} محرك\n"
        report += f"• ✅ نظيف: {harmless} محرك\n"
        report += f"• ⏩ غير مفحوص: {undetected} محرك\n\n"
        
        if threats:
            report += "📌 *تفاصيل التهديدات:*\n"
            report += "\n".join(threats[:10])  # عرض أول 10 تهديدات فقط
            if len(threats) > 10:
                report += f"\n\nو {len(threats)-10} تحذيرات أخرى..."
    else:
        report += "✅ *الرابط آمن* حسب فحص VirusTotal\n\n"
        report += f"• ✅ نظيف: {harmless} محرك\n"
        report += f"• ⏩ غير مفحوص: {undetected} محرك\n"
    
    report += "\n\nℹ️ النتائج قد تتغير مع الوقت حسب تحديثات قواعد البيانات"
    return report

async def check_link(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالجة الروابط المرسلة"""
    try:
        user_input = update.message.text.strip()
        url = extract_url(user_input)
        
        if not url:
            await update.message.reply_text(
                "⚠️ لم يتم العثور على رابط صالح في رسالتك.\n"
                "الرجاء إرسال رابط يبدأ بـ http:// أو https://"
            )
            return
        
        # إعلام المستخدم بأن الفحص جاري
        processing_msg = await update.message.reply_text(
            f"🔍 جاري فحص الرابط:\n{url}\n\n"
            "قد يستغرق هذا بضع ثوانٍ..."
        )
        
        # تحليل الرابط
        result_data = await analyze_url(url)
        
        # إنشاء التقرير
        report = generate_report(result_data, url)
        
        # إرسال التقرير وحذف رسالة الانتظار
        await processing_msg.delete()
        await update.message.reply_text(report, parse_mode='Markdown')
        
    except Exception as e:
        error_msg = (
            "❌ حدث خطأ أثناء محاولة فحص الرابط.\n"
            "الرجاء المحاولة لاحقًا أو التأكد من صحة الرابط."
        )
        await update.message.reply_text(error_msg)
        print(f"Error: {str(e)}")

# إعداد معالجات الأوامر والرسائل
application.add_handler(CommandHandler("start", start))
application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, check_link))

# تشغيل البوت
def main():
    """الدالة الرئيسية لتشغيل البوت"""
    print("✅ البوت يعمل...")
    
    # استخدام webhook على Render
    application.run_webhook(
        listen="0.0.0.0",
        port=10000,
        url_path=BOT_TOKEN,
        webhook_url=f"{WEBHOOK_URL}/{BOT_TOKEN}"
    )

if __name__ == '__main__':
    main()
