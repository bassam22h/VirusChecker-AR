import os
import re
import urllib.parse
import requests
import time
from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters
)
from io import BytesIO

# تهيئة المتغيرات البيئية
BOT_TOKEN = os.environ.get("BOT_TOKEN")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
WEBHOOK_URL = os.environ.get("WEBHOOK_URL")
PORT = int(os.environ.get("PORT", 10000))

# إنشاء التطبيق
application = Application.builder().token(BOT_TOKEN).build()

# ================ وظائف مساعدة ================
async def send_typing_action(update: Update):
    """إظهار مؤشر الكتابة"""
    try:
        await update.message.chat.send_action(action="typing")
    except:
        pass

def extract_url(text: str) -> str:
    """استخراج الروابط من النص"""
    try:
        # فك تشفير URL إن وجد
        decoded_text = urllib.parse.unquote(text)
        
        # إزالة المسافات من الروابط
        fixed_text = decoded_text.replace(" ", "").replace("٫", ".").replace("۔", ".")
        
        # البحث عن الروابط
        url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        match = url_pattern.search(fixed_text)
        return match.group(0) if match else None
    except:
        return None

def is_valid_file(file_name: str) -> bool:
    """التحقق من صحة الملف"""
    valid_extensions = ['.exe', '.dll', '.pdf', '.doc', '.docx', '.xls', 
                      '.xlsx', '.ppt', '.pptx', '.apk', '.jar', '.zip', 
                      '.rar', '.7z', '.msi', '.bat', '.js', '.ps1']
    return any(file_name.lower().endswith(ext) for ext in valid_extensions)

# ================ وظائف VirusTotal API ================
async def analyze_url(url: str) -> dict:
    """تحليل الرابط باستخدام VirusTotal"""
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    # إرسال الرابط للتحليل
    response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url},
        timeout=20
    )
    
    if response.status_code != 200:
        raise Exception("فشل في تحليل الرابط")
    
    analysis_id = response.json()["data"]["id"]
    
    # الانتظار قليلاً لضمان اكتمال التحليل
    time.sleep(15)
    
    # جلب النتائج
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    result = requests.get(analysis_url, headers=headers, timeout=20)
    
    if result.status_code != 200:
        raise Exception("فشل في جلب النتائج")
    
    return result.json()

async def analyze_file(file_content: bytes, file_name: str) -> dict:
    """تحليل الملف باستخدام VirusTotal"""
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
    # إرسال الملف للتحليل
    files = {"file": (file_name, file_content)}
    response = requests.post(
        "https://www.virustotal.com/api/v3/files",
        headers=headers,
        files=files,
        timeout=30
    )
    
    if response.status_code != 200:
        raise Exception("فشل في تحليل الملف")
    
    analysis_id = response.json()["data"]["id"]
    
    # الانتظار لضمان اكتمال التحليل
    time.sleep(20)
    
    # جلب النتائج
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    result = requests.get(analysis_url, headers=headers, timeout=20)
    
    if result.status_code != 200:
        raise Exception("فشل في جلب نتائج الملف")
    
    return result.json()

# ================ توليد التقارير ================
def generate_url_report(result: dict, url: str) -> str:
    """تقرير فحص الرابط"""
    stats = result["data"]["attributes"]["stats"]
    results = result["data"]["attributes"]["results"]
    
    malicious = stats["malicious"]
    suspicious = stats["suspicious"]
    harmless = stats["harmless"]
    undetected = stats["undetected"]
    
    # تحضير قائمة التهديدات
    threats = []
    for engine, data in results.items():
        if data["category"] in ["malicious", "suspicious"]:
            threats.append(f"▫️ {engine}: {data['result']} ({data['category']})")
    
    # بناء التقرير
    report = f"🔍 *نتيجة فحص الرابط*\n\n[{url}]({url})\n\n"
    report += f"🛡 *الحالة:* {'⚠️ خطير' if malicious > 0 else '✅ آمن'}\n\n"
    report += f"• 🚨 ضار: {malicious} محرك\n"
    report += f"• 🟡 مشبوه: {suspicious} محرك\n"
    report += f"• ✅ نظيف: {harmless} محرك\n"
    report += f"• ⏩ غير مفحوص: {undetected} محرك\n\n"
    
    if threats:
        report += "📌 *التهديدات المكتشفة:*\n"
        report += "\n".join(threats[:5])  # عرض أول 5 تهديدات
        if len(threats) > 5:
            report += f"\n\nو {len(threats)-5} تهديدات أخرى..."
    
    report += "\n\n📊 *نصائح أمانية:*\n"
    if malicious > 3:
        report += "▪️ لا تفتح هذا الرابط\n▪️ لا تدخل أي بيانات شخصية\n▪️ احذف الرسالة فوراً"
    elif malicious > 0:
        report += "▪️ تجنب فتح الرابط\n▪️ لا تقم بتنزيل أي ملفات\n▪️ استخدم متصفحاً آمناً"
    else:
        report += "▪️ الرابط يبدو آمناً\n▪️ كن حذراً عند إدخال بيانات حساسة"
    
    return report

def generate_file_report(result: dict, file_name: str) -> str:
    """تقرير فحص الملف"""
    stats = result["data"]["attributes"]["stats"]
    results = result["data"]["attributes"]["results"]
    
    malicious = stats["malicious"]
    suspicious = stats["suspicious"]
    
    # تحضير قائمة التهديدات
    threats = []
    for engine, data in results.items():
        if data["category"] in ["malicious", "suspicious"]:
            threats.append(f"▫️ {engine}: {data['result']} ({data['category']})")
    
    # بناء التقرير
    report = f"📁 *نتيجة فحص الملف*\n\n*{file_name}*\n\n"
    report += f"🛡 *الحالة:* {'⚠️ خطير' if malicious > 0 else '✅ آمن'}\n\n"
    report += f"• 🚨 ضار: {malicious} محرك\n"
    report += f"• 🟡 مشبوه: {suspicious} محرك\n\n"
    
    if threats:
        report += "📌 *التهديدات المكتشفة:*\n"
        report += "\n".join(threats[:5])
        if len(threats) > 5:
            report += f"\n\nو {len(threats)-5} تهديدات أخرى..."
    
    report += "\n\n📊 *نصائح أمانية:*\n"
    if malicious > 3:
        report += "▪️ لا تقم بتشغيل الملف\n▪️ احذف الملف فوراً\n▪️ افحص جهازك بمضاد فيروسات"
    elif malicious > 0:
        report += "▪️ تجنب تشغيل الملف\n▪️ استخدم بيئة معزولة\n▪️ تأكد من مصدر الملف"
    else:
        report += "▪️ الملف يبدو آمناً\n▪️ تأكد من مصدر الملف قبل التشغيل"
    
    return report

# ================ معالجة الرسائل ================
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """رسالة البدء"""
    await send_typing_action(update)
    
    welcome_msg = """
🛡 *مرحباً بك في بوت فحص الروابط والملفات*

📌 *كيفية الاستخدام:*
1. أرسل أي رابط مباشرة وسأفحصه لك
2. أو أرسل ملفاً (حتى 50MB) وسأحلله

🔍 *الملفات المدعومة:*
PDF, EXE, DOC, APK, ZIP وغيرها

⚠️ *ملاحظة:* بعض الروابط قد يتم حظرها تلقائياً من تليجرام. في هذه الحالة جرب إرسال الرابط مع مسافات بين الأحرف.
"""
    await update.message.reply_text(welcome_msg, parse_mode="Markdown")

async def process_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالجة المدخلات من المستخدم"""
    try:
        await send_typing_action(update)
        
        # إذا كان ملف
        if update.message.document:
            file = await update.message.document.get_file()
            file_content = BytesIO(await file.download_as_bytearray())
            file_name = update.message.document.file_name
            
            if not is_valid_file(file_name):
                await update.message.reply_text(
                    "⚠️ نوع الملف غير مدعوم\n"
                    "الرجاء إرسال ملف بامتداد معروف مثل pdf, exe, doc, ..."
                )
                return
            
            # إعلام المستخدم ببدء الفحص
            msg = await update.message.reply_text(f"🔍 جاري فحص الملف: {file_name}...")
            
            # تحليل الملف
            result = await analyze_file(file_content.read(), file_name)
            
            # إنشاء التقرير
            report = generate_file_report(result, file_name)
            
            # إرسال النتائج
            await msg.edit_text(report, parse_mode="Markdown")
            return
        
        # إذا كان نص (رابط محتمل)
        if update.message.text:
            url = extract_url(update.message.text)
            if url:
                # إعلام المستخدم ببدء الفحص
                msg = await update.message.reply_text(f"🔍 جاري فحص الرابط:\n{url}...")
                
                # تحليل الرابط
                result = await analyze_url(url)
                
                # إنشاء التقرير
                report = generate_url_report(result, url)
                
                # إرسال النتائج
                await msg.edit_text(report, parse_mode="Markdown")
                return
        
        # إذا لم يكن رابط ولا ملف
        await update.message.reply_text(
            "⚠️ لم أتمكن من التعرف على الرابط أو الملف\n"
            "الرجاء إرسال رابط صالح أو ملف مدعوم"
        )
        
    except Exception as e:
        print(f"Error: {str(e)}")
        await update.message.reply_text(
            "❌ حدث خطأ أثناء عملية الفحص\n"
            "الرجاء المحاولة لاحقاً أو التأكد من صحة المدخلات"
        )

# ================ تهيئة البوت ================
def main():
    """الدالة الرئيسية لتشغيل البوت"""
    # تسجيل معالجات الأوامر
    application.add_handler(CommandHandler("start", start))
    
    # معالجة الرسائل النصية
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, process_input))
    
    # معالجة الملفات
    application.add_handler(MessageHandler(filters.Document.ALL, process_input))
    
    print("✅ البوت يعمل...")
    application.run_webhook(
        listen="0.0.0.0",
        port=PORT,
        url_path=BOT_TOKEN,
        webhook_url=f"{WEBHOOK_URL}/{BOT_TOKEN}"
    )

if __name__ == '__main__':
    main()
