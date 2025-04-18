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

def extract_and_clean_url(text: str) -> str:
    """
    استخراج وتنظيف الروابط من النص
    يحل مشكلة المسافات في الروابط التي تسبب نتائج غير صحيحة
    """
    try:
        # فك تشفير URL إن وجد
        decoded_text = urllib.parse.unquote(text)
        
        # إزالة جميع المسافات من النص أولاً
        no_spaces_text = decoded_text.replace(" ", "")
        
        # البحث عن الروابط
        url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )
        match = url_pattern.search(no_spaces_text)
        
        if not match:
            return None
            
        # تنظيف الرابط النهائي من أي أحرف غير صالحة
        cleaned_url = match.group(0)
        cleaned_url = cleaned_url.split(' ')[0]  # إزالة أي مسافات لاحقة
        cleaned_url = cleaned_url.split('\n')[0]  # إزالة أي أسطر جديدة
        
        return cleaned_url
    except Exception as e:
        print(f"Error extracting URL: {str(e)}")
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
    
    try:
        # إرسال الرابط للتحليل
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=25
        )
        
        if response.status_code != 200:
            print(f"VirusTotal API Error (submit): {response.status_code} - {response.text}")
            raise Exception("فشل في تحليل الرابط")
        
        analysis_id = response.json()["data"]["id"]
        
        # الانتظار لضمان اكتمال التحليل (زيادة وقت الانتظار)
        time.sleep(20)
        
        # جلب النتائج
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        result = requests.get(analysis_url, headers=headers, timeout=25)
        
        if result.status_code != 200:
            print(f"VirusTotal API Error (results): {result.status_code} - {result.text}")
            raise Exception("فشل في جلب النتائج")
        
        # التحقق من اكتمال التحليل
        if result.json()["data"]["attributes"]["status"] != "completed":
            raise Exception("التحليل لم يكتمل بعد")
        
        return result.json()
    except Exception as e:
        print(f"Analysis Error: {str(e)}")
        raise

# ================ توليد التقارير ================
def translate_threat(threat: str) -> str:
    """ترجمة أنواع التهديدات إلى العربية"""
    threat_translations = {
        "malicious": "برمجيات خبيثة",
        "phishing": "تصيد احتيالي",
        "malware": "برمجيات ضارة",
        "suspicious": "مشبوه",
        "riskware": "برمجيات خطرة",
        "trojan": "حصان طروادة",
        "adware": "برمجيات إعلانية",
        "spyware": "برمجيات تجسسية",
        "ransomware": "برمجيات فدية",
        "worm": "دودة حاسوبية",
        "virus": "فيروس"
    }
    return threat_translations.get(threat.lower(), threat)

def generate_url_report(result: dict, original_url: str) -> str:
    """تقرير فحص الرابط مع الترجمة"""
    stats = result["data"]["attributes"]["stats"]
    results = result["data"]["attributes"]["results"]
    
    malicious = stats["malicious"]
    suspicious = stats["suspicious"]
    harmless = stats["harmless"]
    undetected = stats["undetected"]
    
    # تحضير قائمة التهديدات مترجمة
    threats = []
    for engine, data in results.items():
        if data["category"] in ["malicious", "suspicious"]:
            threat_type = translate_threat(data.get("result", "unknown"))
            threats.append(f"▫️ *{engine}*: {threat_type} ({data['category']})")
    
    # بناء التقرير
    report = f"🔍 *نتيجة فحص الرابط*\n\n[{original_url}]({original_url})\n\n"
    report += f"🛡 *الحالة:* {'⚠️ خطير' if malicious > 0 else '✅ آمن'}\n\n"
    report += f"• 🚨 ضار: {malicious} محرك\n"
    report += f"• 🟡 مشبوه: {suspicious} محرك\n"
    report += f"• ✅ نظيف: {harmless} محرك\n"
    report += f"• ⏩ غير مفحوص: {undetected} محرك\n\n"
    
    if threats:
        report += "📌 *التهديدات المكتشفة:*\n"
        report += "\n".join(threats[:7])  # عرض أول 7 تهديدات
        if len(threats) > 7:
            report += f"\n\nو {len(threats)-7} تحذيرات أخرى..."
    
    report += "\n\n📊 *نصائح أمانية:*\n"
    if malicious >= 3:
        report += "▪️ هذا الرابط خطير جداً!\n"
        report += "▪️ لا تفتحه بأي حال\n"
        report += "▪️ قد يحتوي على برمجيات خبيثة أو صفحات تصيد\n"
        report += "▪️ احذف الرسالة فوراً"
    elif malicious > 0:
        report += "▪️ الرابط يحتوي على تهديدات محتملة\n"
        report += "▪️ تجنب فتحه أو إدخال أي بيانات\n"
        report += "▪️ استخدم متصفحاً آمناً إذا كنت مضطراً"
    else:
        report += "▪️ الرابط يبدو آمناً حسب الفحص الحالي\n"
        report += "▪️ مع ذلك كن حذراً عند إدخال بيانات حساسة"
    
    report += "\n\nℹ️ النتائج من VirusTotal وقد تتغير مع الوقت"
    return report

# ================ معالجة الرسائل ================
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """رسالة البدء المعدلة"""
    await send_typing_action(update)
    
    welcome_msg = """
🛡 *مرحباً بك في بوت فحص الروابط المتقدم*

📌 *كيفية الاستخدام:*
1. أرسل أي رابط مباشرة (حتى مع مسافات بين الأحرف)
2. سأفحصه وأعطيك تقريراً مفصلاً

⚠️ *لأفضل نتائج:*
- تأكد من إزالة أي مسافات قبل وبعد الرابط
- تجنب إرسال روابط مختصرة (استخدم unshorten.it لتفكيكها أولاً)
- بعض الروابط قد يتم حظرها من تليجرام

📁 يمكنك أيضاً إرسال ملفات للفحص (PDF, EXE, ZIP...) حتى 50MB
"""
    await update.message.reply_text(welcome_msg, parse_mode="Markdown", disable_web_page_preview=True)

async def process_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالجة المدخلات مع تحسينات جديدة"""
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
            
            msg = await update.message.reply_text(f"🔍 جاري فحص الملف: {file_name}...")
            result = await analyze_file(file_content.read(), file_name)
            report = generate_file_report(result, file_name)
            await msg.edit_text(report, parse_mode="Markdown")
            return
        
        # إذا كان نص (رابط محتمل)
        if update.message.text:
            original_input = update.message.text.strip()
            url = extract_and_clean_url(original_input)
            
            if not url:
                await update.message.reply_text(
                    "⚠️ لم أتمكن من تحديد رابط صالح\n"
                    "الرجاء التأكد من إرسال رابط يبدأ بـ http:// أو https://"
                )
                return
            
            # إعلام المستخدم بالرابط الذي سيتم فحصه (بعد التنظيف)
            if url != original_input.replace(" ", ""):
                await update.message.reply_text(
                    f"🔗 تم تعديل الرابط للفحص:\n{url}\n"
                    "جاري التحليل الآن..."
                )
            else:
                msg = await update.message.reply_text(f"🔍 جاري فحص الرابط:\n{url}...")
            
            # التحليل وإظهار النتائج
            result = await analyze_url(url)
            report = generate_url_report(result, url)
            
            if 'msg' in locals():
                await msg.edit_text(report, parse_mode="Markdown", disable_web_page_preview=True)
            else:
                await update.message.reply_text(report, parse_mode="Markdown", disable_web_page_preview=True)
            return
        
        await update.message.reply_text("⚠️ الرجاء إرسال رابط صالح أو ملف مدعوم")
        
    except Exception as e:
        print(f"Error in processing: {str(e)}")
        error_msg = (
            "❌ حدث خطأ أثناء الفحص\n"
            "قد يكون بسبب:\n"
            "- رابط غير صالح\n"
            "- مشكلة في اتصال API\n"
            "- محتوى غير مدعوم\n\n"
            "الرجاء المحاولة لاحقاً أو إرسال رابط/ملف آخر"
        )
        await update.message.reply_text(error_msg)

# ================ تشغيل البوت ================
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
