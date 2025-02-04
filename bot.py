
import os
import requests
from telegram import Update
from telegram.ext import Updater, CommandStart, MessageHandler, Filters, CallbackContext

# تعديل هذه المتغيرات بناءً على بياناتك
TELEGRAM_BOT_TOKEN = "TELEGRAM_BOT_TOKEN"
VIRUSTOTAL_API_KEY = "VIRUSTOTAL_API_KEY"

# URL لAPI VirusTotal
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/files"

def start(update: Update, context: CallbackContext):
    """امر البداية"""
    update.message.reply_text("مرحبًا! يمكنك إرسال ملف ليقوم بفحصه VirusTotal.")

def analyze_file(update: Update, context: CallbackContext):
    """تحليل الملف المرسل بواسطة المستخدم"""
    # الحصول على الملف المرسل
    file = update.message.document
    if not file:
        update.message.reply_text("يرجى إرسال ملف صالح.")
        return

    # تنزيل الملف
    file_id = file.file_id
    new_file = context.bot.get_file(file_id)
    file_path = f"temp_{file_id}.tmp"
    new_file.download(file_path)

    # إرسال الملف إلى VirusTotal
    try:
        with open(file_path, "rb") as f:
            files = {"file": f}
            headers = {
                "x-apikey": VIRUSTOTAL_API_KEY
            }
            response = requests.post(VIRUSTOTAL_URL, files=files, headers=headers)
            result = response.json()

        # التحقق من النتيجة
        if response.status_code == 200 and "data" in result:
            analysis_url = result["data"]["links"]["self"]
            update.message.reply_text(f"تم إرسال الملف للفحص.\nرابط النتائج: {analysis_url}")
        else:
            update.message.reply_text("حدث خطأ أثناء فحص الملف. يرجى المحاولة لاحقًا.")
    except Exception as e:
        update.message.reply_text(f"خطأ: {str(e)}")
    finally:
        # حذف الملف المؤقت
        if os.path.exists(file_path):
            os.remove(file_path)

def main():
    """نقطة بدء البوت"""
    updater = Updater(TELEGRAM_BOT_TOKEN, use_context=True)
    dispatcher = updater.dispatcher

    # تعريف الأوامر
    dispatcher.add_handler(CommandStart(start))
    dispatcher.add_handler(MessageHandler(Filters.document, analyze_file))

    # بدء البوت
    updater.start_polling()
    updater.idle()

if __name__ == "__main__":
    main()
