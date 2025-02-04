import os
import requests
from telegram import Update, Bot
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, CallbackContext
from tempfile import NamedTemporaryFile

# استبدل هذه القيم بمفاتيح API الخاصة بك
TELEGRAM_BOT_TOKEN = os.environ.get('7463590385:AAFP2PrMr48TdUPfeLb9NUPETT4mDzWstOQ')  # سيتم تعيينها في Heroku
VIRUSTOTAL_API_KEY = os.environ.get('f01e9e5ecbf63c2c32ccf03a9a0b9447e613a83d51fc67e4bbc30e0fc248b3a2')  # سيتم تعيينها في Heroku

def start(update: Update, context: CallbackContext):
    # إرسال رسالة ترحيب عند استخدام الأمر /start
    update.message.reply_text('مرحباً! أرسل لي ملفاً لأفحصه على VirusTotal.')

def handle_file(update: Update, context: CallbackContext):
    # الحصول على معلومات الملف من المستخدم (Sender)
    file = update.message.document.get_file()
    
    # تنزيل الملف إلى ملف مؤقت
    with NamedTemporaryFile(delete=False) as temp_file:
        file.download(custom_path=temp_file.name)
        file_path = temp_file.name

    # إرسال الملف إلى VirusTotal للفحص
    try:
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        params = {'apikey': VIRUSTOTAL_API_KEY}
        with open(file_path, 'rb') as file_to_scan:
            files = {'file': (os.path.basename(file_path), file_to_scan)}
            response = requests.post(url, files=files, params=params)

        if response.status_code == 200:
            scan_id = response.json()['scan_id']
            # إرسال رسالة تأكيد للمستخدم (Sender)
            update.message.reply_text(f'تم استلام الملف! جاري الفحص... (Scan ID: {scan_id})')

            # استرجاع نتائج الفحص
            report_url = 'https://www.virustotal.com/vtapi/v2/file/report'
            report_params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': scan_id}
            report_response = requests.get(report_url, params=report_params)

            if report_response.status_code == 200:
                report = report_response.json()
                if report['response_code'] == 1:
                    positives = report['positives']
                    total = report['total']
                    # إرسال النتائج للمستخدم (Sender)
                    update.message.reply_text(f'النتائج: {positives}/{total} محركات اكتشفت تهديدًا.')
                else:
                    update.message.reply_text('لم يتم العثور على نتائج.')
            else:
                update.message.reply_text('خطأ في استرجاع النتائج.')
        else:
            update.message.reply_text('خطأ في إرسال الملف إلى VirusTotal.')

    except Exception as e:
        update.message.reply_text(f'حدث خطأ: {str(e)}')

    finally:
        # حذف الملف المؤقت
        os.remove(file_path)

def main():
    updater = Updater(TELEGRAM_BOT_TOKEN, use_context=True)
    dispatcher = updater.dispatcher

    # تعريف الأوامر ومعالجة الملفات
    dispatcher.add_handler(CommandHandler("start", start))
    dispatcher.add_handler(MessageHandler(Filters.document, handle_file))

    # بدء تشغيل البوت
    updater.start_polling()
    updater.idle()

if __name__ == '__main__':
    main()
