import os
import threading
import customtkinter as ctk
from tkinter import filedialog, messagebox
import requests
from dotenv import load_dotenv
import hashlib
import time

class SecurityScanner:
    def __init__(self):
        # Load API key
        load_dotenv()
        self.api_key = os.getenv('VIRUSTOTAL_API_KEY')
        
        if not self.api_key:
            messagebox.showerror("خطأ", "لم يتم العثور على مفتاح API في ملف .env\n\n"
                               "1. قم بإنشاء حساب في https://www.virustotal.com\n"
                               "2. قم بتسجيل الدخول\n"
                               "3. احصل على مفتاح API من https://www.virustotal.com/gui/user/[your_username]/apikey\n"
                               "4. قم بتحديث ملف .env بمفتاح API الخاص بك")
            exit(1)
        
        # Setup session with proper headers
        self.session = requests.Session()
        self.session.headers.update({
            'x-apikey': self.api_key,
            'accept': 'application/json',
            'content-type': 'application/x-www-form-urlencoded'
        })
        
        # Base API URL
        self.api_base_url = 'https://www.virustotal.com/api/v3'
        
        # Initialize API quota
        self.api_requests_remaining = 0
        self.api_requests_limit = 0
        
        # Setup customtkinter appearance
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Setup main window
        self.window = ctk.CTk()
        self.window.title("Security Scanner - Created by Da7rkx0")
        self.window.geometry("800x700")
        
        # Create main frame with padding
        self.main_frame = ctk.CTkFrame(self.window)
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Header with creator name and GitHub link
        self.header_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.header_frame.pack(fill="x", padx=10, pady=(0, 20))
        
        self.title_label = ctk.CTkLabel(
            self.header_frame, 
            text="Security Scanner",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        self.title_label.pack(side="left")
        
        self.github_link = ctk.CTkButton(
            self.header_frame,
            text="GitHub",
            command=lambda: self.open_github(),
            font=ctk.CTkFont(size=12),
            width=70,
            height=25
        )
        self.github_link.pack(side="right", padx=(0, 10))
        
        self.creator_label = ctk.CTkLabel(
            self.header_frame,
            text="Created by Da7rkx0",
            font=ctk.CTkFont(size=12, slant="italic")
        )
        self.creator_label.pack(side="right")
        
        # URL scanning section
        self.url_frame = ctk.CTkFrame(self.main_frame)
        self.url_frame.pack(fill="x", padx=10, pady=(0, 20))
        
        self.url_label = ctk.CTkLabel(
            self.url_frame,
            text="URL to scan:",
            font=ctk.CTkFont(size=14)
        )
        self.url_label.pack(pady=(10, 5))
        
        self.url_entry = ctk.CTkEntry(
            self.url_frame,
            width=400,
            height=35,
            placeholder_text="Enter URL to scan"
        )
        self.url_entry.pack(pady=5)
        
        self.scan_url_button = ctk.CTkButton(
            self.url_frame,
            text="Scan URL",
            command=self.scan_url,
            height=35,
            font=ctk.CTkFont(size=14)
        )
        self.scan_url_button.pack(pady=(5, 10))
        
        # File scanning section
        self.file_frame = ctk.CTkFrame(self.main_frame)
        self.file_frame.pack(fill="x", padx=10, pady=(0, 20))
        
        self.file_label = ctk.CTkLabel(
            self.file_frame,
            text="File to scan:",
            font=ctk.CTkFont(size=14)
        )
        self.file_label.pack(pady=(10, 5))
        
        self.button_frame = ctk.CTkFrame(self.file_frame, fg_color="transparent")
        self.button_frame.pack(pady=5)
        
        self.choose_file_button = ctk.CTkButton(
            self.button_frame,
            text="Choose File",
            command=self.choose_file,
            height=35,
            font=ctk.CTkFont(size=14)
        )
        self.choose_file_button.pack(side="left", padx=5)
        
        self.scan_file_button = ctk.CTkButton(
            self.button_frame,
            text="Scan File",
            command=self.scan_file,
            height=35,
            font=ctk.CTkFont(size=14)
        )
        self.scan_file_button.pack(side="left", padx=5)
        
        self.selected_file_label = ctk.CTkLabel(
            self.file_frame,
            text="No file selected",
            font=ctk.CTkFont(size=12),
            wraplength=700
        )
        self.selected_file_label.pack(pady=(5, 10))
        
        # Add scan options
        self.options_frame = ctk.CTkFrame(self.file_frame)
        self.options_frame.pack(fill="x", pady=5)
        
        self.hash_only_var = ctk.BooleanVar(value=False)
        self.hash_only_checkbox = ctk.CTkCheckBox(
            self.options_frame,
            text="فحص البصمة الرقمية فقط (لا يستهلك من حد الطلبات)",
            variable=self.hash_only_var,
            font=ctk.CTkFont(size=12)
        )
        self.hash_only_checkbox.pack(pady=5)
        
        # Add quota display
        self.quota_label = ctk.CTkLabel(
            self.options_frame,
            text="",
            font=ctk.CTkFont(size=12)
        )
        self.quota_label.pack(pady=5)
        
        # Results section
        self.results_frame = ctk.CTkFrame(self.main_frame)
        self.results_frame.pack(fill="both", expand=True, padx=10, pady=(0, 20))
        
        self.results_label = ctk.CTkLabel(
            self.results_frame,
            text="Scan Results:",
            font=ctk.CTkFont(size=14)
        )
        self.results_label.pack(pady=(10, 5))
        
        self.results_text = ctk.CTkTextbox(
            self.results_frame,
            width=700,
            height=300,
            font=ctk.CTkFont(size=12)
        )
        self.results_text.pack(pady=5, padx=10, fill="both", expand=True)
        
        # Status bar
        self.status_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.status_frame.pack(fill="x", padx=10)
        
        self.status_label = ctk.CTkLabel(
            self.status_frame,
            text="جاري التحقق من مفتاح API...",
            font=ctk.CTkFont(size=12)
        )
        self.status_label.pack(pady=5)
        
        # Initialize selected file
        self.selected_file = None
        
        # Test API key after GUI is created
        try:
            test_response = self.session.get('https://www.virustotal.com/api/v3/users/current')
            
            if test_response.status_code == 401:
                messagebox.showerror("خطأ", "مفتاح API غير صالح. يرجى التحقق من مفتاح API في ملف .env")
                exit(1)
            elif test_response.status_code != 200:
                messagebox.showerror("خطأ", f"خطأ في الاتصال بـ VirusTotal. رمز الحالة: {test_response.status_code}")
                exit(1)
                
            # Get user quota
            quota = test_response.json().get('data', {}).get('attributes', {}).get('quotas', {})
            if quota:
                self.api_requests_remaining = quota.get('api_requests_daily', {}).get('remaining', 0)
                self.api_requests_limit = quota.get('api_requests_daily', {}).get('allowed', 0)
                self.update_status(f"جاهز للفحص - الطلبات المتبقية: {self.api_requests_remaining}/{self.api_requests_limit}")
                self.quota_label.configure(text=f"الحد اليومي المسموح به: {self.api_requests_limit} | الطلبات المتبقية: {self.api_requests_remaining}")
            else:
                self.update_status("جاهز للفحص")
            
        except requests.exceptions.RequestException as e:
            messagebox.showerror("خطأ", f"تعذر الاتصال بـ VirusTotal: {str(e)}")
            exit(1)
        
    def update_status(self, message):
        self.status_label.configure(text=message)
        self.window.update()
    
    def choose_file(self):
        self.selected_file = filedialog.askopenfilename()
        if self.selected_file:
            self.update_status(f"Selected file: {os.path.basename(self.selected_file)}")
            self.selected_file_label.configure(text=os.path.basename(self.selected_file))
    
    def calculate_sha256(self, file_path):
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def wait_for_analysis(self, analysis_url, max_attempts=30):
        attempt = 0
        while attempt < max_attempts:
            try:
                response = self.session.get(analysis_url)
                if response.status_code == 200:
                    result = response.json()
                    status = result.get('data', {}).get('attributes', {}).get('status')
                    
                    # Log progress
                    progress = result.get('data', {}).get('attributes', {}).get('progress', {})
                    if progress and isinstance(progress, int):
                        self.update_status(f"جاري التحليل... {progress}%")
                    
                    if status == 'completed':
                        return result
                    elif status == 'failed':
                        raise Exception("فشل التحليل من قبل VirusTotal")
                elif response.status_code == 401:
                    raise Exception("مفتاح API غير صالح")
                elif response.status_code == 404:
                    raise Exception("لم يتم العثور على نتائج التحليل")
            except requests.exceptions.RequestException as e:
                self.update_status(f"محاولة الاتصال {attempt + 1}/{max_attempts}")
            
            attempt += 1
            time.sleep(2)
        
        raise Exception("انتهت مهلة التحليل. يرجى المحاولة مرة أخرى")

    def scan_file(self):
        if not self.selected_file:
            messagebox.showwarning("تنبيه", "الرجاء اختيار ملف أولاً")
            return
        
        if not os.path.exists(self.selected_file):
            messagebox.showerror("خطأ", "الملف المحدد غير موجود")
            return
        
        hash_only = self.hash_only_var.get()
        if not hash_only and self.api_requests_remaining <= 0:
            response = messagebox.askyesno(
                "تحذير",
                "لقد تجاوزت الحد اليومي المسموح به من الطلبات.\n\n"
                "هل تريد فحص البصمة الرقمية للملف فقط؟\n"
                "(هذا لا يستهلك من حد الطلبات)"
            )
            if response:
                self.hash_only_var.set(True)
                hash_only = True
            else:
                return
        
        def scan():
            try:
                self.scan_file_button.configure(state="disabled")
                self.choose_file_button.configure(state="disabled")
                self.results_text.delete("1.0", "end")
                
                # Show file info
                file_size = os.path.getsize(self.selected_file)
                file_name = os.path.basename(self.selected_file)
                
                self.results_text.insert("end", "=== معلومات الملف ===\n")
                self.results_text.insert("end", f"اسم الملف: {file_name}\n")
                self.results_text.insert("end", f"حجم الملف: {file_size / 1024:.2f} كيلوبايت\n")
                self.results_text.insert("end", f"نوع الملف: {os.path.splitext(file_name)[1]}\n\n")
                
                # Calculate hash
                self.update_status("جاري حساب البصمة الرقمية للملف...")
                file_hash = self.calculate_sha256(self.selected_file)
                self.results_text.insert("end", f"البصمة الرقمية للملف (SHA-256):\n{file_hash}\n\n")
                
                if hash_only:
                    self.results_text.insert("end", "\nلفحص هذه البصمة الرقمية، يمكنك:\n")
                    self.results_text.insert("end", "1. نسخ البصمة الرقمية\n")
                    self.results_text.insert("end", "2. الذهاب إلى https://www.virustotal.com/gui/home/search\n")
                    self.results_text.insert("end", "3. لصق البصمة الرقمية والبحث عنها\n")
                    self.update_status("تم حساب البصمة الرقمية بنجاح")
                    return
                
                # Check file size
                if file_size > 32 * 1024 * 1024:  # 32MB limit
                    raise Exception("حجم الملف يتجاوز 32 ميجابايت. يرجى استخدام واجهة VirusTotal مباشرة لفحص الملفات الكبيرة.")
                
                # Check for previous analysis
                self.update_status("جاري البحث عن تحليلات سابقة...")
                response = self.session.get(f"{self.api_base_url}/files/{file_hash}")
                
                if response.status_code == 200:
                    self.results_text.insert("end", "✓ تم العثور على نتائج تحليل سابقة\n\n")
                    self.display_results(response.json())
                    self.update_status("اكتمل فحص الملف (من التحليلات السابقة)")
                else:
                    self.results_text.insert("end", "جاري بدء تحليل جديد...\n\n")
                    
                    # Get upload URL
                    self.update_status("جاري تجهيز عملية الرفع...")
                    url_response = self.session.get(f"{self.api_base_url}/files/upload_url")
                    
                    if url_response.status_code != 200:
                        raise Exception(f"فشل الحصول على رابط الرفع (الحالة: {url_response.status_code})")
                    
                    upload_url = url_response.json().get('data')
                    
                    # Upload file
                    self.update_status("جاري رفع الملف...")
                    self.results_text.insert("end", "جاري رفع الملف إلى VirusTotal...\n")
                    
                    with open(self.selected_file, 'rb') as file:
                        files = {'file': (file_name, file)}
                        upload_response = self.session.post(upload_url, files=files, timeout=180)
                    
                    if upload_response.status_code != 200:
                        raise Exception(f"فشل رفع الملف (الحالة: {upload_response.status_code})")
                    
                    upload_result = upload_response.json()
                    analysis_id = upload_result.get('data', {}).get('id')
                    
                    if not analysis_id:
                        raise Exception("لم يتم استلام معرف التحليل")
                    
                    # Wait for analysis
                    self.update_status("جاري انتظار نتائج التحليل...")
                    self.results_text.insert("end", "جاري تحليل الملف...\n")
                    
                    analysis_url = f"{self.api_base_url}/analyses/{analysis_id}"
                    result = self.wait_for_analysis(analysis_url, max_attempts=45)
                    
                    self.display_results(result)
                    self.update_status("اكتمل فحص الملف")
                    
                    # Update remaining quota
                    self.api_requests_remaining = max(0, self.api_requests_remaining - 1)
                    if self.api_requests_remaining == 0:
                        self.update_status("تم استنفاد جميع الطلبات المتاحة لهذا اليوم")
                    else:
                        self.update_status(f"اكتمل الفحص - الطلبات المتبقية: {self.api_requests_remaining}")
                    self.quota_label.configure(text=f"الحد اليومي المسموح به: {self.api_requests_limit} | الطلبات المتبقية: {self.api_requests_remaining}")
                
            except Exception as e:
                error_message = str(e)
                self.results_text.insert("end", f"\n❌ خطأ: {error_message}\n")
                messagebox.showerror("خطأ", f"خطأ في فحص الملف: {error_message}")
                self.update_status("فشل الفحص")
            finally:
                self.scan_file_button.configure(state="normal")
                self.choose_file_button.configure(state="normal")
        
        threading.Thread(target=scan, daemon=True).start()
    
    def scan_url(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("تنبيه", "الرجاء إدخال رابط")
            return
        
        def scan():
            self.scan_url_button.configure(state="disabled")
            self.update_status(f"جاري فحص الرابط: {url}...")
            
            try:
                # Submit URL for scanning
                data = {'url': url}
                scan_response = self.session.post(f"{self.api_base_url}/urls", data=data)
                
                if scan_response.status_code != 200:
                    raise Exception(f"فشل إرسال الرابط: {scan_response.text}")
                
                # Get the analysis ID
                analysis_id = scan_response.json()['data']['id']
                
                # Wait for analysis to complete
                self.update_status("جاري انتظار نتائج التحليل...")
                result = self.wait_for_analysis(f"{self.api_base_url}/analyses/{analysis_id}")
                
                self.display_results(result)
                self.update_status("اكتمل فحص الرابط")
                    
            except requests.exceptions.ConnectionError as e:
                error_message = f"خطأ في الاتصال: تعذر الاتصال بخوادم VirusTotal. يرجى التحقق من اتصال الإنترنت.\nتفاصيل الخطأ: {str(e)}"
                messagebox.showerror("خطأ في الاتصال", error_message)
                self.update_status("فشل الاتصال")
            except requests.exceptions.Timeout as e:
                error_message = "انتهت مهلة الطلب. استغرق الخادم وقتاً طويلاً للرد."
                messagebox.showerror("خطأ في المهلة", error_message)
                self.update_status("انتهت مهلة الطلب")
            except Exception as e:
                error_message = str(e)
                messagebox.showerror("خطأ", f"خطأ في فحص الرابط: {error_message}")
                self.update_status("فشل الفحص")
            finally:
                self.scan_url_button.configure(state="normal")
        
        threading.Thread(target=scan, daemon=True).start()
    
    def open_github(self):
        """Open GitHub profile in default browser"""
        import webbrowser
        webbrowser.open("https://github.com/Da7rkx0")
    
    def format_scan_results(self, result):
        try:
            stats = result.get('data', {}).get('attributes', {}).get('stats', {})
            results = result.get('data', {}).get('attributes', {}).get('results', {})
            
            if not stats or not results:
                return "لم يتم العثور على نتائج تحليل. يرجى المحاولة مرة أخرى."
            
            output = []
            output.append("=== نتائج الفحص ===")
            output.append(f"🔴 برامج ضارة: {stats.get('malicious', 0)}")
            output.append(f"⚠️ مشبوه: {stats.get('suspicious', 0)}")
            output.append(f"✅ آمن: {stats.get('harmless', 0)}")
            output.append(f"⚪ غير معروف: {stats.get('undetected', 0)}")
            
            # Add total engines
            total_engines = len(results)
            output.append(f"\nعدد محركات الفحص: {total_engines}")
            
            if stats.get('malicious', 0) > 0 or stats.get('suspicious', 0) > 0:
                output.append("\n⚠️ تحذير: تم اكتشاف تهديدات محتملة!")
                output.append("\n=== تفاصيل التهديدات ===")
                
                # Sort engines by category (malicious first, then suspicious)
                sorted_results = sorted(
                    [(engine, res) for engine, res in results.items() if res.get('category') in ['malicious', 'suspicious']],
                    key=lambda x: (x[1].get('category') != 'malicious', x[0])
                )
                
                for engine, res in sorted_results:
                    output.append(f"\n🔍 {engine}:")
                    output.append(f"التصنيف: {res.get('category', 'غير معروف')}")
                    if res.get('result'):
                        output.append(f"النتيجة: {res.get('result')}")
                    if res.get('method'):
                        output.append(f"طريقة الكشف: {res.get('method')}")
                    if res.get('engine_name'):
                        output.append(f"اسم المحرك: {res.get('engine_name')}")
                    if res.get('engine_version'):
                        output.append(f"إصدار المحرك: {res.get('engine_version')}")
            else:
                output.append("\n✅ لم يتم العثور على تهديدات")
                
                # Add some safe engines as examples
                output.append("\n=== بعض محركات الفحص الآمنة ===")
                safe_engines = [(engine, res) for engine, res in results.items() if res.get('category') == 'harmless'][:5]
                for engine, res in safe_engines:
                    output.append(f"\n✓ {engine}")
                    if res.get('engine_version'):
                        output.append(f"إصدار المحرك: {res.get('engine_version')}")
            
            return "\n".join(output)
        except Exception as e:
            return f"خطأ في معالجة النتائج: {str(e)}"
    
    def display_results(self, results):
        self.results_text.delete("1.0", "end")
        if isinstance(results, str):
            self.results_text.insert("end", results)
        else:
            formatted_results = self.format_scan_results(results)
            self.results_text.insert("end", formatted_results)
    
    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = SecurityScanner()
    app.run()
