import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from PIL import Image
import hashlib
import base64
import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as crypto_padding


class ComplexProtectionSystem:
    """Комплексна система захисту: AES-256 + LSB Стеганографія"""

    def __init__(self, root):
        self.root = root
        self.root.title("Комплексний захист інформації - ЛР7")
        self.root.geometry("1000x850")
        self.root.configure(bg='#f0f0f0')

        # Маркери для стеганографії (щоб точно знати де початок і кінець)
        self.START_MARKER = "###START###"
        self.END_MARKER = "###END###"

        # Дані для аналітики
        self.analytics = {
            'encrypt_time': 0,
            'stego_time': 0,
            'decrypt_time': 0,
            'extract_time': 0,
            'original_size': 0,
            'encrypted_size': 0,
            'final_size': 0,
            'total_protect_time': 0,
            'total_extract_time': 0
        }

        # Змінні для зберігання шляхів
        self.protect_image = None
        self.stego_image_path = None
        self.extract_image = None

        # Створення інтерфейсу
        self.setup_ui()

    def setup_ui(self):
        """Налаштування графічного інтерфейсу"""
        # Стилізація
        style = ttk.Style()
        style.theme_use('clam')

        # --- Заголовок ---
        header_frame = tk.Frame(self.root, bg="#2c3e50", height=80)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)

        title_label = tk.Label(header_frame,
                               text="🔐 Комплексний захист інформації",
                               font=("Segoe UI", 18, "bold"),
                               bg="#2c3e50", fg="white")
        title_label.pack(pady=(15, 5))

        subtitle = tk.Label(header_frame,
                            text="ЛР №7: AES-256 шифрування + LSB стеганографія",
                            font=("Segoe UI", 10), bg="#2c3e50", fg="#bdc3c7")
        subtitle.pack()

        # Основний контейнер
        main_frame = tk.Frame(self.root, bg='#f0f0f0')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Notebook для вкладок
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Вкладки
        self.protect_frame = ttk.Frame(self.notebook)
        self.extract_frame = ttk.Frame(self.notebook)
        self.analytics_frame = ttk.Frame(self.notebook)

        self.notebook.add(self.protect_frame, text=' 🔒 ЗАХИСТ ДАНИХ ')
        self.notebook.add(self.extract_frame, text=' 🔓 ВІДНОВЛЕННЯ ДАНИХ ')
        self.notebook.add(self.analytics_frame, text=' 📊 АНАЛІТИКА ТА ЗВІТ ')

        self.create_protect_tab()
        self.create_extract_tab()
        self.create_analytics_tab()

    def create_protect_tab(self):
        """Вкладка захисту"""
        container = tk.Frame(self.protect_frame, bg="#f0f0f0")
        container.pack(fill="both", expand=True, padx=10, pady=10)

        # 1. Персональні дані
        p_frame = tk.LabelFrame(container, text="1. Генерація ключа (Персональні дані)", font=("Arial", 10, "bold"),
                                bg="#f0f0f0")
        p_frame.pack(fill="x", pady=5, padx=5)

        tk.Label(p_frame, text="Ім'я:", bg="#f0f0f0").grid(row=0, column=0, padx=10, pady=10)
        self.protect_name = ttk.Entry(p_frame, width=20)
        self.protect_name.grid(row=0, column=1, padx=5)
        self.protect_name.insert(0, "Oleksandr")

        tk.Label(p_frame, text="Прізвище:", bg="#f0f0f0").grid(row=0, column=2, padx=10)
        self.protect_surname = ttk.Entry(p_frame, width=20)
        self.protect_surname.grid(row=0, column=3, padx=5)
        self.protect_surname.insert(0, "Novoseltsev")

        tk.Label(p_frame, text="Рік:", bg="#f0f0f0").grid(row=0, column=4, padx=10)
        self.protect_year = ttk.Entry(p_frame, width=10)
        self.protect_year.grid(row=0, column=5, padx=5)
        self.protect_year.insert(0, "2005")

        # 2. Повідомлення
        msg_frame = tk.LabelFrame(container, text="2. Секретне повідомлення", font=("Arial", 10, "bold"), bg="#f0f0f0")
        msg_frame.pack(fill="both", expand=True, pady=5, padx=5)

        self.message_text = scrolledtext.ScrolledText(msg_frame, height=5, font=("Arial", 10))
        self.message_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.message_text.insert('1.0', 'Це секретне повідомлення для Лабораторної роботи №7.')

        # 3. Зображення
        img_frame = tk.LabelFrame(container, text="3. Контейнер (Зображення)", font=("Arial", 10, "bold"), bg="#f0f0f0")
        img_frame.pack(fill="x", pady=5, padx=5)

        tk.Button(img_frame, text="📁 Обрати файл...", command=self.load_protect_image,
                  bg="#3498db", fg="white", font=("Arial", 9, "bold")).pack(side="left", padx=10, pady=10)
        self.protect_img_label = tk.Label(img_frame, text="Файл не обрано", bg="#f0f0f0", fg="#7f8c8d")
        self.protect_img_label.pack(side="left")

        # Кнопка запуску
        tk.Button(container, text="🔒 ЗАШИФРУВАТИ ТА ПРИХОВАТИ", command=self.perform_protection,
                  bg="#27ae60", fg="white", font=("Arial", 12, "bold"), height=2).pack(fill="x", pady=15, padx=5)

    def create_extract_tab(self):
        """Вкладка витягування"""
        container = tk.Frame(self.extract_frame, bg="#f0f0f0")
        container.pack(fill="both", expand=True, padx=10, pady=10)

        # 1. Ключ
        p_frame = tk.LabelFrame(container, text="1. Ключ розшифрування (Має співпадати)", font=("Arial", 10, "bold"),
                                bg="#f0f0f0")
        p_frame.pack(fill="x", pady=5, padx=5)

        tk.Label(p_frame, text="Ім'я:", bg="#f0f0f0").grid(row=0, column=0, padx=10, pady=10)
        self.extract_name = ttk.Entry(p_frame, width=20)
        self.extract_name.grid(row=0, column=1, padx=5)
        self.extract_name.insert(0, "Oleksandr")

        tk.Label(p_frame, text="Прізвище:", bg="#f0f0f0").grid(row=0, column=2, padx=10)
        self.extract_surname = ttk.Entry(p_frame, width=20)
        self.extract_surname.grid(row=0, column=3, padx=5)
        self.extract_surname.insert(0, "Novoseltsev")

        tk.Label(p_frame, text="Рік:", bg="#f0f0f0").grid(row=0, column=4, padx=10)
        self.extract_year = ttk.Entry(p_frame, width=10)
        self.extract_year.grid(row=0, column=5, padx=5)
        self.extract_year.insert(0, "2005")

        # 2. Файл
        img_frame = tk.LabelFrame(container, text="2. Стегоконтейнер (PNG)", font=("Arial", 10, "bold"), bg="#f0f0f0")
        img_frame.pack(fill="x", pady=5, padx=5)

        tk.Button(img_frame, text="📁 Обрати файл...", command=self.load_extract_image,
                  bg="#e67e22", fg="white", font=("Arial", 9, "bold")).pack(side="left", padx=10, pady=10)
        self.extract_img_label = tk.Label(img_frame, text="Файл не обрано", bg="#f0f0f0", fg="#7f8c8d")
        self.extract_img_label.pack(side="left")

        # Кнопка
        tk.Button(container, text="🔓 ВИТЯГТИ ТА РОЗШИФРУВАТИ", command=self.perform_extraction,
                  bg="#c0392b", fg="white", font=("Arial", 12, "bold"), height=2).pack(fill="x", pady=15, padx=5)

        # 3. Результат
        res_frame = tk.LabelFrame(container, text="3. Відновлене повідомлення", font=("Arial", 10, "bold"),
                                  bg="#f0f0f0")
        res_frame.pack(fill="both", expand=True, pady=5, padx=5)

        self.result_text = scrolledtext.ScrolledText(res_frame, height=8, font=("Arial", 10), state='disabled')
        self.result_text.pack(fill="both", expand=True, padx=5, pady=5)

    def create_analytics_tab(self):
        """Вкладка аналітики"""
        self.metrics_text = scrolledtext.ScrolledText(self.analytics_frame, font=("Consolas", 10), width=80, height=30)
        self.metrics_text.pack(fill="both", expand=True, padx=20, pady=20)
        self.metrics_text.insert('1.0', "Тут з'явиться звіт після виконання операцій...")
        self.metrics_text.config(state='disabled')

    # --- ЛОГІКА ПРОГРАМИ ---

    def generate_key(self, name, surname, year):
        """Генерація AES ключа (SHA-256)"""
        personal_string = f"{name}{surname}{year}"
        return hashlib.sha256(personal_string.encode()).digest()

    def encrypt_data(self, data, key):
        """Шифрування AES-256"""
        start_time = time.time()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padder = crypto_padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()

        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        result = iv + encrypted

        encrypt_time = (time.time() - start_time) * 1000
        return base64.b64encode(result).decode('utf-8'), encrypt_time

    def decrypt_data(self, encrypted_base64, key):
        """Розшифрування AES-256"""
        start_time = time.time()
        try:
            encrypted_data = base64.b64decode(encrypted_base64)
            iv = encrypted_data[:16]
            encrypted = encrypted_data[16:]

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()

            decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()

            unpadder = crypto_padding.PKCS7(128).unpadder()
            decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

            decrypt_time = (time.time() - start_time) * 1000
            return decrypted.decode('utf-8'), decrypt_time
        except Exception:
            raise ValueError("Невірний ключ або пошкоджені дані")

    def hide_in_image(self, image_path, message):
        """LSB Стеганографія"""
        start_time = time.time()
        img = Image.open(image_path).convert('RGB')

        # Додаємо маркери
        full_message = self.START_MARKER + message + self.END_MARKER
        data_bytes = full_message.encode('utf-8')

        # Конвертуємо в біти
        bits = ''.join([format(b, '08b') for b in data_bytes])

        if len(bits) > img.width * img.height * 3:
            raise ValueError("Зображення замале для цього тексту!")

        pixels = list(img.getdata())
        new_pixels = []
        bit_idx = 0

        for p in pixels:
            r, g, b = p
            channels = [r, g, b]
            for i in range(3):
                if bit_idx < len(bits):
                    # Замінюємо останній біт
                    channels[i] = (channels[i] & ~1) | int(bits[bit_idx])
                    bit_idx += 1
            new_pixels.append(tuple(channels))

        stego_img = Image.new(img.mode, img.size)
        stego_img.putdata(new_pixels)

        output_path = "stego_output.png"
        stego_img.save(output_path, "PNG")

        stego_time = (time.time() - start_time) * 1000
        final_size = os.path.getsize(output_path)

        return output_path, stego_time, final_size

    def extract_from_image(self, image_path):
        """Витягування з LSB"""
        start_time = time.time()
        img = Image.open(image_path).convert('RGB')
        pixels = list(img.getdata())

        binary_data = ""
        for p in pixels:
            for channel in p:
                binary_data += str(channel & 1)

        # Конвертуємо біти в байти
        all_bytes = bytearray()
        for i in range(0, len(binary_data), 8):
            byte_str = binary_data[i:i + 8]
            if len(byte_str) < 8: break
            all_bytes.append(int(byte_str, 2))

            # Перевіряємо чи знайшли маркер кінця (оптимізація швидкості)
            # Перевіряємо останні N байт
            try:
                current_tail = all_bytes[-len(self.END_MARKER.encode()):]
                if current_tail == self.END_MARKER.encode():
                    break
            except:
                pass

        try:
            full_text = all_bytes.decode('utf-8', errors='ignore')
        except:
            full_text = all_bytes.decode('latin-1')

        if self.START_MARKER in full_text and self.END_MARKER in full_text:
            start = full_text.find(self.START_MARKER) + len(self.START_MARKER)
            end = full_text.find(self.END_MARKER)
            extract_time = (time.time() - start_time) * 1000
            return full_text[start:end], extract_time

        raise ValueError("Стеганографічні дані не знайдено!")

    # --- ОБРОБНИКИ КНОПОК ---

    def load_protect_image(self):
        path = filedialog.askopenfilename(filetypes=[("Images", "*.jpg *.png *.jpeg")])
        if path:
            self.protect_image = path
            self.protect_img_label.config(text=os.path.basename(path), fg="#27ae60")

    def load_extract_image(self):
        path = filedialog.askopenfilename(filetypes=[("PNG Images", "*.png")])
        if path:
            self.extract_image = path
            self.extract_img_label.config(text=os.path.basename(path), fg="#e67e22")

    def perform_protection(self):
        name = self.protect_name.get()
        surname = self.protect_surname.get()
        year = self.protect_year.get()
        message = self.message_text.get('1.0', 'end-1c').strip()

        if not all([name, surname, year, message, self.protect_image]):
            messagebox.showwarning("Увага", "Заповніть всі поля!")
            return

        try:
            start_total = time.time()

            # 1. Генерація ключа
            key = self.generate_key(name, surname, year)

            # 2. Шифрування
            encrypted_b64, t_enc = self.encrypt_data(message.encode(), key)
            self.analytics['encrypt_time'] = t_enc
            self.analytics['original_size'] = len(message.encode())
            self.analytics['encrypted_size'] = len(encrypted_b64)

            # 3. Стеганографія
            out_path, t_stego, f_size = self.hide_in_image(self.protect_image, encrypted_b64)
            self.analytics['stego_time'] = t_stego
            self.analytics['final_size'] = f_size
            self.stego_image_path = out_path

            self.analytics['total_protect_time'] = (time.time() - start_total) * 1000

            self.update_analytics_display()
            messagebox.showinfo("Успіх", f"Дані збережено у {out_path}")

        except Exception as e:
            messagebox.showerror("Помилка", str(e))

    def perform_extraction(self):
        name = self.extract_name.get()
        surname = self.extract_surname.get()
        year = self.extract_year.get()

        if not all([name, surname, year, self.extract_image]):
            messagebox.showwarning("Увага", "Заповніть дані та оберіть файл!")
            return

        try:
            start_total = time.time()
            key = self.generate_key(name, surname, year)

            # 1. Витягування
            encrypted_msg, t_extr = self.extract_from_image(self.extract_image)
            self.analytics['extract_time'] = t_extr

            # 2. Розшифрування
            decrypted_msg, t_decr = self.decrypt_data(encrypted_msg, key)
            self.analytics['decrypt_time'] = t_decr

            self.analytics['total_extract_time'] = (time.time() - start_total) * 1000

            self.result_text.config(state='normal')
            self.result_text.delete('1.0', 'end')
            self.result_text.insert('1.0', decrypted_msg)
            self.result_text.config(state='disabled')

            self.update_analytics_display()
            messagebox.showinfo("Успіх", "Дані відновлено!")

        except Exception as e:
            messagebox.showerror("Помилка", str(e))

    def update_analytics_display(self):
        self.metrics_text.config(state='normal')
        self.metrics_text.delete('1.0', 'end')

        report = f"""
{'=' * 60}
             ЗВІТ ПРО ЕФЕКТИВНІСТЬ ЗАХИСТУ
{'=' * 60}

📊 МЕТРИКИ ЗАХИСТУ:
{'─' * 60}
🔒 ЕТАП 1: ШИФРУВАННЯ (AES-256)
   • Час шифрування:           {self.analytics['encrypt_time']:.2f} мс
   • Розмір оригіналу:          {self.analytics['original_size']} байт
   • Розмір шифротексту:        {self.analytics['encrypted_size']} байт

🖼️  ЕТАП 2: СТЕГАНОГРАФІЯ (LSB)
   • Час приховування:          {self.analytics['stego_time']:.2f} мс
   • Розмір стегоконтейнера:    {self.analytics['final_size'] / 1024:.2f} КБ

⏱️  ЗАГАЛЬНИЙ ЧАС ЗАХИСТУ:      {self.analytics['total_protect_time']:.2f} мс

{'─' * 60}

🔓 МЕТРИКИ ВІДНОВЛЕННЯ:
{'─' * 60}
   • Час витягування:           {self.analytics['extract_time']:.2f} мс
   • Час розшифрування:         {self.analytics['decrypt_time']:.2f} мс

⏱️  ЗАГАЛЬНИЙ ЧАС ВІДНОВЛЕННЯ:  {self.analytics['total_extract_time']:.2f} мс

{'=' * 60}
"""
        self.metrics_text.insert('1.0', report)
        self.metrics_text.config(state='disabled')

    def export_csv(self):
        try:
            with open('security_report.csv', 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Metric', 'Value'])
                for k, v in self.analytics.items():
                    writer.writerow([k, v])
            messagebox.showinfo("Export", "Report saved to security_report.csv")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def update_analytics(self):
        report = f"""
        === ЗВІТ ЕФЕКТИВНОСТІ ===

        [1] ЦІЛІСНІСТЬ ДАНИХ
        Статус: {self.analytics['integrity_status']}

        [2] ЧАСОВІ МЕТРИКИ (мс)
        Шифрування:   {self.analytics['encrypt_time']:.2f}
        Стеганографія:{self.analytics['stego_time']:.2f}
        Відновлення:  {self.analytics['total_extract_time']:.2f}

        [3] МЕТРИКИ ОБ'ЄМУ (Байт)
        Оригінал:     {self.analytics['original_size']}
        Шифротекст:   {self.analytics['encrypted_size']}
        Контейнер:    {self.analytics['final_size']}
        """
        self.metrics_text.config(state='normal')
        self.metrics_text.delete('1.0', 'end')
        self.metrics_text.insert('1.0', report)
        self.metrics_text.config(state='disabled')
def main():
    root = tk.Tk()
    app = ComplexProtectionSystem(root)
    root.mainloop()


if __name__ == "__main__":
    main()

