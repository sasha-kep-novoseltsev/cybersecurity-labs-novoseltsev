import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import hashlib
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as crypto_padding
import json
from tkinter import filedialog



class EmailEncryptor:
    def __init__(self, root):
        self.root = root
        self.root.title("Email-шифратор - Захищена комунікація")
        self.root.geometry("800x750")
        self.root.configure(bg='#f0f0f0')

        # Стиль
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Title.TLabel', font=('Arial', 14, 'bold'))
        style.configure('Subtitle.TLabel', font=('Arial', 11, 'bold'))
        style.configure('Action.TButton', font=('Arial', 10, 'bold'))

        # Створення вкладок
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)

        # Вкладка відправлення
        self.send_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.send_frame, text='📤 Відправити')

        # Вкладка отримання
        self.receive_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.receive_frame, text='📥 Отримати')

        # Вкладка довідки
        self.help_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.help_frame, text='❓ Довідка')

        self.setup_send_tab()
        self.setup_receive_tab()
        self.setup_help_tab()

    def generate_key_from_personal_data(self, name, surname, year):
        """Генерація ключа на основі персональних даних"""
        personal_string = f"{name}{surname}{year}"
        key = hashlib.sha256(personal_string.encode()).digest()
        return key

    def encrypt_message(self, message, key):
        """Шифрування повідомлення з використанням AES-256"""
        try:
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()

            padder = crypto_padding.PKCS7(128).padder()
            padded_data = padder.update(message.encode('utf-8')) + padder.finalize()

            encrypted = encryptor.update(padded_data) + encryptor.finalize()
            result = iv + encrypted

            return base64.b64encode(result).decode('utf-8')
        except Exception as e:
            raise Exception(f"Помилка шифрування: {str(e)}")

    def decrypt_message(self, encrypted_message, key):
        """Розшифрування повідомлення"""
        try:
            encrypted_data = base64.b64decode(encrypted_message)
            iv = encrypted_data[:16]
            encrypted = encrypted_data[16:]

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()

            decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()

            unpadder = crypto_padding.PKCS7(128).unpadder()
            decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

            return decrypted.decode('utf-8')
        except Exception as e:
            raise Exception(f"Помилка розшифрування: {str(e)}")

    def encrypt_file(self, file_path, key):
        """Шифрування файлу"""
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()

            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()

            padder = crypto_padding.PKCS7(128).padder()
            padded_data = padder.update(file_data) + padder.finalize()

            encrypted = encryptor.update(padded_data) + encryptor.finalize()
            result = iv + encrypted

            return base64.b64encode(result).decode('utf-8')
        except Exception as e:
            raise Exception(f"Помилка шифрування файлу: {str(e)}")

    def decrypt_file(self, encrypted_data, key, save_path):
        """Розшифрування файлу"""
        try:
            encrypted_bytes = base64.b64decode(encrypted_data)
            iv = encrypted_bytes[:16]
            encrypted = encrypted_bytes[16:]

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()

            decrypted_padded = decryptor.update(encrypted) + decryptor.finalize()

            unpadder = crypto_padding.PKCS7(128).unpadder()
            decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()

            with open(save_path, 'wb') as f:
                f.write(decrypted)

            return True
        except Exception as e:
            raise Exception(f"Помилка розшифрування файлу: {str(e)}")

    def setup_send_tab(self):
        """Налаштування вкладки відправлення"""
        main_frame = ttk.Frame(self.send_frame, padding="15")
        main_frame.pack(fill='both', expand=True)

        # Заголовок
        ttk.Label(main_frame, text="📤 ВІДПРАВЛЕННЯ ЗАШИФРОВАНОГО ПОВІДОМЛЕННЯ",
                  style='Title.TLabel').pack(pady=(0, 20))

        # Секція відправника
        sender_frame = ttk.LabelFrame(main_frame, text="👤 Ваші дані (відправник)", padding="10")
        sender_frame.pack(fill='x', pady=(0, 15))

        ttk.Label(sender_frame, text="Email:").grid(row=0, column=0, sticky='w', pady=5, padx=5)
        self.send_email = ttk.Entry(sender_frame, width=50)
        self.send_email.grid(row=0, column=1, pady=5, padx=5)
        self.send_email.insert(0, "ivan.petrenko@gmail.com")

        ttk.Label(sender_frame, text="Ім'я:").grid(row=1, column=0, sticky='w', pady=5, padx=5)
        self.send_name = ttk.Entry(sender_frame, width=50)
        self.send_name.grid(row=1, column=1, pady=5, padx=5)
        self.send_name.insert(0, "Ivan")

        ttk.Label(sender_frame, text="Прізвище:").grid(row=2, column=0, sticky='w', pady=5, padx=5)
        self.send_surname = ttk.Entry(sender_frame, width=50)
        self.send_surname.grid(row=2, column=1, pady=5, padx=5)
        self.send_surname.insert(0, "Petrenko")

        ttk.Label(sender_frame, text="Рік народження:").grid(row=3, column=0, sticky='w', pady=5, padx=5)
        self.send_year = ttk.Entry(sender_frame, width=50)
        self.send_year.grid(row=3, column=1, pady=5, padx=5)
        self.send_year.insert(0, "1995")

        # Секція повідомлення
        message_frame = ttk.LabelFrame(main_frame, text="✉️ Ваше повідомлення", padding="10")
        message_frame.pack(fill='both', expand=True, pady=(0, 15))

        self.send_message_text = scrolledtext.ScrolledText(message_frame, width=70, height=8, wrap=tk.WORD)
        self.send_message_text.pack(fill='both', expand=True, pady=5)
        self.send_message_text.insert('1.0', "Зустрічаємося завтра о 15:00 біля центрального входу.")

        # Файл
        file_frame = ttk.Frame(message_frame)
        file_frame.pack(fill='x', pady=5)
        ttk.Label(file_frame, text="📎 Прикріпити файл (опціонально):").pack(side='left', padx=5)
        ttk.Button(file_frame, text="Обрати файл", command=self.select_send_file).pack(side='left', padx=5)
        self.send_file_label = ttk.Label(file_frame, text="Файл не обрано", foreground='gray')
        self.send_file_label.pack(side='left', padx=5)

        # Кнопка шифрування
        ttk.Button(main_frame, text="🔒 ЗАШИФРУВАТИ ТА СКОПІЮВАТИ",
                   style='Action.TButton', command=self.perform_send).pack(pady=15)

        # Зашифроване повідомлення
        output_frame = ttk.LabelFrame(main_frame, text="🔐 Зашифровані дані (для надсилання)", padding="10")
        output_frame.pack(fill='both', expand=True)

        # Текстове поле з можливістю виділення
        self.send_output = tk.Text(output_frame, width=70, height=10, wrap=tk.WORD,
                                   bg='#f9f9f9', relief=tk.SOLID, borderwidth=1)
        self.send_output.pack(fill='both', expand=True, pady=5)

        # Додаємо плейсхолдер
        self.send_output.insert('1.0', 'Тут з\'явиться зашифроване повідомлення...')
        self.send_output.config(fg='gray')

        btn_frame = ttk.Frame(output_frame)
        btn_frame.pack(pady=5)
        ttk.Button(btn_frame, text="📋 Копіювати в буфер", command=self.copy_send_output).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="➡️ Відкрити в \"Отримати\"", command=self.move_to_receive).pack(side='left', padx=5)

        self.send_file_path = None

    def setup_receive_tab(self):
        """Налаштування вкладки отримання"""
        main_frame = ttk.Frame(self.receive_frame, padding="15")
        main_frame.pack(fill='both', expand=True)

        # Заголовок
        ttk.Label(main_frame, text="📥 ОТРИМАННЯ ЗАШИФРОВАНОГО ПОВІДОМЛЕННЯ",
                  style='Title.TLabel').pack(pady=(0, 20))

        # Секція отримувача
        receiver_frame = ttk.LabelFrame(main_frame, text="👤 Ваші дані (отримувач)", padding="10")
        receiver_frame.pack(fill='x', pady=(0, 15))

        ttk.Label(receiver_frame, text="Ім'я:").grid(row=0, column=0, sticky='w', pady=5, padx=5)
        self.receive_name = ttk.Entry(receiver_frame, width=50)
        self.receive_name.grid(row=0, column=1, pady=5, padx=5)
        self.receive_name.insert(0, "Ivan")

        ttk.Label(receiver_frame, text="Прізвище:").grid(row=1, column=0, sticky='w', pady=5, padx=5)
        self.receive_surname = ttk.Entry(receiver_frame, width=50)
        self.receive_surname.grid(row=1, column=1, pady=5, padx=5)
        self.receive_surname.insert(0, "Petrenko")

        ttk.Label(receiver_frame, text="Рік народження:").grid(row=2, column=0, sticky='w', pady=5, padx=5)
        self.receive_year = ttk.Entry(receiver_frame, width=50)
        self.receive_year.grid(row=2, column=1, pady=5, padx=5)
        self.receive_year.insert(0, "1995")

        # Секція зашифрованих даних
        input_frame = ttk.LabelFrame(main_frame, text="🔐 Вставте зашифровані дані", padding="10")
        input_frame.pack(fill='both', expand=True, pady=(0, 15))

        self.receive_input = scrolledtext.ScrolledText(input_frame, width=70, height=8, wrap=tk.WORD)
        self.receive_input.pack(fill='both', expand=True, pady=5)

        ttk.Button(input_frame, text="📋 Вставити з буфера",
                   command=self.paste_from_clipboard).pack(pady=5)

        # Кнопка розшифрування
        ttk.Button(main_frame, text="🔓 РОЗШИФРУВАТИ",
                   style='Action.TButton', command=self.perform_receive).pack(pady=15)

        # Розшифроване повідомлення
        output_frame = ttk.LabelFrame(main_frame, text="✉️ Розшифроване повідомлення", padding="10")
        output_frame.pack(fill='both', expand=True)

        self.receive_output = scrolledtext.ScrolledText(output_frame, width=70, height=8, wrap=tk.WORD,
                                                        bg='#f0fff0')
        self.receive_output.pack(fill='both', expand=True, pady=5)

    def setup_help_tab(self):
        """Налаштування вкладки довідки"""
        main_frame = ttk.Frame(self.help_frame, padding="20")
        main_frame.pack(fill='both', expand=True)

        ttk.Label(main_frame, text="❓ ЯК КОРИСТУВАТИСЯ ПРОГРАМОЮ",
                  style='Title.TLabel').pack(pady=(0, 20))

        # Створюємо фрейм для тексту і скролу
        text_frame = ttk.Frame(main_frame)
        text_frame.pack(fill='both', expand=True)

        # Текст довідки
        help_text = """
    📤 ВІДПРАВЛЕННЯ ПОВІДОМЛЕННЯ:

    1. Перейдіть на вкладку "📤 Відправити"
    2. Заповніть свої дані (ім'я, прізвище, рік народження)
    3. Напишіть повідомлення
    4. За бажанням прикріпіть файл
    5. Натисніть "🔒 ЗАШИФРУВАТИ ТА СКОПІЮВАТИ"
    6. Зашифровані дані автоматично скопіюються в буфер обміну
    7. Відправте їх отримувачу (через email, месенджер тощо)

    ⚠️ ВАЖЛИВО: Перед відправкою повідомте отримувачу ваші персональні дані 
    (ім'я, прізвище, рік) іншим безпечним каналом (телефон, особиста зустріч)!


    📥 ОТРИМАННЯ ПОВІДОМЛЕННЯ:

    1. Перейдіть на вкладку "📥 Отримати"
    2. Введіть персональні дані ВІДПРАВНИКА (ті, що він вам повідомив)
    3. Вставте зашифровані дані у відповідне поле
    4. Натисніть "🔓 РОЗШИФРУВАТИ"
    5. Прочитайте повідомлення та збережіть файл (якщо він є)


    🔑 ПРИНЦИП РОБОТИ:

    Програма використовує симетричне шифрування AES-256:
    • Ключ генерується з персональних даних (Ім'я + Прізвище + Рік)
    • Відправник шифрує повідомлення своїм ключем
    • Отримувач розшифровує тим самим ключем (тому потрібні ті самі дані)
    • Якщо дані не співпадають - розшифрування неможливе!


    💡 ПОРАДИ:

    ✓ Зберігайте персональні дані співрозмовників у безпечному місці
    ✓ Використовуйте складні комбінації (не тільки справжні дані)
    ✓ Домовляйтеся про персональні дані особисто або по телефону
    ✓ Не передавайте персональні дані тим самим каналом, що й повідомлення
    ✓ Кожен раз можна використовувати різні персональні дані для різних людей


    ⚠️ БЕЗПЕКА:

    • Програма використовує криптографічно стійкий алгоритм AES-256
    • Без знання точних персональних даних розшифрування неможливе
    • Навіть одна літера або цифра відмінності зроблять розшифрування неможливим
        """

        # Створюємо текстове поле з прокруткою
        text_widget = tk.Text(text_frame, wrap="word", font=('Arial', 10), bg="#f0f0f0")
        text_widget.insert("1.0", help_text)
        text_widget.config(state="disabled")  # Забороняємо редагування
        text_widget.pack(side="left", fill="both", expand=True)

        # Додаємо вертикальний скролбар
        scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=text_widget.yview)
        scrollbar.pack(side="right", fill="y")
        text_widget.config(yscrollcommand=scrollbar.set)

    def select_send_file(self):
        """Вибір файлу для шифрування"""
        file_path = filedialog.askopenfilename(title="Оберіть файл")
        if file_path:
            self.send_file_path = file_path
            file_name = os.path.basename(file_path)
            self.send_file_label.config(text=f"✓ {file_name}", foreground='green')

    def perform_send(self):
        """Виконання шифрування та копіювання"""
        name = self.send_name.get().strip()
        surname = self.send_surname.get().strip()
        year = self.send_year.get().strip()
        message = self.send_message_text.get('1.0', 'end-1c').strip()

        if not all([name, surname, year]):
            messagebox.showwarning("Попередження", "Заповніть всі персональні дані!")
            return

        if not message and not self.send_file_path:
            messagebox.showwarning("Попередження", "Введіть повідомлення або оберіть файл!")
            return

        try:
            # Генерація ключа
            key = self.generate_key_from_personal_data(name, surname, year)

            # Підготовка даних
            result = {
                "email": self.send_email.get(),
                "sender": f"{name} {surname}",
                "message": None,
                "file": None,
                "file_name": None
            }

            # Шифрування повідомлення
            if message:
                encrypted_message = self.encrypt_message(message, key)
                result["message"] = encrypted_message

            # Шифрування файлу
            if self.send_file_path:
                encrypted_file = self.encrypt_file(self.send_file_path, key)
                result["file"] = encrypted_file
                result["file_name"] = os.path.basename(self.send_file_path)

            # Формування JSON
            result_json = json.dumps(result, ensure_ascii=False, indent=2)

            # Відображення результату
            self.send_output.config(state=tk.NORMAL, fg='black')
            self.send_output.delete('1.0', 'end')
            self.send_output.insert('1.0', result_json)

            # Копіювання в буфер обміну
            self.root.clipboard_clear()
            self.root.clipboard_append(result_json)

            messagebox.showinfo("Успіх",
                                "✓ Повідомлення зашифровано!\n"
                                "✓ Дані скопійовано в буфер обміну!\n\n"
                                "Тепер відправте їх отримувачу.\n"
                                "Не забудьте повідомити йому ваші персональні дані!")

        except Exception as e:
            messagebox.showerror("Помилка", f"Помилка шифрування: {str(e)}")

    def perform_receive(self):
        """Виконання розшифрування"""
        name = self.receive_name.get().strip()
        surname = self.receive_surname.get().strip()
        year = self.receive_year.get().strip()
        encrypted_data = self.receive_input.get('1.0', 'end-1c').strip()

        if not all([name, surname, year]):
            messagebox.showwarning("Попередження", "Заповніть персональні дані відправника!")
            return

        if not encrypted_data:
            messagebox.showwarning("Попередження", "Вставте зашифровані дані!")
            return

        try:
            # Генерація ключа
            key = self.generate_key_from_personal_data(name, surname, year)

            # Парсинг JSON
            data = json.loads(encrypted_data)

            result_text = f"📧 Від: {data.get('email', 'Невідомо')}\n"
            result_text += f"👤 Відправник: {data.get('sender', 'Невідомо')}\n"
            result_text += "─" * 60 + "\n\n"

            # Розшифрування повідомлення
            if data.get('message'):
                decrypted_message = self.decrypt_message(data['message'], key)
                result_text += f"📝 Повідомлення:\n{decrypted_message}\n\n"

            # Розшифрування файлу
            if data.get('file'):
                file_name = data.get('file_name', 'file')
                # Визначаємо розширення з початкового імені файлу (якщо є)
                _, ext = os.path.splitext(file_name)
                # Якщо розширення порожнє — підставляємо .txt за замовчуванням
                def_ext = ext if ext else ".txt"

                save_path = filedialog.asksaveasfilename(
                    defaultextension=def_ext,
                    initialfile=file_name,
                    title="Зберегти розшифрований файл",
                    filetypes=[("Відповідний тип", f"*{def_ext}"), ("Усі файли", "*.*")]
                )
                if save_path:
                    self.decrypt_file(data['file'], key, save_path)
                    result_text += f"📎 Файл збережено: {os.path.basename(save_path)}"

            # Відображення результату
            self.receive_output.delete('1.0', 'end')
            self.receive_output.insert('1.0', result_text)

            messagebox.showinfo("Успіх", "✓ Повідомлення успішно розшифровано!")

        except json.JSONDecodeError:
            messagebox.showerror("Помилка",
                                 "Неправильний формат даних!\n"
                                 "Переконайтеся, що ви скопіювали ВСІ зашифровані дані.")
        except Exception as e:
            messagebox.showerror("Помилка",
                                 f"Помилка розшифрування!\n\n{str(e)}\n\n"
                                 "Можливі причини:\n"
                                 "• Неправильні персональні дані відправника\n"
                                 "• Пошкоджені зашифровані дані\n"
                                 "• Невідповідність ключа")

    def copy_send_output(self):
        """Копіювання зашифрованих даних"""
        text = self.send_output.get('1.0', 'end-1c').strip()
        if text and text != 'Тут з\'явиться зашифроване повідомлення...':
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            messagebox.showinfo("Успіх", "✓ Зашифровані дані скопійовано в буфер обміну!")
        else:
            messagebox.showwarning("Попередження", "Немає даних для копіювання!")

    def move_to_receive(self):
        """Переміщення даних у вкладку отримання"""
        text = self.send_output.get('1.0', 'end-1c').strip()
        if text and text != 'Тут з\'явиться зашифроване повідомлення...':
            self.receive_input.delete('1.0', 'end')
            self.receive_input.insert('1.0', text)
            self.notebook.select(self.receive_frame)
            messagebox.showinfo("Успіх", "✓ Дані перенесено у вкладку \"Отримати\"!")
        else:
            messagebox.showwarning("Попередження", "Немає даних для переміщення!")

    def paste_from_clipboard(self):
        """Вставити дані з буфера обміну"""
        try:
            clipboard_text = self.root.clipboard_get()
            self.receive_input.delete('1.0', 'end')
            self.receive_input.insert('1.0', clipboard_text)
            messagebox.showinfo("Успіх", "✓ Дані вставлено з буфера обміну!")
        except tk.TclError:
            messagebox.showwarning("Попередження", "Буфер обміну порожній!")


if __name__ == "__main__":
    root = tk.Tk()
    app = EmailEncryptor(root)
    root.mainloop()