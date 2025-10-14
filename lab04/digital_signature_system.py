import hashlib
import os
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog


class DigitalSignatureSystem:
    """Спрощена система цифрових підписів"""

    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.modulus = 1000007

    def generate_keys(self, name, birth_date, secret_word):
        """Генерація пари ключів на основі персональних даних"""
        personal_data = name + birth_date + secret_word
        private_key_hash = hashlib.sha256(personal_data.encode()).hexdigest()

        self.private_key = int(private_key_hash, 16) % (10 ** 15)
        self.public_key = (self.private_key * 7) % self.modulus

        self._save_keys(name, birth_date, secret_word, private_key_hash)

        return {
            'personal_data': personal_data,
            'hash': private_key_hash,
            'private_key': self.private_key,
            'public_key': self.public_key
        }

    def _save_keys(self, name, birth_date, secret_word, hash_value):
        """Збереження ключів у файли"""
        with open("private_key.txt", "w", encoding='utf-8') as f:
            f.write(f"{self.private_key}\n")
            f.write(f"\n--- ІНФОРМАЦІЯ ПРО КЛЮЧ ---\n")
            f.write(f"Вихідні дані: {name} + {birth_date} + {secret_word}\n")
            f.write(f"SHA-256: {hash_value}\n")

        with open("public_key.txt", "w", encoding='utf-8') as f:
            f.write(f"{self.public_key}\n")
            f.write(f"\n--- ІНФОРМАЦІЯ ПРО КЛЮЧ ---\n")
            f.write(f"Обчислено: ({self.private_key} * 7) mod {self.modulus}\n")

    def load_keys(self):
        """Завантаження ключів з файлів"""
        try:
            with open("private_key.txt", "r", encoding='utf-8') as f:
                self.private_key = int(f.readline().strip())
            with open("public_key.txt", "r", encoding='utf-8') as f:
                self.public_key = int(f.readline().strip())
            return True
        except FileNotFoundError:
            return False

    def create_document_hash(self, filename):
        """Створення SHA-256 хешу документа"""
        try:
            with open(filename, 'rb') as f:
                content = f.read()
            return hashlib.sha256(content).hexdigest()
        except FileNotFoundError:
            return None

    def sign_document(self, filename):
        """Створення цифрового підпису документа"""
        if not self.private_key:
            return None

        doc_hash = self.create_document_hash(filename)
        if not doc_hash:
            return None

        doc_hash_int = int(doc_hash, 16)
        signature = doc_hash_int ^ self.private_key

        signature_file = filename + ".sig"
        with open(signature_file, "w", encoding='utf-8') as f:
            f.write(f"{signature}\n")
            f.write(f"\n--- ІНФОРМАЦІЯ ПРО ПІДПИС ---\n")
            f.write(f"Підписаний документ: {filename}\n")
            f.write(f"Хеш документа: {doc_hash}\n")

        return {
            'filename': filename,
            'hash': doc_hash,
            'signature': signature,
            'signature_file': signature_file
        }

    def verify_signature(self, filename, signature_file=None):
        """Перевірка цифрового підпису"""
        if not self.private_key:
            return None

        if not signature_file:
            signature_file = filename + ".sig"

        try:
            with open(signature_file, "r", encoding='utf-8') as f:
                signature = int(f.readline().strip())
        except (FileNotFoundError, ValueError):
            return None

        current_hash = self.create_document_hash(filename)
        if not current_hash:
            return None

        current_hash_int = int(current_hash, 16)
        decrypted_hash = signature ^ self.private_key

        is_valid = (decrypted_hash == current_hash_int)

        return {
            'filename': filename,
            'signature_file': signature_file,
            'current_hash': current_hash,
            'signature': signature,
            'decrypted_hash': decrypted_hash,
            'expected_hash': current_hash_int,
            'is_valid': is_valid
        }


class DigitalSignatureGUI:
    """Графічний інтерфейс для системи цифрових підписів"""

    def __init__(self, root):
        self.root = root
        self.root.title("Система цифрових підписів")
        self.root.geometry("900x700")
        self.root.resizable(True, True)

        self.system = DigitalSignatureSystem()

        # Стилі
        style = ttk.Style()
        style.theme_use('clam')

        self.setup_ui()

    def setup_ui(self):
        """Налаштування інтерфейсу"""
        # Головний контейнер
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(5, weight=1)

        # Заголовок
        title_label = ttk.Label(main_frame, text="Система цифрових підписів",
                                font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, pady=10)

        # Notebook для вкладок
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)

        # Вкладка 1: Генерація ключів
        self.create_keys_tab()

        # Вкладка 2: Підписання документів
        self.create_signing_tab()

        # Вкладка 3: Перевірка підписів
        self.create_verification_tab()

        # Вкладка 4: Тестування підробок
        self.create_testing_tab()

        # Область виводу логів
        log_frame = ttk.LabelFrame(main_frame, text="Лог операцій", padding="5")
        log_frame.grid(row=5, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=10, width=80,
                                                  state='disabled', wrap=tk.WORD)
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Кнопка очистки логів
        clear_btn = ttk.Button(log_frame, text="Очистити лог", command=self.clear_log)
        clear_btn.grid(row=1, column=0, pady=5)

    def create_keys_tab(self):
        """Вкладка генерації ключів"""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="Генерація ключів")

        # Поля вводу
        ttk.Label(tab, text="Ім'я (латиницею):").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.name_entry = ttk.Entry(tab, width=40)
        self.name_entry.grid(row=0, column=1, pady=5)
        self.name_entry.insert(0, "Novoseltsev")

        ttk.Label(tab, text="Дата народження (DDMMYYYY):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.birth_entry = ttk.Entry(tab, width=40)
        self.birth_entry.grid(row=1, column=1, pady=5)
        self.birth_entry.insert(0, "01012000")

        ttk.Label(tab, text="Секретне слово:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.secret_entry = ttk.Entry(tab, width=40, show="*")
        self.secret_entry.grid(row=2, column=1, pady=5)
        self.secret_entry.insert(0, "mySecretWord123")

        # Кнопка генерації
        generate_btn = ttk.Button(tab, text="Згенерувати ключі",
                                  command=self.generate_keys)
        generate_btn.grid(row=3, column=0, columnspan=2, pady=15)

        # Результати
        result_frame = ttk.LabelFrame(tab, text="Результат генерації", padding="10")
        result_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)

        self.keys_result_text = scrolledtext.ScrolledText(result_frame, height=10,
                                                          width=70, state='disabled')
        self.keys_result_text.grid(row=0, column=0)

    def create_signing_tab(self):
        """Вкладка підписання документів"""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="Підписання")

        # Вибір файлу
        ttk.Label(tab, text="Виберіть документ для підписання:").grid(row=0, column=0,
                                                                      sticky=tk.W, pady=5)

        file_frame = ttk.Frame(tab)
        file_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        self.sign_file_entry = ttk.Entry(file_frame, width=50)
        self.sign_file_entry.grid(row=0, column=0, padx=5)

        browse_btn = ttk.Button(file_frame, text="Огляд...",
                                command=self.browse_file_to_sign)
        browse_btn.grid(row=0, column=1)

        # Або створити новий
        ttk.Label(tab, text="Або створіть новий тестовий документ:").grid(row=2, column=0,
                                                                          sticky=tk.W, pady=(15, 5))

        create_btn = ttk.Button(tab, text="Створити тестовий документ",
                                command=self.create_test_document)
        create_btn.grid(row=3, column=0, pady=5)

        # Кнопка підписання
        sign_btn = ttk.Button(tab, text="Підписати документ",
                              command=self.sign_document)
        sign_btn.grid(row=4, column=0, pady=15)

        # Результати
        result_frame = ttk.LabelFrame(tab, text="Результат підписання", padding="10")
        result_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)

        self.sign_result_text = scrolledtext.ScrolledText(result_frame, height=10,
                                                          width=70, state='disabled')
        self.sign_result_text.grid(row=0, column=0)

    def create_verification_tab(self):
        """Вкладка перевірки підписів"""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="Перевірка")

        # Вибір файлу документа
        ttk.Label(tab, text="Документ:").grid(row=0, column=0, sticky=tk.W, pady=5)

        doc_frame = ttk.Frame(tab)
        doc_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        self.verify_doc_entry = ttk.Entry(doc_frame, width=50)
        self.verify_doc_entry.grid(row=0, column=0, padx=5)

        browse_doc_btn = ttk.Button(doc_frame, text="Огляд...",
                                    command=self.browse_doc_to_verify)
        browse_doc_btn.grid(row=0, column=1)

        # Вибір файлу підпису
        ttk.Label(tab, text="Файл підпису (необов'язково):").grid(row=2, column=0,
                                                                  sticky=tk.W, pady=5)

        sig_frame = ttk.Frame(tab)
        sig_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        self.verify_sig_entry = ttk.Entry(sig_frame, width=50)
        self.verify_sig_entry.grid(row=0, column=0, padx=5)

        browse_sig_btn = ttk.Button(sig_frame, text="Огляд...",
                                    command=self.browse_sig_to_verify)
        browse_sig_btn.grid(row=0, column=1)

        # Кнопка перевірки
        verify_btn = ttk.Button(tab, text="Перевірити підпис",
                                command=self.verify_signature)
        verify_btn.grid(row=4, column=0, pady=15)

        # Результати
        result_frame = ttk.LabelFrame(tab, text="Результат перевірки", padding="10")
        result_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)

        self.verify_result_text = scrolledtext.ScrolledText(result_frame, height=10,
                                                            width=70, state='disabled')
        self.verify_result_text.grid(row=0, column=0)

    def create_testing_tab(self):
        """Вкладка тестування підробок"""
        tab = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(tab, text="Тестування")

        ttk.Label(tab, text="Автоматичне тестування виявлення підробок",
                  font=('Arial', 12, 'bold')).grid(row=0, column=0, pady=10)

        # Вибір файлу для тестування
        ttk.Label(tab, text="Документ для тестування:").grid(row=1, column=0,
                                                             sticky=tk.W, pady=5)

        test_frame = ttk.Frame(tab)
        test_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=5)

        self.test_file_entry = ttk.Entry(test_frame, width=50)
        self.test_file_entry.grid(row=0, column=0, padx=5)

        browse_test_btn = ttk.Button(test_frame, text="Огляд...",
                                     command=self.browse_file_to_test)
        browse_test_btn.grid(row=0, column=1)

        # Кнопки тестування
        btn_frame = ttk.Frame(tab)
        btn_frame.grid(row=3, column=0, pady=15)

        test_all_btn = ttk.Button(btn_frame, text="Запустити всі тести",
                                  command=self.run_all_tests)
        test_all_btn.grid(row=0, column=0, padx=5)

        test_mod_btn = ttk.Button(btn_frame, text="Тест модифікації",
                                  command=self.test_modification)
        test_mod_btn.grid(row=0, column=1, padx=5)

        test_forge_btn = ttk.Button(btn_frame, text="Тест підробки",
                                    command=self.test_forgery)
        test_forge_btn.grid(row=0, column=2, padx=5)

        # Результати
        result_frame = ttk.LabelFrame(tab, text="Результати тестування", padding="10")
        result_frame.grid(row=4, column=0, sticky=(tk.W, tk.E), pady=10)

        self.test_result_text = scrolledtext.ScrolledText(result_frame, height=12,
                                                          width=70, state='disabled')
        self.test_result_text.grid(row=0, column=0)

    # Методи для роботи
    def log(self, message):
        """Додати повідомлення в лог"""
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')

    def clear_log(self):
        """Очистити лог"""
        self.log_text.config(state='normal')
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state='disabled')

    def generate_keys(self):
        """Генерація ключів"""
        name = self.name_entry.get().strip()
        birth_date = self.birth_entry.get().strip()
        secret_word = self.secret_entry.get().strip()

        if not name or not birth_date or not secret_word:
            messagebox.showerror("Помилка", "Заповніть всі поля!")
            return

        self.log("=== Генерація ключів ===")
        result = self.system.generate_keys(name, birth_date, secret_word)

        # Виведення результату
        self.keys_result_text.config(state='normal')
        self.keys_result_text.delete(1.0, tk.END)
        self.keys_result_text.insert(tk.END, f"Вихідні дані: {result['personal_data']}\n\n")
        self.keys_result_text.insert(tk.END, f"SHA-256 хеш:\n{result['hash']}\n\n")
        self.keys_result_text.insert(tk.END, f"Приватний ключ:\n{result['private_key']}\n\n")
        self.keys_result_text.insert(tk.END, f"Публічний ключ:\n{result['public_key']}\n\n")
        self.keys_result_text.insert(tk.END, f"Формула: ({result['private_key']} * 7) mod 1000007\n")
        self.keys_result_text.config(state='disabled')

        self.log(f"✓ Ключі згенеровано та збережено у файли")
        messagebox.showinfo("Успіх", "Ключі успішно згенеровано!")

    def browse_file_to_sign(self):
        """Вибір файлу для підписання"""
        filename = filedialog.askopenfilename(title="Виберіть документ")
        if filename:
            self.sign_file_entry.delete(0, tk.END)
            self.sign_file_entry.insert(0, filename)

    def create_test_document(self):
        """Створення тестового документа"""
        filename = "test_document.txt"
        with open(filename, "w", encoding='utf-8') as f:
            f.write("Це тестовий документ для демонстрації цифрових підписів.\n")
            f.write(f"Автор: {self.name_entry.get()}\n")
            f.write("Дата створення: 2025-10-14\n")
            f.write("Вміст: Важлива інформація, яка потребує захисту.\n")

        self.sign_file_entry.delete(0, tk.END)
        self.sign_file_entry.insert(0, filename)
        self.log(f"✓ Створено тестовий документ: {filename}")
        messagebox.showinfo("Успіх", f"Документ створено: {filename}")

    def sign_document(self):
        """Підписання документа"""
        if not self.system.private_key:
            if not self.system.load_keys():
                messagebox.showerror("Помилка", "Спочатку згенеруйте ключі!")
                return

        filename = self.sign_file_entry.get().strip()
        if not filename:
            messagebox.showerror("Помилка", "Виберіть файл для підписання!")
            return

        if not os.path.exists(filename):
            messagebox.showerror("Помилка", "Файл не знайдено!")
            return

        self.log(f"=== Підписання документа: {filename} ===")
        result = self.system.sign_document(filename)

        if not result:
            messagebox.showerror("Помилка", "Не вдалося підписати документ!")
            return

        # Виведення результату
        self.sign_result_text.config(state='normal')
        self.sign_result_text.delete(1.0, tk.END)
        self.sign_result_text.insert(tk.END, f"Документ: {result['filename']}\n\n")
        self.sign_result_text.insert(tk.END, f"SHA-256 хеш документа:\n{result['hash']}\n\n")
        self.sign_result_text.insert(tk.END, f"Цифровий підпис:\n{result['signature']}\n\n")
        self.sign_result_text.insert(tk.END, f"Підпис збережено у файл:\n{result['signature_file']}\n")
        self.sign_result_text.config(state='disabled')

        self.log(f"✓ Документ підписано. Підпис: {result['signature_file']}")
        messagebox.showinfo("Успіх", "Документ успішно підписано!")

    def browse_doc_to_verify(self):
        """Вибір документа для перевірки"""
        filename = filedialog.askopenfilename(title="Виберіть документ")
        if filename:
            self.verify_doc_entry.delete(0, tk.END)
            self.verify_doc_entry.insert(0, filename)

    def browse_sig_to_verify(self):
        """Вибір файлу підпису"""
        filename = filedialog.askopenfilename(title="Виберіть файл підпису",
                                              filetypes=[("Signature files", "*.sig"),
                                                         ("All files", "*.*")])
        if filename:
            self.verify_sig_entry.delete(0, tk.END)
            self.verify_sig_entry.insert(0, filename)

    def verify_signature(self):
        """Перевірка підпису"""
        if not self.system.private_key:
            if not self.system.load_keys():
                messagebox.showerror("Помилка", "Спочатку згенеруйте ключі!")
                return

        filename = self.verify_doc_entry.get().strip()
        if not filename:
            messagebox.showerror("Помилка", "Виберіть документ!")
            return

        sig_file = self.verify_sig_entry.get().strip() or None

        self.log(f"=== Перевірка підпису: {filename} ===")
        result = self.system.verify_signature(filename, sig_file)

        if not result:
            messagebox.showerror("Помилка", "Не вдалося перевірити підпис!")
            return

        # Виведення результату
        self.verify_result_text.config(state='normal')
        self.verify_result_text.delete(1.0, tk.END)
        self.verify_result_text.insert(tk.END, f"Документ: {result['filename']}\n")
        self.verify_result_text.insert(tk.END, f"Файл підпису: {result['signature_file']}\n\n")
        self.verify_result_text.insert(tk.END, f"Поточний хеш документа:\n{result['current_hash']}\n\n")
        self.verify_result_text.insert(tk.END, f"Підпис: {result['signature']}\n\n")
        self.verify_result_text.insert(tk.END, f"Розшифрований хеш:\n{result['decrypted_hash']}\n\n")
        self.verify_result_text.insert(tk.END, f"Очікуваний хеш:\n{result['expected_hash']}\n\n")

        if result['is_valid']:
            self.verify_result_text.insert(tk.END, "=" * 50 + "\n")
            self.verify_result_text.insert(tk.END, "✓ ПІДПИС ДІЙСНИЙ\n")
            self.verify_result_text.insert(tk.END, "=" * 50 + "\n")
            self.verify_result_text.insert(tk.END, "Документ не був змінений після підписання\n")
            self.log("✓ Підпис ДІЙСНИЙ")
            messagebox.showinfo("Результат", "✓ Підпис ДІЙСНИЙ\n\nДокумент автентичний!")
        else:
            self.verify_result_text.insert(tk.END, "=" * 50 + "\n")
            self.verify_result_text.insert(tk.END, "✗ ПІДПИС НЕДІЙСНИЙ\n")
            self.verify_result_text.insert(tk.END, "=" * 50 + "\n")
            self.verify_result_text.insert(tk.END, "Документ був модифікований або підпис підроблений\n")
            self.log("✗ Підпис НЕДІЙСНИЙ")
            messagebox.showwarning("Результат", "✗ ПІДПИС НЕДІЙСНИЙ\n\nДокумент підроблено!")

        self.verify_result_text.config(state='disabled')

    def browse_file_to_test(self):
        """Вибір файлу для тестування"""
        filename = filedialog.askopenfilename(title="Виберіть документ")
        if filename:
            self.test_file_entry.delete(0, tk.END)
            self.test_file_entry.insert(0, filename)

    def run_all_tests(self):
        """Запуск всіх тестів"""
        if not self.system.private_key:
            if not self.system.load_keys():
                messagebox.showerror("Помилка", "Спочатку згенеруйте ключі!")
                return

        filename = self.test_file_entry.get().strip()
        if not filename:
            messagebox.showerror("Помилка", "Виберіть файл для тестування!")
            return

        if not os.path.exists(filename):
            messagebox.showerror("Помилка", "Файл не знайдено!")
            return

        self.test_result_text.config(state='normal')
        self.test_result_text.delete(1.0, tk.END)

        self.log("=== Запуск повного тестування ===")

        # Тест 1: Оригінальний документ
        self.test_result_text.insert(tk.END, "=" * 50 + "\n")
        self.test_result_text.insert(tk.END, "ТЕСТ 1: Перевірка оригінального документа\n")
        self.test_result_text.insert(tk.END, "=" * 50 + "\n")

        result = self.system.verify_signature(filename)
        if result and result['is_valid']:
            self.test_result_text.insert(tk.END, "✓ Оригінальний підпис дійсний\n\n")
            self.log("Тест 1: ПРОЙДЕНО")
        else:
            self.test_result_text.insert(tk.END, "✗ Помилка перевірки оригіналу\n\n")
            self.log("Тест 1: ПРОВАЛЕНО")

        # Тест 2: Модифікація
        self.test_result_text.insert(tk.END, "=" * 50 + "\n")
        self.test_result_text.insert(tk.END, "ТЕСТ 2: Виявлення модифікації документа\n")
        self.test_result_text.insert(tk.END, "=" * 50 + "\n")

        # Зберігаємо оригінал
        with open(filename, 'r', encoding='utf-8') as f:
            original_content = f.read()

        # Модифікуємо
        with open(filename, 'a', encoding='utf-8') as f:
            f.write("\n[МОДИФІКОВАНО] Тестовий текст")

        result = self.system.verify_signature(filename)

        # Відновлюємо оригінал
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(original_content)

        if result and not result['is_valid']:
            self.test_result_text.insert(tk.END, "✓ Модифікацію успішно виявлено\n\n")
            self.log("Тест 2: ПРОЙДЕНО")
        else:
            self.test_result_text.insert(tk.END, "✗ Помилка виявлення модифікації\n\n")
            self.log("Тест 2: ПРОВАЛЕНО")

        # Тест 3: Підроблений підпис
        self.test_result_text.insert(tk.END, "=" * 50 + "\n")
        self.test_result_text.insert(tk.END, "ТЕСТ 3: Виявлення підробленого підпису\n")
        self.test_result_text.insert(tk.END, "=" * 50 + "\n")

        sig_file = filename + ".sig"
        if os.path.exists(sig_file):
            # Зберігаємо оригінальний підпис
            with open(sig_file, 'r', encoding='utf-8') as f:
                original_sig_content = f.read()

            # Створюємо підроблений підпис
            fake_signature = 999999999999
            with open(sig_file, 'w', encoding='utf-8') as f:
                f.write(f"{fake_signature}\n")
                f.write(f"\n--- ПІДРОБЛЕНИЙ ПІДПИС ---\n")

            result = self.system.verify_signature(filename)

            # Відновлюємо оригінальний підпис
            with open(sig_file, 'w', encoding='utf-8') as f:
                f.write(original_sig_content)

            if result and not result['is_valid']:
                self.test_result_text.insert(tk.END, "✓ Підробку успішно виявлено\n\n")
                self.log("Тест 3: ПРОЙДЕНО")
            else:
                self.test_result_text.insert(tk.END, "✗ Помилка виявлення підробки\n\n")
                self.log("Тест 3: ПРОВАЛЕНО")
        else:
            self.test_result_text.insert(tk.END, "⚠ Файл підпису не знайдено\n\n")
            self.log("Тест 3: ПРОПУЩЕНО")

        self.test_result_text.insert(tk.END, "=" * 50 + "\n")
        self.test_result_text.insert(tk.END, "ТЕСТУВАННЯ ЗАВЕРШЕНО\n")
        self.test_result_text.insert(tk.END, "=" * 50 + "\n")
        self.test_result_text.config(state='disabled')

        self.log("=== Тестування завершено ===")
        messagebox.showinfo("Тестування", "Всі тести завершено!\nДив. результати у вкладці.")

    def test_modification(self):
        """Тест виявлення модифікації"""
        if not self.system.private_key:
            if not self.system.load_keys():
                messagebox.showerror("Помилка", "Спочатку згенеруйте ключі!")
                return

        filename = self.test_file_entry.get().strip()
        if not filename or not os.path.exists(filename):
            messagebox.showerror("Помилка", "Виберіть існуючий файл!")
            return

        self.test_result_text.config(state='normal')
        self.test_result_text.delete(1.0, tk.END)

        self.log("=== Тест модифікації документа ===")
        self.test_result_text.insert(tk.END, "ТЕСТ МОДИФІКАЦІЇ ДОКУМЕНТА\n")
        self.test_result_text.insert(tk.END, "=" * 50 + "\n\n")

        # Зберігаємо оригінал
        with open(filename, 'r', encoding='utf-8') as f:
            original_content = f.read()

        original_hash = self.system.create_document_hash(filename)
        self.test_result_text.insert(tk.END, f"Оригінальний хеш:\n{original_hash}\n\n")

        # Модифікуємо
        with open(filename, 'a', encoding='utf-8') as f:
            f.write("\n[МОДИФІКОВАНО] Змінено зміст документа")

        modified_hash = self.system.create_document_hash(filename)
        self.test_result_text.insert(tk.END, f"Хеш після модифікації:\n{modified_hash}\n\n")

        # Перевіряємо підпис
        result = self.system.verify_signature(filename)

        # Відновлюємо оригінал
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(original_content)

        if result and not result['is_valid']:
            self.test_result_text.insert(tk.END, "=" * 50 + "\n")
            self.test_result_text.insert(tk.END, "✓ ТЕСТ ПРОЙДЕНО\n")
            self.test_result_text.insert(tk.END, "=" * 50 + "\n")
            self.test_result_text.insert(tk.END, "Система успішно виявила модифікацію документа\n")
            self.log("✓ Тест модифікації ПРОЙДЕНО")
            messagebox.showinfo("Тест", "✓ Модифікацію успішно виявлено!")
        else:
            self.test_result_text.insert(tk.END, "=" * 50 + "\n")
            self.test_result_text.insert(tk.END, "✗ ТЕСТ ПРОВАЛЕНО\n")
            self.test_result_text.insert(tk.END, "=" * 50 + "\n")
            self.log("✗ Тест модифікації ПРОВАЛЕНО")
            messagebox.showerror("Тест", "✗ Помилка виявлення модифікації")

        self.test_result_text.config(state='disabled')

    def test_forgery(self):
        """Тест виявлення підробки підпису"""
        if not self.system.private_key:
            if not self.system.load_keys():
                messagebox.showerror("Помилка", "Спочатку згенеруйте ключі!")
                return

        filename = self.test_file_entry.get().strip()
        if not filename or not os.path.exists(filename):
            messagebox.showerror("Помилка", "Виберіть існуючий файл!")
            return

        sig_file = filename + ".sig"
        if not os.path.exists(sig_file):
            messagebox.showerror("Помилка", "Файл підпису не знайдено!")
            return

        self.test_result_text.config(state='normal')
        self.test_result_text.delete(1.0, tk.END)

        self.log("=== Тест підробки підпису ===")
        self.test_result_text.insert(tk.END, "ТЕСТ ПІДРОБКИ ПІДПИСУ\n")
        self.test_result_text.insert(tk.END, "=" * 50 + "\n\n")

        # Зберігаємо оригінальний підпис
        with open(sig_file, 'r', encoding='utf-8') as f:
            original_sig = int(f.readline().strip())
            original_sig_content = f.read()

        self.test_result_text.insert(tk.END, f"Оригінальний підпис: {original_sig}\n\n")

        # Створюємо підроблений підпис
        fake_signature = 123456789012345
        self.test_result_text.insert(tk.END, f"Підроблений підпис: {fake_signature}\n\n")

        with open(sig_file, 'w', encoding='utf-8') as f:
            f.write(f"{fake_signature}\n")
            f.write(f"\n--- ПІДРОБЛЕНИЙ ПІДПИС ---\n")
            f.write("Цей підпис був підроблений для тестування\n")

        # Перевіряємо
        result = self.system.verify_signature(filename)

        # Відновлюємо оригінальний підпис
        with open(sig_file, 'w', encoding='utf-8') as f:
            f.write(f"{original_sig}\n")
            f.write(original_sig_content)

        if result and not result['is_valid']:
            self.test_result_text.insert(tk.END, "=" * 50 + "\n")
            self.test_result_text.insert(tk.END, "✓ ТЕСТ ПРОЙДЕНО\n")
            self.test_result_text.insert(tk.END, "=" * 50 + "\n")
            self.test_result_text.insert(tk.END, "Система успішно виявила підроблений підпис\n")
            self.log("✓ Тест підробки ПРОЙДЕНО")
            messagebox.showinfo("Тест", "✓ Підробку підпису успішно виявлено!")
        else:
            self.test_result_text.insert(tk.END, "=" * 50 + "\n")
            self.test_result_text.insert(tk.END, "✗ ТЕСТ ПРОВАЛЕНО\n")
            self.test_result_text.insert(tk.END, "=" * 50 + "\n")
            self.log("✗ Тест підробки ПРОВАЛЕНО")
            messagebox.showerror("Тест", "✗ Помилка виявлення підробки")

        self.test_result_text.config(state='disabled')


def main():
    """Головна функція запуску програми"""
    root = tk.Tk()
    app = DigitalSignatureGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()