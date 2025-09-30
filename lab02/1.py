import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import string
from collections import Counter
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


class CipherComparison:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Порівняльний аналіз класичних шифрів")
        self.window.geometry("1200x800")
        self.window.configure(bg='#f0f0f0')

        self.ukr_alphabet = 'абвгґдеєжзиіїйклмнопрстуфхцчшщьюя'
        self.create_widgets()

    def caesar_cipher(self, text, shift, decode=False):
        """Шифрування методом Цезаря"""
        if decode:
            shift = -shift
        result = []

        for char in text:
            if char.lower() in self.ukr_alphabet:
                is_upper = char.isupper()
                idx = self.ukr_alphabet.index(char.lower())
                new_idx = (idx + shift) % len(self.ukr_alphabet)
                new_char = self.ukr_alphabet[new_idx]
                result.append(new_char.upper() if is_upper else new_char)
            elif char in string.ascii_letters:
                is_upper = char.isupper()
                base = ord('A') if is_upper else ord('a')
                shifted = (ord(char) - base + shift) % 26
                result.append(chr(base + shifted))
            else:
                result.append(char)

        return ''.join(result)

    def vigenere_cipher(self, text, key, decode=False):
        """Шифрування методом Віженера"""
        key = key.lower()
        result = []
        key_idx = 0

        for char in text:
            if char.lower() in self.ukr_alphabet:
                is_upper = char.isupper()
                char_idx = self.ukr_alphabet.index(char.lower())
                key_char = key[key_idx % len(key)]

                if key_char in self.ukr_alphabet:
                    key_shift = self.ukr_alphabet.index(key_char)
                else:
                    key_shift = ord(key_char.lower()) - ord('a')

                if decode:
                    key_shift = -key_shift

                new_idx = (char_idx + key_shift) % len(self.ukr_alphabet)
                new_char = self.ukr_alphabet[new_idx]
                result.append(new_char.upper() if is_upper else new_char)
                key_idx += 1
            elif char in string.ascii_letters:
                is_upper = char.isupper()
                base = ord('A') if is_upper else ord('a')
                char_pos = ord(char.lower()) - ord('a')
                key_char = key[key_idx % len(key)]
                key_shift = ord(key_char.lower()) - ord('a')

                if decode:
                    key_shift = -key_shift

                new_pos = (char_pos + key_shift) % 26
                result.append(chr(base + new_pos))
                key_idx += 1
            else:
                result.append(char)

        return ''.join(result)

    def generate_caesar_key(self, date):
        """Генерація ключа для Цезаря (сума цифр дати)"""
        return sum(int(d) for d in date if d.isdigit())

    def brute_force_caesar(self, encrypted_text):
        """Brute force атака на шифр Цезаря"""
        results = []
        for shift in range(1, 34):  # для української абетки
            decrypted = self.caesar_cipher(encrypted_text, shift, decode=True)
            results.append((shift, decrypted))
        return results

    def frequency_analysis(self, text):
        """Частотний аналіз тексту"""
        letters_only = ''.join(c.lower() for c in text if c.lower() in self.ukr_alphabet or c in string.ascii_lowercase)
        return Counter(letters_only)

    def calculate_complexity(self, cipher_type, key):
        """Розрахунок складності ключа"""
        if cipher_type == "Цезарь":
            return f"Низька (1 параметр, {len(self.ukr_alphabet)} варіантів)"
        else:
            return f"Середня (ключ довжиною {len(key)} символів)"

    def create_widgets(self):
        # Заголовок
        title = tk.Label(self.window, text="🔐 Порівняльний аналіз класичних шифрів",
                         font=('Arial', 18, 'bold'), bg='#f0f0f0', fg='#2c3e50')
        title.pack(pady=10)

        # Фрейм для вводу
        input_frame = ttk.LabelFrame(self.window, text="Вхідні дані", padding=10)
        input_frame.pack(fill='x', padx=20, pady=5)

        # Текст для шифрування
        tk.Label(input_frame, text="Текст для шифрування:").grid(row=0, column=0, sticky='w', pady=5)
        self.text_input = scrolledtext.ScrolledText(input_frame, height=3, width=80, font=('Arial', 10))
        self.text_input.grid(row=1, column=0, columnspan=3, pady=5)
        self.text_input.insert('1.0', 'Захист інформації – важлива дисципліна')

        # Дата народження
        tk.Label(input_frame, text="Дата народження (для Цезаря):").grid(row=2, column=0, sticky='w', pady=5)
        self.date_input = ttk.Entry(input_frame, width=20, font=('Arial', 10))
        self.date_input.grid(row=2, column=1, sticky='w', pady=5)
        self.date_input.insert(0, '18022005')

        # Прізвище
        tk.Label(input_frame, text="Прізвище (для Віженера):").grid(row=3, column=0, sticky='w', pady=5)
        self.surname_input = ttk.Entry(input_frame, width=20, font=('Arial', 10))
        self.surname_input.grid(row=3, column=1, sticky='w', pady=5)
        self.surname_input.insert(0, 'Novoseltsev')

        # Кнопки
        btn_frame = tk.Frame(input_frame, bg='white')
        btn_frame.grid(row=4, column=0, columnspan=3, pady=10)

        ttk.Button(btn_frame, text="🔒 Зашифрувати", command=self.encrypt_text).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="🔓 Розшифрувати", command=self.decrypt_text).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="📊 Аналіз", command=self.show_analysis).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="🔨 Brute Force", command=self.brute_force).pack(side='left', padx=5)

        # Основний фрейм для результатів (горизонтальне розташування)
        main_results_frame = tk.Frame(self.window, bg='#f0f0f0')
        main_results_frame.pack(fill='both', expand=True, padx=20, pady=5)

        # Лівий фрейм - результати шифрування
        left_frame = ttk.LabelFrame(main_results_frame, text="Результати шифрування", padding=10)
        left_frame.pack(side='left', fill='both', expand=True, padx=(0, 10))

        # Результат Цезаря
        tk.Label(left_frame, text="Шифр Цезаря:", font=('Arial', 11, 'bold')).pack(anchor='w', pady=5)
        self.caesar_result = scrolledtext.ScrolledText(left_frame, height=6, width=50, font=('Courier', 10))
        self.caesar_result.pack(fill='x', pady=5)

        # Результат Віженера
        tk.Label(left_frame, text="Шифр Віженера:", font=('Arial', 11, 'bold')).pack(anchor='w', pady=5)
        self.vigenere_result = scrolledtext.ScrolledText(left_frame, height=6, width=50, font=('Courier', 10))
        self.vigenere_result.pack(fill='x', pady=5)

        # Правий фрейм - порівняльна таблиця
        right_frame = ttk.LabelFrame(main_results_frame, text="Порівняльна таблиця", padding=10)
        right_frame.pack(side='right', fill='both', expand=True)

        self.comparison_table = scrolledtext.ScrolledText(right_frame, height=20, width=65, font=('Courier', 9))
        self.comparison_table.pack(fill='both', expand=True)

    def encrypt_text(self):
        """Шифрування тексту обома методами"""
        text = self.text_input.get('1.0', 'end-1c')
        date = self.date_input.get()
        surname = self.surname_input.get()

        if not text or not date or not surname:
            messagebox.showerror("Помилка", "Заповніть всі поля!")
            return

        # Генерація ключів
        caesar_shift = self.generate_caesar_key(date)

        # Шифрування
        caesar_encrypted = self.caesar_cipher(text, caesar_shift)
        vigenere_encrypted = self.vigenere_cipher(text, surname)

        # Виведення результатів
        self.caesar_result.delete('1.0', 'end')
        self.caesar_result.insert('1.0', f"Ключ (зсув): {caesar_shift}\n")
        self.caesar_result.insert('end', f"Зашифровано: {caesar_encrypted}")

        self.vigenere_result.delete('1.0', 'end')
        self.vigenere_result.insert('1.0', f"Ключ: {surname}\n")
        self.vigenere_result.insert('end', f"Зашифровано: {vigenere_encrypted}")

        # Порівняльна таблиця
        self.update_comparison_table(text, caesar_encrypted, vigenere_encrypted, caesar_shift, surname)

    def decrypt_text(self):
        """Розшифрування тексту"""
        date = self.date_input.get()
        surname = self.surname_input.get()

        caesar_shift = self.generate_caesar_key(date)

        # Розшифрування Цезаря
        caesar_text = self.caesar_result.get('1.0', 'end-1c').split('\n')[-1].replace('Зашифровано: ', '')
        if caesar_text:
            caesar_decrypted = self.caesar_cipher(caesar_text, caesar_shift, decode=True)
            messagebox.showinfo("Розшифровано (Цезарь)", caesar_decrypted)

        # Розшифрування Віженера
        vigenere_text = self.vigenere_result.get('1.0', 'end-1c').split('\n')[-1].replace('Зашифровано: ', '')
        if vigenere_text:
            vigenere_decrypted = self.vigenere_cipher(vigenere_text, surname, decode=True)
            messagebox.showinfo("Розшифровано (Віженер)", vigenere_decrypted)

    def update_comparison_table(self, original, caesar_enc, vigenere_enc, caesar_key, vigenere_key):
        """Оновлення таблиці порівняння"""
        self.comparison_table.delete('1.0', 'end')

        table = f"""
{'=' * 90}
{'Параметр':<30} | {'Цезарь':<25} | {'Віженер':<25}
{'=' * 90}
{'Довжина оригіналу':<30} | {len(original):<25} | {len(original):<25}
{'Довжина результату':<30} | {len(caesar_enc):<25} | {len(vigenere_enc):<25}
{'Складність ключа':<30} | {self.calculate_complexity('Цезарь', str(caesar_key)):<25} | {self.calculate_complexity('Віженер', vigenere_key):<25}
{'Унікальних символів':<30} | {len(set(caesar_enc)):<25} | {len(set(vigenere_enc)):<25}
{'=' * 90}

ВИСНОВКИ:
• Шифр Цезаря: Простий, але вразливий до brute force (34 варіанти)
• Шифр Віженера: Складніший, стійкіший до частотного аналізу
• Обидва методи зберігають довжину тексту та розділові знаки
        """

        self.comparison_table.insert('1.0', table)

    def show_analysis(self):
        """Відображення частотного аналізу"""
        text = self.text_input.get('1.0', 'end-1c')
        date = self.date_input.get()
        surname = self.surname_input.get()

        caesar_shift = self.generate_caesar_key(date)
        caesar_enc = self.caesar_cipher(text, caesar_shift)
        vigenere_enc = self.vigenere_cipher(text, surname)

        # Частотний аналіз
        freq_original = self.frequency_analysis(text)
        freq_caesar = self.frequency_analysis(caesar_enc)
        freq_vigenere = self.frequency_analysis(vigenere_enc)

        # Створення графіка
        fig, axes = plt.subplots(1, 3, figsize=(15, 4))

        for ax, freq, title in zip(axes,
                                   [freq_original, freq_caesar, freq_vigenere],
                                   ['Оригінал', 'Цезарь', 'Віженер']):
            if freq:
                chars = list(freq.keys())[:10]
                counts = [freq[c] for c in chars]
                ax.bar(chars, counts, color='steelblue')
                ax.set_title(title, fontsize=12, weight='bold')
                ax.set_xlabel('Символи')
                ax.set_ylabel('Частота')
                ax.grid(axis='y', alpha=0.3)

        plt.tight_layout()

        # Відображення в новому вікні
        analysis_window = tk.Toplevel(self.window)
        analysis_window.title("Частотний аналіз")
        analysis_window.geometry("1000x500")

        canvas = FigureCanvasTkAgg(fig, analysis_window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill='both', expand=True)

    def brute_force(self):
        """Brute force атака на Цезаря"""
        caesar_text = self.caesar_result.get('1.0', 'end-1c').split('\n')[-1].replace('Зашифровано: ', '')

        if not caesar_text:
            messagebox.showerror("Помилка", "Спочатку зашифруйте текст!")
            return

        results = self.brute_force_caesar(caesar_text)

        # Відображення результатів
        bf_window = tk.Toplevel(self.window)
        bf_window.title("Brute Force - Шифр Цезаря")
        bf_window.geometry("800x600")

        tk.Label(bf_window, text="Всі можливі варіанти розшифрування:",
                 font=('Arial', 12, 'bold')).pack(pady=10)

        result_text = scrolledtext.ScrolledText(bf_window, width=90, height=30, font=('Courier', 9))
        result_text.pack(padx=10, pady=10, fill='both', expand=True)

        for shift, decrypted in results:
            result_text.insert('end', f"Зсув {shift:2d}: {decrypted}\n")

    def run(self):
        """Запуск програми"""
        self.window.mainloop()


if __name__ == "__main__":
    app = CipherComparison()
    app.run()