import tkinter as tk
from tkinter import ttk, messagebox
import re
from datetime import datetime
import string


class PasswordSecurityAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Аналізатор безпеки паролів")
        self.root.geometry("800x700")
        self.root.configure(bg='#f0f0f0')

        # Стиль для виджетів
        style = ttk.Style()
        style.theme_use('clam')

        # Налаштування кольорів
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'), background='#f0f0f0')
        style.configure('Header.TLabel', font=('Arial', 12, 'bold'), background='#f0f0f0')
        style.configure('Good.TLabel', foreground='green', background='#f0f0f0')
        style.configure('Warning.TLabel', foreground='orange', background='#f0f0f0')
        style.configure('Bad.TLabel', foreground='red', background='#f0f0f0')

        # Словник поширених слів
        self.common_words = ['password', 'admin', 'user', 'qwerty', '123456',
                             'letmein', 'welcome', 'monkey', 'dragon', 'master',
                             'пароль', 'адмін', 'користувач']

        self.create_widgets()

    def create_widgets(self):
        # Заголовок
        title_frame = tk.Frame(self.root, bg='#2c3e50', height=60)
        title_frame.pack(fill='x', pady=(0, 20))
        title_frame.pack_propagate(False)

        title_label = tk.Label(title_frame, text="🔐 Аналізатор безпеки паролів",
                               font=('Arial', 18, 'bold'), bg='#2c3e50', fg='white')
        title_label.pack(expand=True)

        # Основний контейнер
        main_frame = tk.Frame(self.root, bg='#f0f0f0')
        main_frame.pack(fill='both', expand=True, padx=20)

        # Секція персональних даних
        personal_frame = tk.LabelFrame(main_frame, text="Персональні дані",
                                       font=('Arial', 12, 'bold'), bg='#f0f0f0', pady=10)
        personal_frame.pack(fill='x', pady=(0, 15))

        # Поля для персональних даних
        tk.Label(personal_frame, text="Ім'я:", bg='#f0f0f0').grid(row=0, column=0, sticky='w', padx=5)
        self.name_entry = tk.Entry(personal_frame, width=20)
        self.name_entry.grid(row=0, column=1, padx=5, pady=2)

        tk.Label(personal_frame, text="Прізвище:", bg='#f0f0f0').grid(row=0, column=2, sticky='w', padx=5)
        self.surname_entry = tk.Entry(personal_frame, width=20)
        self.surname_entry.grid(row=0, column=3, padx=5, pady=2)

        tk.Label(personal_frame, text="Дата народження:", bg='#f0f0f0').grid(row=1, column=0, sticky='w', padx=5)
        self.birth_entry = tk.Entry(personal_frame, width=20)
        self.birth_entry.grid(row=1, column=1, padx=5, pady=2)
        tk.Label(personal_frame, text="(DD.MM.YYYY)", font=('Arial', 8), bg='#f0f0f0').grid(row=1, column=2, sticky='w')

        tk.Label(personal_frame, text="Email:", bg='#f0f0f0').grid(row=2, column=0, sticky='w', padx=5)
        self.email_entry = tk.Entry(personal_frame, width=40)
        self.email_entry.grid(row=2, column=1, columnspan=2, padx=5, pady=2, sticky='w')

        tk.Label(personal_frame, text="Телефон:", bg='#f0f0f0').grid(row=3, column=0, sticky='w', padx=5)
        self.phone_entry = tk.Entry(personal_frame, width=20)
        self.phone_entry.grid(row=3, column=1, padx=5, pady=2)

        # Секція пароля
        password_frame = tk.LabelFrame(main_frame, text="Аналіз пароля",
                                       font=('Arial', 12, 'bold'), bg='#f0f0f0', pady=10)
        password_frame.pack(fill='x', pady=(0, 15))

        tk.Label(password_frame, text="Введіть пароль:", bg='#f0f0f0', font=('Arial', 10, 'bold')).pack(anchor='w')
        self.password_entry = tk.Entry(password_frame, width=50, show="*", font=('Arial', 12))
        self.password_entry.pack(pady=5, anchor='w')

        # Кнопка показати/приховати пароль
        button_frame = tk.Frame(password_frame, bg='#f0f0f0')
        button_frame.pack(fill='x', pady=5)

        self.show_password_var = tk.BooleanVar()
        show_check = tk.Checkbutton(button_frame, text="Показати пароль",
                                    variable=self.show_password_var,
                                    command=self.toggle_password_visibility, bg='#f0f0f0')
        show_check.pack(side='left')

        # Кнопка аналізу
        analyze_btn = tk.Button(button_frame, text="🔍 Аналізувати пароль",
                                command=self.analyze_password,
                                bg='#3498db', fg='white', font=('Arial', 11, 'bold'),
                                relief='flat', padx=20, pady=8)
        analyze_btn.pack(side='right')

        # Секція результатів
        results_frame = tk.LabelFrame(main_frame, text="Результати аналізу",
                                      font=('Arial', 12, 'bold'), bg='#f0f0f0')
        results_frame.pack(fill='both', expand=True)

        # Текстове поле для результатів з прокруткою
        text_frame = tk.Frame(results_frame, bg='#f0f0f0')
        text_frame.pack(fill='both', expand=True, padx=10, pady=10)

        self.results_text = tk.Text(text_frame, wrap='word', font=('Arial', 10),
                                    bg='white', relief='sunken', bd=2)
        scrollbar = tk.Scrollbar(text_frame, orient='vertical', command=self.results_text.yview)
        self.results_text.configure(yscrollcommand=scrollbar.set)

        self.results_text.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        # Конфігурація тегів для кольорового тексту
        self.results_text.tag_configure('good', foreground='green', font=('Arial', 10, 'bold'))
        self.results_text.tag_configure('warning', foreground='orange', font=('Arial', 10, 'bold'))
        self.results_text.tag_configure('bad', foreground='red', font=('Arial', 10, 'bold'))
        self.results_text.tag_configure('header', font=('Arial', 12, 'bold'))
        self.results_text.tag_configure('bold', font=('Arial', 10, 'bold'))

    def toggle_password_visibility(self):
        if self.show_password_var.get():
            self.password_entry.configure(show="")
        else:
            self.password_entry.configure(show="*")

    def analyze_password(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Помилка", "Будь ласка, введіть пароль для аналізу")
            return

        # Очищення поля результатів
        self.results_text.delete(1.0, tk.END)

        # Збір персональних даних
        personal_data = {
            'name': self.name_entry.get().lower(),
            'surname': self.surname_entry.get().lower(),
            'birth': self.birth_entry.get(),
            'email': self.email_entry.get().lower(),
            'phone': self.phone_entry.get()
        }

        # Проведення аналізу
        score = 0
        max_score = 100

        self.add_result("🔐 ЗВІТ ПРО БЕЗПЕКУ ПАРОЛЯ\n", 'header')
        self.add_result("=" * 50 + "\n\n", 'bold')

        # Аналіз довжини
        length_score, length_feedback = self.analyze_length(password)
        score += length_score
        self.add_result(f"📏 Довжина пароля: {len(password)} символів\n", 'bold')
        self.add_result(f"   {length_feedback}\n\n")

        # Аналіз складності
        complexity_score, complexity_feedback = self.analyze_complexity(password)
        score += complexity_score
        self.add_result("🎯 Аналіз складності:\n", 'bold')
        for feedback in complexity_feedback:
            self.add_result(f"   {feedback}\n")
        self.add_result("\n")

        # Аналіз словникових слів
        dict_score, dict_feedback = self.analyze_dictionary(password)
        score += dict_score
        self.add_result("📚 Перевірка словникових слів:\n", 'bold')
        self.add_result(f"   {dict_feedback}\n\n")

        # Аналіз зв'язку з персональними даними
        personal_score, personal_feedback = self.analyze_personal_connection(password, personal_data)
        score += personal_score
        self.add_result("👤 Зв'язок з персональними даними:\n", 'bold')
        for feedback in personal_feedback:
            self.add_result(f"   {feedback}\n")
        self.add_result("\n")

        # Загальна оцінка
        self.add_result("📊 ЗАГАЛЬНА ОЦІНКА:\n", 'header')
        self.add_result("=" * 30 + "\n")

        percentage = (score / max_score) * 100
        if percentage >= 80:
            self.add_result(f"Оцінка: {percentage:.0f}% - ВІДМІННО! 🟢\n", 'good')
            self.add_result("Ваш пароль має високий рівень безпеки.\n\n", 'good')
        elif percentage >= 60:
            self.add_result(f"Оцінка: {percentage:.0f}% - ДОБРЕ 🟡\n", 'warning')
            self.add_result("Ваш пароль має середній рівень безпеки, але можна покращити.\n\n", 'warning')
        else:
            self.add_result(f"Оцінка: {percentage:.0f}% - ПОТРЕБУЄ ПОКРАЩЕННЯ! 🔴\n", 'bad')
            self.add_result("Ваш пароль має низький рівень безпеки.\n\n", 'bad')

        # Рекомендації
        recommendations = self.generate_recommendations(password, personal_data, percentage)
        self.add_result("💡 РЕКОМЕНДАЦІЇ ДЛЯ ПОКРАЩЕННЯ:\n", 'header')
        self.add_result("=" * 35 + "\n")
        for i, rec in enumerate(recommendations, 1):
            self.add_result(f"{i}. {rec}\n")

    def add_result(self, text, tag='normal'):
        self.results_text.insert(tk.END, text, tag)
        self.results_text.see(tk.END)

    def analyze_length(self, password):
        length = len(password)
        if length >= 16:
            return 25, "✅ Відмінна довжина (16+ символів)"
        elif length >= 12:
            return 20, "✅ Хороша довжина (12-15 символів)"
        elif length >= 8:
            return 15, "⚠️ Мінімальна довжина (8-11 символів)"
        else:
            return 0, "❌ Занадто короткий пароль (менше 8 символів)"

    def analyze_complexity(self, password):
        score = 0
        feedback = []

        if re.search(r'[a-z]', password):
            score += 5
            feedback.append("✅ Містить малі літери")
        else:
            feedback.append("❌ Відсутні малі літери")

        if re.search(r'[A-Z]', password):
            score += 5
            feedback.append("✅ Містить великі літери")
        else:
            feedback.append("❌ Відсутні великі літери")

        if re.search(r'[0-9]', password):
            score += 5
            feedback.append("✅ Містить цифри")
        else:
            feedback.append("❌ Відсутні цифри")

        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 10
            feedback.append("✅ Містить спеціальні символи")
        else:
            feedback.append("❌ Відсутні спеціальні символи")

        return score, feedback

    def analyze_dictionary(self, password):
        password_lower = password.lower()
        found_words = []

        for word in self.common_words:
            if word in password_lower:
                found_words.append(word)

        if not found_words:
            return 20, "✅ Не містить поширених словникових слів"
        else:
            return 0, f"❌ Містить словникові слова: {', '.join(found_words)}"

    def analyze_personal_connection(self, password, personal_data):
        score = 20
        feedback = []
        found_connections = []

        password_lower = password.lower()

        # Перевірка імені та прізвища
        if personal_data['name'] and personal_data['name'] in password_lower:
            found_connections.append("ім'я")
            score -= 10

        if personal_data['surname'] and personal_data['surname'] in password_lower:
            found_connections.append("прізвище")
            score -= 10

        # Перевірка дати народження
        if personal_data['birth']:
            birth_parts = personal_data['birth'].replace('.', '').replace('/', '').replace('-', '')
            if len(birth_parts) >= 4:
                # Перевірка року
                year = birth_parts[-4:]
                if year in password:
                    found_connections.append(f"рік народження ({year})")
                    score -= 10

                # Перевірка дня та місяця
                if len(birth_parts) >= 8:
                    day_month = birth_parts[:4]
                    if day_month in password:
                        found_connections.append("день/місяць народження")
                        score -= 5

        # Перевірка email
        if personal_data['email']:
            email_part = personal_data['email'].split('@')[0]
            if email_part in password_lower:
                found_connections.append("частина email")
                score -= 10

        # Перевірка телефону
        if personal_data['phone']:
            phone_digits = re.sub(r'\D', '', personal_data['phone'])
            if len(phone_digits) >= 4:
                # Перевірка останніх 4 цифр
                last_digits = phone_digits[-4:]
                if last_digits in password:
                    found_connections.append(f"частина телефону ({last_digits})")
                    score -= 10

        if found_connections:
            feedback.append(f"❌ Містить персональні дані: {', '.join(found_connections)}")
        else:
            feedback.append("✅ Не містить очевидних персональних даних")

        return max(0, score), feedback

    def generate_recommendations(self, password, personal_data, score):
        recommendations = []

        if len(password) < 12:
            recommendations.append("Збільшіть довжину пароля до мінімум 12 символів")

        if not re.search(r'[A-Z]', password):
            recommendations.append("Додайте великі літери (A-Z)")

        if not re.search(r'[a-z]', password):
            recommendations.append("Додайте малі літери (a-z)")

        if not re.search(r'[0-9]', password):
            recommendations.append("Додайте цифри (0-9)")

        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            recommendations.append("Додайте спеціальні символи (!@#$%^&* тощо)")

        # Перевірка на словникові слова
        password_lower = password.lower()
        for word in self.common_words:
            if word in password_lower:
                recommendations.append(f"Уникайте поширених слів як '{word}'")
                break

        # Перевірка персональних даних
        if any([personal_data['name'] and personal_data['name'] in password_lower,
                personal_data['surname'] and personal_data['surname'] in password_lower]):
            recommendations.append("Не використовуйте своє ім'я чи прізвище в паролі")

        if score < 60:
            recommendations.extend([
                "Використовуйте генератор паролів для створення складних паролів",
                "Використовуйте унікальні паролі для кожного акаунту",
                "Розгляньте можливість використання менеджера паролів",
                "Увімкніть двофакторну автентифікацію там, де це можливо"
            ])

        if not recommendations:
            recommendations.append("Ваш пароль має високий рівень безпеки! Продовжуйте в тому ж дусі.")

        return recommendations


def main():
    root = tk.Tk()
    app = PasswordSecurityAnalyzer(root)
    root.mainloop()


if __name__ == "__main__":
    main()