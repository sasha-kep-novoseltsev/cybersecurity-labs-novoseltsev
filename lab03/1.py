import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import os


class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Стеганографія LSB")
        self.root.geometry("1000x700")
        self.root.resizable(False, False)

        self.original_image = None
        self.stego_image = None
        self.original_path = None

        # Маркери для повідомлення
        self.START_MARKER = "###START###"
        self.END_MARKER = "###END###"

        self.setup_ui()

    def setup_ui(self):
        # Заголовок
        header_frame = tk.Frame(self.root, bg="#2c3e50", height=80)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)

        title_label = tk.Label(header_frame, text="Стеганографія LSB",
                               font=("Arial", 20, "bold"), bg="#2c3e50", fg="white")
        title_label.pack(pady=10)

        subtitle_label = tk.Label(header_frame,
                                  text="Приховування текстової інформації в зображеннях",
                                  font=("Arial", 10), bg="#2c3e50", fg="#ecf0f1")
        subtitle_label.pack()

        # Основна область
        main_frame = tk.Frame(self.root, bg="#ecf0f1")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Вибір режиму
        mode_frame = tk.Frame(main_frame, bg="#ecf0f1")
        mode_frame.pack(fill=tk.X, pady=(0, 15))

        self.mode = tk.StringVar(value="hide")

        hide_btn = tk.Radiobutton(mode_frame, text="Приховати", variable=self.mode,
                                  value="hide", font=("Arial", 11), bg="#ecf0f1",
                                  command=self.switch_mode)
        hide_btn.pack(side=tk.LEFT, padx=5)

        extract_btn = tk.Radiobutton(mode_frame, text="Витягти", variable=self.mode,
                                     value="extract", font=("Arial", 11), bg="#ecf0f1",
                                     command=self.switch_mode)
        extract_btn.pack(side=tk.LEFT, padx=5)

        # Завантаження файлу
        file_frame = tk.Frame(main_frame, bg="#ecf0f1")
        file_frame.pack(fill=tk.X, pady=(0, 15))

        load_btn = tk.Button(file_frame, text="Завантажити зображення",
                             command=self.load_image, font=("Arial", 10),
                             bg="#3498db", fg="white", padx=15, pady=5, relief=tk.FLAT)
        load_btn.pack(side=tk.LEFT)

        self.file_label = tk.Label(file_frame, text="Файл не обрано",
                                   font=("Arial", 9), bg="#ecf0f1", fg="#7f8c8d")
        self.file_label.pack(side=tk.LEFT, padx=10)

        # Додаткові кнопки
        self.save_original_btn = tk.Button(file_frame, text="Зберегти оригінал",
                                           command=self.save_original,
                                           font=("Arial", 9), bg="#95a5a6", fg="white",
                                           padx=10, pady=5, relief=tk.FLAT, state=tk.DISABLED)
        self.save_original_btn.pack(side=tk.LEFT, padx=5)

        self.save_stego_btn = tk.Button(file_frame, text="Зберегти стегоконтейнер",
                                        command=self.save_stego,
                                        font=("Arial", 9), bg="#9b59b6", fg="white",
                                        padx=10, pady=5, relief=tk.FLAT, state=tk.DISABLED)
        self.save_stego_btn.pack(side=tk.LEFT, padx=5)

        # Область для роботи з повідомленням
        self.work_frame = tk.Frame(main_frame, bg="#ecf0f1")
        self.work_frame.pack(fill=tk.BOTH, expand=True)

        self.setup_hide_interface()

    def setup_hide_interface(self):
        for widget in self.work_frame.winfo_children():
            widget.destroy()

        # Поле вводу повідомлення
        msg_label = tk.Label(self.work_frame, text="Повідомлення для приховування:",
                             font=("Arial", 10, "bold"), bg="#ecf0f1")
        msg_label.pack(anchor=tk.W, pady=(0, 5))

        self.message_text = tk.Text(self.work_frame, height=5, font=("Arial", 10),
                                    wrap=tk.WORD, relief=tk.SOLID, borderwidth=1)
        self.message_text.pack(fill=tk.X, pady=(0, 10))

        # Кнопка приховування
        hide_btn = tk.Button(self.work_frame, text="Приховати повідомлення",
                             command=self.hide_message, font=("Arial", 10, "bold"),
                             bg="#27ae60", fg="white", padx=20, pady=8, relief=tk.FLAT)
        hide_btn.pack(pady=(0, 15))

        # Область зображень
        images_frame = tk.Frame(self.work_frame, bg="#ecf0f1")
        images_frame.pack(fill=tk.BOTH, expand=True)

        # Оригінал
        orig_frame = tk.Frame(images_frame, bg="white", relief=tk.SOLID, borderwidth=1)
        orig_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

        orig_title = tk.Label(orig_frame, text="Оригінальне зображення",
                              font=("Arial", 10, "bold"), bg="white")
        orig_title.pack(pady=5)

        self.orig_canvas = tk.Canvas(orig_frame, bg="#f8f9fa", width=400, height=300)
        self.orig_canvas.pack(padx=5, pady=5)

        # Стегоконтейнер
        stego_frame = tk.Frame(images_frame, bg="white", relief=tk.SOLID, borderwidth=1)
        stego_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0))

        stego_title = tk.Label(stego_frame, text="Стегоконтейнер",
                               font=("Arial", 10, "bold"), bg="white")
        stego_title.pack(pady=5)

        self.stego_canvas = tk.Canvas(stego_frame, bg="#f8f9fa", width=400, height=300)
        self.stego_canvas.pack(padx=5, pady=5)

        self.save_btn = tk.Button(stego_frame, text="Зберегти стегоконтейнер",
                                  command=self.save_image, font=("Arial", 9),
                                  bg="#34495e", fg="white", state=tk.DISABLED,
                                  relief=tk.FLAT)
        self.save_btn.pack(pady=5)

        # Статистика
        self.stats_frame = tk.Frame(self.work_frame, bg="#e8f4f8",
                                    relief=tk.SOLID, borderwidth=1)
        self.stats_label = tk.Label(self.stats_frame, text="", font=("Arial", 9),
                                    bg="#e8f4f8", justify=tk.LEFT)

    def setup_extract_interface(self):
        for widget in self.work_frame.winfo_children():
            widget.destroy()

        # Кнопка витягування
        extract_btn = tk.Button(self.work_frame, text="Витягти повідомлення",
                                command=self.extract_message, font=("Arial", 10, "bold"),
                                bg="#e67e22", fg="white", padx=20, pady=8, relief=tk.FLAT)
        extract_btn.pack(pady=(0, 15))

        # Результат
        result_label = tk.Label(self.work_frame, text="Витягнуте повідомлення:",
                                font=("Arial", 10, "bold"), bg="#ecf0f1")
        result_label.pack(anchor=tk.W, pady=(0, 5))

        self.result_text = tk.Text(self.work_frame, height=8, font=("Arial", 10),
                                   wrap=tk.WORD, relief=tk.SOLID, borderwidth=1,
                                   state=tk.DISABLED)
        self.result_text.pack(fill=tk.BOTH, expand=True, pady=(0, 15))

        # Зображення
        img_frame = tk.Frame(self.work_frame, bg="white", relief=tk.SOLID, borderwidth=1)
        img_frame.pack(fill=tk.BOTH, expand=True)

        img_title = tk.Label(img_frame, text="Завантажене зображення",
                             font=("Arial", 10, "bold"), bg="white")
        img_title.pack(pady=5)

        self.extract_canvas = tk.Canvas(img_frame, bg="#f8f9fa", width=820, height=300)
        self.extract_canvas.pack(padx=5, pady=5)

    def switch_mode(self):
        if self.mode.get() == "hide":
            self.setup_hide_interface()
        else:
            self.setup_extract_interface()

        if self.original_image:
            self.display_original_image()

    def load_image(self):
        file_path = filedialog.askopenfilename(
            title="Оберіть зображення",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp"), ("All files", "*.*")]
        )

        if file_path:
            try:
                self.original_image = Image.open(file_path).convert('RGB')
                self.original_path = file_path
                self.file_label.config(text=os.path.basename(file_path), fg="#2c3e50")
                self.display_original_image()
                self.stego_image = None

                # Оновлюємо стан кнопок
                if hasattr(self, 'save_btn') and self.save_btn.winfo_exists():
                    self.save_btn.config(state=tk.DISABLED)
                self.save_original_btn.config(state=tk.NORMAL)
                self.save_stego_btn.config(state=tk.DISABLED)
            except Exception as e:
                messagebox.showerror("Помилка", f"Не вдалося завантажити зображення: {str(e)}")

    def save_original(self):
        if not self.original_image:
            messagebox.showwarning("Увага", "Немає зображення для збереження")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG files", "*.png"), ("JPEG files", "*.jpg"), ("All files", "*.*")],
            initialfile="original_image"
        )

        if file_path:
            try:
                ext = os.path.splitext(file_path)[1].lower()
                if ext in ['.jpg', '.jpeg']:
                    self.original_image.save(file_path, "JPEG", quality=95)
                else:
                    self.original_image.save(file_path, "PNG")
                messagebox.showinfo("Успіх", "Оригінальне зображення збережено")
            except Exception as e:
                messagebox.showerror("Помилка", f"Помилка збереження: {str(e)}")

    def save_stego(self):
        if not self.stego_image:
            messagebox.showwarning("Увага", "Немає стегоконтейнера для збереження")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG files", "*.png"), ("All files", "*.*")],
            initialfile="stego_image"
        )

        if file_path:
            try:
                self.stego_image.save(file_path, "PNG")
                messagebox.showinfo("Успіх", "Стегоконтейнер збережено")
            except Exception as e:
                messagebox.showerror("Помилка", f"Помилка збереження: {str(e)}")

    def display_original_image(self):
        if not self.original_image:
            return

        if self.mode.get() == "hide":
            canvas = self.orig_canvas
            max_w, max_h = 400, 300
        else:
            canvas = self.extract_canvas
            max_w, max_h = 820, 300

        img_copy = self.original_image.copy()
        img_copy.thumbnail((max_w, max_h), Image.Resampling.LANCZOS)
        photo = ImageTk.PhotoImage(img_copy)

        canvas.delete("all")
        canvas.image = photo
        canvas.create_image(max_w // 2, max_h // 2, image=photo)

    def text_to_binary(self, text):
        """(опціонально) Конвертує рядок у бітову стрічку використовуючи UTF-8."""
        data = text.encode('utf-8')
        return ''.join(format(b, '08b') for b in data)

    def binary_to_text(self, binary):
        """(опціонально) Конвертує бітову стрічку в текст з декодуванням UTF-8 (ignore помилки)."""
        ba = bytearray()
        for i in range(0, len(binary) - (len(binary) % 8), 8):
            ba.append(int(binary[i:i+8], 2))
        try:
            return ba.decode('utf-8', errors='ignore')
        except Exception:
            return ba.decode('latin-1', errors='ignore')

    def hide_message(self):
        """Надійне приховування повідомлення (UTF-8, 8 біт на байт)."""
        if not self.original_image:
            messagebox.showwarning("Увага", "Спочатку завантажте зображення")
            return

        message = self.message_text.get("1.0", tk.END).rstrip('\n')
        if not message:
            messagebox.showwarning("Увага", "Введіть повідомлення")
            return

        try:
            full_message = self.START_MARKER + message + self.END_MARKER
            data = full_message.encode('utf-8')  # bytes
            total_bits = len(data) * 8

            img = self.original_image.copy()
            width, height = img.size
            max_bits = width * height * 3  # 3 біти на піксель (RGB)

            if total_bits > max_bits:
                messagebox.showerror(
                    "Помилка",
                    f"Повідомлення занадто довге!\n"
                    f"Максимум: {max_bits // 8} байтів (≈символів у залежності від кодування)\n"
                    f"Ваше: {len(data)} байтів"
                )
                return

            pixels = list(img.getdata())
            new_pixels = []
            byte_index = 0
            bit_index = 0  # від 0 до 7

            for p in pixels:
                r, g, b = p
                channels = [r, g, b]
                for ch in range(3):
                    if byte_index < len(data):
                        # беремо поточний біт (старший біт першого байта -> позиція 7-bit_index)
                        bit = (data[byte_index] >> (7 - bit_index)) & 1
                        channels[ch] = (channels[ch] & 0xFE) | bit
                        bit_index += 1
                        if bit_index == 8:
                            bit_index = 0
                            byte_index += 1
                    # інакше залишаємо канал без змін
                new_pixels.append(tuple(channels))

            # Створюємо та зберігаємо stego-зображення
            self.stego_image = Image.new(img.mode, img.size)
            self.stego_image.putdata(new_pixels)
            self.display_stego_image()

            # статистика
            binary_str = ''.join(format(b, '08b') for b in data)
            modified_pixels = (total_bits + 2) // 3
            self.show_statistics(message, binary_str, modified_pixels, width * height)

            self.save_btn.config(state=tk.NORMAL)
            self.save_stego_btn.config(state=tk.NORMAL)
            messagebox.showinfo("Успіх", "Повідомлення успішно приховано!")

        except Exception as e:
            messagebox.showerror("Помилка", f"Помилка приховування: {str(e)}")

    def extract_message(self):
        """Надійне витягування повідомлення, яке було заховано UTF-8 байтами."""
        if not self.original_image:
            messagebox.showwarning("Увага", "Спочатку завантажте зображення")
            return

        # Переконаємось, що поле для результату існує (якщо виклик з іншого місця)
        if not hasattr(self, "result_text"):
            self.setup_extract_interface()

        try:
            img = self.original_image.copy()
            pixels = list(img.getdata())

            start_marker = self.START_MARKER.encode('utf-8')
            end_marker = self.END_MARKER.encode('utf-8')

            byte_buf = bytearray()
            curr = 0
            bits_collected = 0

            for p in pixels:
                # p має як мінімум 3 канали (R,G,B) — у нас load_image робить .convert('RGB')
                for ch in range(3):
                    bit = p[ch] & 1
                    curr = (curr << 1) | bit
                    bits_collected += 1

                    if bits_collected == 8:
                        byte_buf.append(curr & 0xFF)
                        curr = 0
                        bits_collected = 0

                        # Кожного разу, коли додаємо байт, швидко перевіряємо наявність END маркера
                        if end_marker in byte_buf:
                            # Декодуємо, і шукаємо маркери в тексті
                            try:
                                full_text = bytes(byte_buf).decode('utf-8', errors='ignore')
                            except Exception:
                                full_text = bytes(byte_buf).decode('latin-1', errors='ignore')

                            start_idx = full_text.find(self.START_MARKER)
                            end_idx = full_text.find(self.END_MARKER)

                            if start_idx != -1 and end_idx != -1 and start_idx < end_idx:
                                extracted = full_text[start_idx + len(self.START_MARKER):end_idx]

                                # Відображення результату
                                self.result_text.config(state=tk.NORMAL)
                                self.result_text.delete("1.0", tk.END)
                                self.result_text.insert("1.0", extracted)
                                self.result_text.config(state=tk.DISABLED)

                                messagebox.showinfo("Успіх",
                                                    f"Повідомлення витягнуто!\n"
                                                    f"Довжина: {len(extracted)} символів")
                                return

            # Якщо вийшли з циклу — не знайдено
            messagebox.showinfo("Результат",
                                "Приховане повідомлення не знайдено.\n"
                                "Можливо, це зображення не містить прихованих даних "
                                "або повідомлення записане іншим методом/кодовкою.")
        except Exception as e:
            messagebox.showerror("Помилка", f"Помилка витягування: {str(e)}")

    def extract_message(self):
        """Функція витягування прихованого повідомлення"""
        if not self.original_image:
            messagebox.showwarning("Увага", "Спочатку завантажте зображення")
            return

        try:
            # Крок 1: Читання пікселів
            img = self.original_image.copy()
            pixels = list(img.getdata())

            # Крок 2: Витягування бітів з молодших бітів (LSB)
            binary_message = ""
            pixel_count = 0
            max_pixels = len(pixels)

            # Розраховуємо мінімальну довжину для маркерів
            markers_length = len(self.START_MARKER + self.END_MARKER)
            min_bits = markers_length * 8

            for pixel in pixels:
                pixel_count += 1

                for channel in range(3):  # RGB канали
                    # Витягуємо молодший біт
                    binary_message += str(pixel[channel] & 1)

                # Перевіряємо кожні 8 біт після мінімальної кількості
                if len(binary_message) >= min_bits and len(binary_message) % 8 == 0:
                    try:
                        # Конвертуємо в текст
                        text = self.binary_to_text(binary_message)

                        # Крок 3: Пошук маркерів
                        if self.END_MARKER in text:
                            start_idx = text.find(self.START_MARKER)
                            end_idx = text.find(self.END_MARKER)

                            if start_idx != -1 and end_idx != -1 and start_idx < end_idx:
                                # Крок 4: Витягування повідомлення
                                extracted_message = text[start_idx + len(self.START_MARKER):end_idx]

                                # Відображення результату
                                self.result_text.config(state=tk.NORMAL)
                                self.result_text.delete("1.0", tk.END)
                                self.result_text.insert("1.0", extracted_message)
                                self.result_text.config(state=tk.DISABLED)

                                messagebox.showinfo("Успіх",
                                                    f"Повідомлення витягнуто!\n"
                                                    f"Довжина: {len(extracted_message)} символів")
                                return
                    except Exception:
                        # Продовжуємо пошук при помилках декодування
                        pass

                # Обмеження для великих зображень (перші 30% пікселів)
                if pixel_count > max_pixels * 0.3:
                    break

            # Якщо не знайдено
            messagebox.showinfo("Результат",
                                "Приховане повідомлення не знайдено.\n"
                                "Можливо, це зображення не містить прихованих даних.")

        except Exception as e:
            messagebox.showerror("Помилка", f"Помилка витягування: {str(e)}")

    def display_stego_image(self):
        if not self.stego_image:
            return

        img_copy = self.stego_image.copy()
        img_copy.thumbnail((400, 300), Image.Resampling.LANCZOS)
        photo = ImageTk.PhotoImage(img_copy)

        self.stego_canvas.delete("all")
        self.stego_canvas.image = photo
        self.stego_canvas.create_image(200, 150, image=photo)

    def show_statistics(self, message, binary, modified_pixels, total_pixels):
        """Відображення статистики приховування"""
        self.stats_frame.pack(fill=tk.X, pady=(15, 0))

        percentage = (modified_pixels / total_pixels) * 100

        stats_text = f"📊 Статистика приховування:\n\n"
        stats_text += f"• Довжина повідомлення: {len(message)} символів\n"
        stats_text += f"• Двійковий код: {len(binary)} біт\n"
        stats_text += f"• Модифіковано пікселів: {modified_pixels} з {total_pixels}\n"
        stats_text += f"• Відсоток змін: {percentage:.4f}%\n"
        stats_text += f"• Розмір зображення: {self.original_image.size[0]}x{self.original_image.size[1]}"

        self.stats_label.config(text=stats_text)
        self.stats_label.pack(padx=10, pady=10)

    def save_image(self):
        """Збереження стегоконтейнера"""
        if not self.stego_image:
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG files", "*.png"), ("All files", "*.*")],
            initialfile="stego_image"
        )

        if file_path:
            try:
                self.stego_image.save(file_path, "PNG")
                messagebox.showinfo("Успіх", "Стегоконтейнер збережено!")
            except Exception as e:
                messagebox.showerror("Помилка", f"Помилка збереження: {str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()