import tkinter as tk
from tkinter import ttk
from tkinter import filedialog, messagebox
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
import datetime
import os  # Импортируем модуль os для работы с файлами

class CertificateApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Генератор Сертификатов")
        self.root.geometry("400x400")
          
          
        self.root.config(bg='lightblue')
        
        self.create_inputs()

        self.generate_certificate_button = ttk.Button(root, text="Создать Сертификат", command=self.generate_certificate, style="Primary.TButton")
        self.generate_certificate_button.place(x=7, y=250)

        self.generate_signature_button = ttk.Button(root, text="Создать Цифровую Подпись", command=self.generate_signature, style="Secondary.TButton")
        self.generate_signature_button.place(x=175, y=250)
        
        self.open_certificate_button = ttk.Button(root, text="Открыть Сертификат", command=self.open_certificate, style="Quaternary.TButton")
        self.open_certificate_button.place(x=7, y=300)
        
        self.generate_private_key_button = ttk.Button(root, text="Создать Закрытый Ключ", command=self.generate_private_key, style="Tertiary.TButton")
        self.generate_private_key_button.place(x=175, y=300)

        

        self.style = ttk.Style()
        self.style.configure("Primary.TButton", foreground="blue", background="blue", font=("Helvetica", 12))
        self.style.configure("Secondary.TButton", foreground="green", background="green", font=("Helvetica", 12))
        self.style.configure("Tertiary.TButton", foreground="red", background="red", font=("Helvetica", 12))
        self.style.configure("Quaternary.TButton", foreground="purple", background="purple", font=("Helvetica", 12))
        
        self.style.configure("TEntry", foreground="green", background="blue")
    def create_inputs(self):
        self.inputs = {}

        labels = [
            "Страна (C):",
            "Область (ST):",
            "Населенный пункт (L):",
            "Организация (O):",
            "Подразделение (OU):",
            "Общее Имя (CN):",
            "Адрес электронной почты (EMAIL):",
            "Название сертификата:"
        ]

        for label_text in labels:
            label_frame = ttk.Frame(self.root)
            label_frame.pack(fill="x", padx=10, pady=(5, 0))

            label = ttk.Label(label_frame, text=label_text)
            label.pack(side="left", padx=(0, 10))

            input_var = tk.StringVar()
            input_entry = ttk.Entry(label_frame, textvariable=input_var, width=30)
            input_entry.pack(side="right")

            # Используйте первую часть текста метки (до двоеточия) в качестве ключа, кроме названия сертификата
            key = label_text.split(":")[0].strip()
            if key == "Название сертификата":
                key = "certificate_name"
            self.inputs[key] = input_var

    def generate_certificate(self):
        # Получаем название сертификата от пользователя
        certificate_name = self.inputs["certificate_name"].get()

        subject_attributes = [
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, self.inputs["Страна (C)"].get()),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, self.inputs["Область (ST)"].get()),
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, self.inputs["Населенный пункт (L)"].get()),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, self.inputs["Организация (O)"].get()),
            x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, self.inputs["Подразделение (OU)"].get()),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, self.inputs["Общее Имя (CN)"].get()),
            x509.NameAttribute(x509.NameOID.EMAIL_ADDRESS, self.inputs["Адрес электронной почты (EMAIL)"].get())
        ]

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        subject = x509.Name(subject_attributes)
        csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(
            private_key, hashes.SHA256(), default_backend()
        )

        issuer = subject
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now())
            .not_valid_after(datetime.datetime(2025, 3, 15))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        )

        certificate = builder.sign(
            private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend()
        )

        # Используем введенное название сертификата для именования файлов
        cert_file_name = certificate_name + ".crt"
        key_file_name = certificate_name + ".key"

        cert_bytes = certificate.public_bytes(serialization.Encoding.PEM)
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        with open(cert_file_name, "wb") as cert_file:
            cert_file.write(cert_bytes)

        with open(key_file_name, "wb") as key_file:
            key_file.write(private_key_bytes)

        print(f"Сертификат и закрытый ключ успешно созданы: {cert_file_name}, {key_file_name}")

    def generate_signature(self):
        message = b"Hello, World!"
        with open("private_key.key", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
         )
        
        with open("signature.pem", "wb") as signature_file:
            signature_file.write(signature)
        print("Цифровая подпись успешно создана.")

    def generate_private_key(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open("private_key.key", "wb") as key_file:
            key_file.write(private_key_bytes)
        print("Закрытый ключ успешно создан.")

    def open_certificate(self):
        # Получаем название сертификата от пользователя
        certificate_name = self.inputs["certificate_name"].get()
        
        # Имя файла сертификата, который нужно открыть
        cert_file_name = certificate_name + ".crt"

        # Проверяем, существует ли файл сертификата
        if os.path.exists(cert_file_name):
            # Открываем файл сертификата
            os.startfile(cert_file_name)
        else:
            messagebox.showerror("Ошибка", f"Файл сертификата '{cert_file_name}' не найден.")

if __name__ == "__main__":
    root = tk.Tk()
    app = CertificateApp(root)
    root.mainloop()
