import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
import base64

# Генерація AES ключа та IV
def generate_key_iv(output_dir):
    key = os.urandom(32)
    iv = os.urandom(16)
    key_path = os.path.join(output_dir, "key.txt")
    with open(key_path, "w") as key_file:
        key_file.write(f"key: {base64.b64encode(key).decode()}\nIV: {base64.b64encode(iv).decode()}")
    return key, iv, key_path

# AES Шифрування
def encrypt_file(input_file, key, iv):
    with open(input_file, "rb") as f:
        plaintext = f.read()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padding_length = 16 - (len(plaintext) % 16)
    plaintext += bytes([padding_length] * padding_length)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(ciphertext)
    mac = h.finalize()
    output_file = f"{input_file}.enc"
    with open(output_file, "wb") as f:
        f.write(ciphertext + mac)
    messagebox.showinfo("Шифрування", f"Файл зашифровано та збережено як {output_file}")

# AES Дешифрування
def decrypt_file(input_file, key, iv):
    try:
        with open(input_file, "rb") as f:
            data = f.read()
        ciphertext, received_mac = data[:-32], data[-32:]
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(ciphertext)
        h.verify(received_mac)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        padding_length = plaintext[-1]
        plaintext = plaintext[:-padding_length]
        output_file = input_file.replace(".enc", "_decrypted.txt")
        with open(output_file, "wb") as f:
            f.write(plaintext)
        messagebox.showinfo("Дешифрування", f"Файл дешифровано та збережено як {output_file}")
    except Exception as e:
        messagebox.showerror("Помилка", f"Дешифрування не вдалося: {str(e)}. Будь ласка, перевірте ключ та IV.")

# Генерація пари RSA ключів
def generate_rsa_keys(output_dir):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()

    private_key_path = os.path.join(output_dir, "private_key.pem")
    with open(private_key_path, "wb") as private_file:
        private_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    public_key_path = os.path.join(output_dir, "public_key.pem")
    with open(public_key_path, "wb") as public_file:
        public_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return private_key, public_key, private_key_path, public_key_path

# RSA Шифрування
def encrypt_with_rsa(input_file, public_key):
    with open(input_file, "rb") as f:
        plaintext = f.read()
    ciphertext = public_key.encrypt(plaintext, padding.PKCS1v15())
    output_file = f"{input_file}.rsa_enc"
    with open(output_file, "wb") as f:
        f.write(ciphertext)
    messagebox.showinfo("RSA Шифрування", f"Файл зашифровано за допомогою RSA та збережено як {output_file}")

# RSA Дешифрування
def decrypt_with_rsa(input_file, private_key):
    try:
        with open(input_file, "rb") as f:
            ciphertext = f.read()
        plaintext = private_key.decrypt(ciphertext, padding.PKCS1v15())
        output_file = input_file.replace(".rsa_enc", "_rsa_decrypted.txt")
        with open(output_file, "wb") as f:
            f.write(plaintext)
        messagebox.showinfo("RSA Дешифрування", f"Файл дешифровано за допомогою RSA та збережено як {output_file}")
    except Exception as e:
        messagebox.showerror("Помилка", f"RSA дешифрування не вдалося: {str(e)}")

# Цифровий підпис RSA
def sign_file(input_file, private_key):
    with open(input_file, "rb") as f:
        data = f.read()
    signature = private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    signature_file = f"{input_file}.sig"
    with open(signature_file, "wb") as f:
        f.write(signature)
    messagebox.showinfo("Підпис", f"Цифровий підпис збережено як {signature_file}")

# Перевірка підпису RSA
def verify_signature(input_file, signature_file, public_key):
    try:
        with open(input_file, "rb") as f:
            data = f.read()
        with open(signature_file, "rb") as f:
            signature = f.read()
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        messagebox.showinfo("Перевірка підпису", "Підпис є дійсним.")
    except Exception as e:
        messagebox.showerror("Помилка", f"Перевірка підпису не вдалася: {str(e)}")

# Графічний інтерфейс
def create_gui():
    def encrypt_action():
        input_file = filedialog.askopenfilename(title="Виберіть файл для шифрування")
        if input_file:
            output_dir = os.path.dirname(input_file)
            key, iv, key_path = generate_key_iv(output_dir)
            encrypt_file(input_file, key, iv)
            messagebox.showinfo("Ключ та IV", f"Ключ та IV збережено у {key_path}")

    def decrypt_action():
        input_file = filedialog.askopenfilename(title="Виберіть файл для дешифрування")
        key = key_entry.get()
        iv = iv_entry.get()

        # Перевірка на порожні поля для ключа та IV
        if not key or not iv:
            messagebox.showerror("Помилка", "Поле Ключа або IV не може бути порожнім!")
            return

        try:
            key = base64.b64decode(key)
            iv = base64.b64decode(iv)
            if input_file and key and iv:
                decrypt_file(input_file, key, iv)
        except Exception as e:
            messagebox.showerror("Помилка", f"Неправильний формат ключа або IV: {str(e)}")

    def generate_rsa_action():
        output_dir = filedialog.askdirectory(title="Виберіть директорію для збереження RSA ключів")
        if output_dir:
            private_key, public_key, private_key_path, public_key_path = generate_rsa_keys(output_dir)
            messagebox.showinfo("RSA Ключі", f"Приватний ключ збережено у {private_key_path}\nПублічний ключ збережено у {public_key_path}")

    def rsa_encrypt_action():
        input_file = filedialog.askopenfilename(title="Виберіть файл для шифрування RSA")
        public_key_path = filedialog.askopenfilename(title="Виберіть публічний ключ")
        with open(public_key_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
        encrypt_with_rsa(input_file, public_key)

    def rsa_decrypt_action():
        input_file = filedialog.askopenfilename(title="Виберіть файл для дешифрування RSA")
        private_key_path = filedialog.askopenfilename(title="Виберіть приватний ключ")
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
        decrypt_with_rsa(input_file, private_key)

    def sign_action():
        input_file = filedialog.askopenfilename(title="Виберіть файл для підпису")
        private_key_path = filedialog.askopenfilename(title="Виберіть приватний ключ для підпису")
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
        sign_file(input_file, private_key)

    def verify_signature_action():
        input_file = filedialog.askopenfilename(title="Виберіть файл для перевірки підпису")
        signature_file = filedialog.askopenfilename(title="Виберіть файл підпису")
        public_key_path = filedialog.askopenfilename(title="Виберіть публічний ключ для перевірки")
        with open(public_key_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
        verify_signature(input_file, signature_file, public_key)

    root = tk.Tk()
    root.title("AES & RSA Шифрування/Дешифрування")

    tk.Button(root, text="Зашифрувати файл (AES)", command=encrypt_action).pack(pady=5)
    tk.Button(root, text="Дешифрувати файл (AES)", command=decrypt_action).pack(pady=5)
    
    # Поле для введення ключа
    tk.Label(root, text="Ключ:").pack()
    key_entry = tk.Entry(root, width=35, show="*")
    key_entry.pack(pady=2)
    # Поле для введення IV
    tk.Label(root, text="IV:").pack()
    iv_entry = tk.Entry(root, width=35)
    iv_entry.pack(pady=2)

    tk.Button(root, text="Генерувати RSA ключі", command=generate_rsa_action).pack(pady=5)
    tk.Button(root, text="Зашифрувати за допомогою RSA", command=rsa_encrypt_action).pack(pady=5)
    tk.Button(root, text="Дешифрувати за допомогою RSA", command=rsa_decrypt_action).pack(pady=5)
    tk.Button(root, text="Підписати файл", command=sign_action).pack(pady=5)
    tk.Button(root, text="Перевірка підпису", command=verify_signature_action).pack(pady=5)

    root.mainloop()

create_gui()
