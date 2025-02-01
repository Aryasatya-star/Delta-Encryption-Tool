import os
import base64 as bs64
import customtkinter as ctk
from tkinter import filedialog as fd, messagebox as msgbox, simpledialog as d

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB

class Base32:
    @staticmethod
    def encode(data: bytes) -> bytes:
        return bs64.b32encode(data)

    @staticmethod
    def decode(data: bytes) -> bytes:
        return bs64.b32decode(data)

class Base64:
    @staticmethod
    def encode(data: bytes) -> bytes:
        return bs64.b64encode(data)

    @staticmethod
    def decode(data: bytes) -> bytes:
        return bs64.b64decode(data)

class Base128:
    @staticmethod
    def encode(data: bytes) -> str:
        encoded = []
        data = bs64.b16encode(bs64.b85encode(data))
        for byte in data:
            high = byte >> 1
            low = byte & 0x01
            encoded.append(high)
            encoded.append(low)
        return ' '.join(map(str, encoded))

    @staticmethod
    def decode(data: str) -> bytes:
        data_list = list(map(int, data.split()))
        if len(data_list) % 2 != 0:
            raise ValueError("Input length must be even.")

        decoded = bytearray()
        for i in range(0, len(data_list), 2):
            high = data_list[i] << 1
            low = data_list[i + 1]
            decoded.append(high | low)

        decoded = bs64.b85decode(bs64.b16decode(bytes(decoded)))
        return decoded

def show_message(title, message):
    dialog = ctk.CTkToplevel(app)
    dialog.title(title)
    dialog.geometry("400x200")
    dialog.resizable(False, False)
    dialog.attributes('-topmost', True)
    
    text_box = ctk.CTkTextbox(dialog, width=350, height=350)
    text_box.pack(pady=10)
    text_box.insert("1.0", message)
    text_box.configure(state="disabled")  

    close_button = ctk.CTkButton(dialog, text="Close", command=dialog.destroy)
    close_button.pack(pady=10)

def browse_file():
    file_path = fd.askopenfilename(title="Select File")
    if file_path:
        entry_filepath.delete(0, ctk.END)
        entry_filepath.insert(0, file_path)

def show_done(label):
    label.configure(text="Done!", text_color="#28A745")
    label.after(1000, lambda: label.grid_forget())
    label.after(1000, lambda: app.geometry("850x400"))

def start_encryption():
    file_path = entry_filepath.get()
    if not os.path.isfile(file_path):
        msgbox.showerror("Error", "File not found. Please select a valid file.")
        return

    file_size = os.path.getsize(file_path)
    if file_size > MAX_FILE_SIZE:
        msgbox.showerror("Error", f"File size exceeds the maximum limit of {MAX_FILE_SIZE // (1024 * 1024)} MB.")
        return

    app.geometry("850x410")
    please_wait_label_encrypt.configure(text="Please wait...", text_color="orange")
    please_wait_label_encrypt.grid(row=3, column=0, columnspan=3, pady=10)
    app.update()

    try:
        password = None
        has_password = False
        password_segment = ""

        if pw_var.get():
            password = d.askstring("", "Please create a password: ")
            if password:
                has_password = True
                password_segment = Base64.encode(password.encode()).decode()
            else:
                has_password = False
        else:
            has_password = False

        with open(file_path, 'rb') as f:
            data = f.read()

        selected = selected_phase.get()
        if selected == "Low Level":
            final = Base128.encode(data)
            phase = 1
        elif selected == "High Level":
            final = Base64.encode(Base32.encode(Base128.encode(Base64.encode(Base128.encode(data).encode()).decode().encode()).encode()).decode().encode()).decode()
            phase = 5

        file_name, file_extension = os.path.splitext(os.path.basename(file_path))
        key = f"{phase}:{Base64.encode(file_extension.encode()).decode()}:{has_password}:{password_segment}"
        encrypted_key = Base64.encode(key.encode()).decode()

        encrypted_file = file_name + ".enc"
        with open(encrypted_file, 'w', encoding="utf-8") as f:
            f.write(final)

        os.remove(file_path)

        entry_filepath.delete("0", "end")
        pw_var.set(False)

        show_done(please_wait_label_encrypt)
        app.after(2000, show_done, please_wait_label_encrypt)
        if msgbox.askyesno("Success", f"File encrypted successfully!\n\nDo you want to create backup key file?"):
            with open("key.txt", 'w', encoding="utf-8") as f:
                f.write(f"key: {encrypted_key}\npassword: {password}")
                msgbox.showinfo("Done", f"Your backup key file is in:\n{os.path.abspath("key.txt")}")
        else:
            show_message("", f"Your key is: {encrypted_key}\nYour password is: {password}\n\n\nPLEASE DO NOT LOSE IT")

    except Exception as e:
        please_wait_label_encrypt.grid_forget()
        msgbox.showerror("Error", f"An error occurred: {e}")

def browse_enc_file():
    file_path = fd.askopenfilename(title="Select Encrypted File", filetypes=[("Encrypted Files", "*.enc")])
    if file_path:
        entry_enc_filepath.delete(0, ctk.END)
        entry_enc_filepath.insert(0, file_path)

def start_decryption():
    enc_file_path = entry_enc_filepath.get()

    if not os.path.isfile(enc_file_path):
        msgbox.showerror("Error", "Encrypted file not found. Please select a valid .enc file.")
        return

    app.geometry("850x410")
    please_wait_label_decrypt.configure(text="Please wait...", text_color="orange")
    please_wait_label_decrypt.grid(row=2, column=0, columnspan=3, pady=10)
    app.update()

    try:
        encrypted_key = entry_key.get()
        if not encrypted_key:
            msgbox.showerror("Error", "Decryption key is required.")
            return

        try:
            key = Base64.decode(encrypted_key.encode()).decode()
            phase, file_extension_encoded, has_password, password_segment = key.split(":")
            phase = int(phase)
            file_extension = Base64.decode(file_extension_encoded.encode()).decode()
            has_password = has_password == "True"
        except ValueError:
            raise ValueError("Invalid decryption key format.")

        if has_password:
            user_password = d.askstring("", "Please insert the password: ")
            if not user_password:
                msgbox.showerror("Error", "Password is required to decrypt the file.")
                return

            decoded_password = Base64.decode(password_segment.encode()).decode()
            if user_password != decoded_password:
                msgbox.showerror("Error", "Incorrect password. Decryption failed.")
                return

        with open(enc_file_path, 'r', encoding="utf-8") as f:
            data = f.read()

        if phase == 1:
            final = Base128.decode(data)
        elif phase == 5:
            final = Base128.decode(Base64.decode(Base128.decode(Base32.decode(Base64.decode(data).decode())).decode()))

        original_file_path = os.path.splitext(enc_file_path)[0] + file_extension
        with open(original_file_path, 'wb') as f:
            f.write(final)

        os.remove(enc_file_path)

        entry_enc_filepath.delete("0", "end")
        entry_key.delete("0", "end")

        show_done(please_wait_label_decrypt)
        app.after(2000, show_done, please_wait_label_encrypt)
        msgbox.showinfo("Success", f"File decrypted successfully!\nYour file is saved as '{original_file_path}'")

    except Exception as e:
        please_wait_label_decrypt.grid_forget()
        msgbox.showerror("Error", f"An error occurred: {e}")

app = ctk.CTk()
app.title("DeltaEncryption Tool")
app.geometry("850x400")
app.resizable(False, False)

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("green")

tab_view = ctk.CTkTabview(app)
tab_view.pack(expand=True, fill="both")

encrypt_tab = tab_view.add("Encrypt")
decrypt_tab = tab_view.add("Decrypt")

header_frame_encrypt = ctk.CTkFrame(encrypt_tab)
header_frame_encrypt.pack(pady=10, fill="x")

logo_encrypt = ctk.CTkLabel(header_frame_encrypt, text="🔒 DeltaEncryption Tool - Encrypt", font=("Consolas", 20))
logo_encrypt.pack(pady=10)

frame_encrypt = ctk.CTkFrame(encrypt_tab, corner_radius=15)
frame_encrypt.pack(pady=20, padx=20, expand=True)

label_filepath = ctk.CTkLabel(frame_encrypt, text="Select File:", font=("Consolas", 15))
label_filepath.grid(row=0, column=0, padx=10, pady=10, sticky="e")

entry_filepath = ctk.CTkEntry(frame_encrypt, width=350)
entry_filepath.grid(row=0, column=1, padx=10, pady=10)

button_browse = ctk.CTkButton(frame_encrypt, text="Browse", command=browse_file, fg_color="#007BFB", hover_color="#009BFB")
button_browse.grid(row=0, column=2, padx=10, pady=10)

phases = ["Low Level", "High Level"]
selected_phase = ctk.StringVar(value="Select Phase")

phase_menu = ctk.CTkOptionMenu(encrypt_tab, values=phases, variable=selected_phase)
phase_menu.pack(pady=10)

please_wait_label_encrypt = ctk.CTkLabel(frame_encrypt, text="Please wait...", font=("Consolas", 18), text_color="orange")
please_wait_label_encrypt.grid(row=3, column=0, columnspan=3, pady=10)
please_wait_label_encrypt.grid_forget() 

action_frame_encrypt = ctk.CTkFrame(encrypt_tab, corner_radius=15)
action_frame_encrypt.pack(pady=20)

button_encrypt = ctk.CTkButton(action_frame_encrypt, text="🔐 Encrypt Now!", command=start_encryption, fg_color="#28A745", hover_color="#218838")
button_encrypt.pack(side="left", padx=10)

pw_var = ctk.BooleanVar(value=False)

pw_checkbutton = ctk.CTkCheckBox(action_frame_encrypt, text="Enable Password", variable=pw_var, checkmark_color="#FFF", hover_color="#DC3545", fg_color="#C82333")
pw_checkbutton.pack(side="left", padx=20)

header_frame_decrypt = ctk.CTkFrame(decrypt_tab)
header_frame_decrypt.pack(pady=10, fill="x")

logo_decrypt = ctk.CTkLabel(header_frame_decrypt, text="🔓 DeltaEncryption Tool - Decrypt", font=("Consolas", 20))
logo_decrypt.pack(pady=10)

frame_decrypt = ctk.CTkFrame(decrypt_tab, corner_radius=15)
frame_decrypt.pack(pady=20, padx=20, fill="x", expand=True)

label_enc_filepath = ctk.CTkLabel(frame_decrypt, text="Select Encrypted File (.enc):", font=("Consolas", 15))
label_enc_filepath.grid(row=0, column=0, padx=10, pady=10, sticky="w")

entry_enc_filepath = ctk.CTkEntry(frame_decrypt, width=350)
entry_enc_filepath.grid(row=0, column=1, padx=10, pady=10)

button_browse_enc = ctk.CTkButton(frame_decrypt, text="Browse", command=browse_enc_file, fg_color="#007BFF")
button_browse_enc.grid(row=0, column=2, padx=10, pady=10)

label_key = ctk.CTkLabel(frame_decrypt, text="Insert the key here: ", font=("Consolas", 15))
label_key.grid(row=1, column=0, padx=10, pady=10, sticky="w")

entry_key = ctk.CTkEntry(frame_decrypt, width=350)
entry_key.grid(row=1, column=1, padx=10, pady=10)

please_wait_label_decrypt = ctk.CTkLabel(frame_decrypt, text="Please wait...", font=("Consolas", 18), text_color="orange")
please_wait_label_decrypt.grid(row=2, column=0, columnspan=3, pady=10)
please_wait_label_decrypt.grid_forget()

button_decrypt = ctk.CTkButton(decrypt_tab, text="🔓 Decrypt Now!", command=start_decryption, fg_color="#DC3545", hover_color="#C82333")
button_decrypt.pack(pady=20)

footer = ctk.CTkLabel(app, text="© 2024 Delta Studios | All Rights Reserved", font=("Consolas", 14))
footer.pack(side="bottom", pady=10)

#@ ------------------------------------------------------ RUN THE PROGRAM ------------------------------------------------------

app.mainloop()