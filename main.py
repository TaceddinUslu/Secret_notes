import tkinter
from tkinter import *
from PIL import ImageTk, Image
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os
import tkinter.messagebox

window = tkinter.Tk()
window.title("secretNotes")
window.minsize(400,700)

def User_interface():
    def derive_key(password: str) -> bytes:
        password = password.encode()
        salt = b'some_salt_value'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key



    def image_secret():
        global img
        img = Image.open("pngwing.com.png")
        img = img.resize((100, 100), Image.LANCZOS)
        img = ImageTk.PhotoImage(img)
        panel = Label(window, image=img)
        panel.pack(side="top", anchor="center", fill="both", expand="yes")
        panel.place(x=150, y=15)
    image_secret()

    # communicate with files
    def save_data():
        title = enter_entry.get()
        enterText = enter_text.get("1.0", END).replace("\n", " ")

        # Load the key from the file
        key = derive_key(key_entry.get())

        # Encrypt the data
        fernet = Fernet(key)

        enterText_encrypted = fernet.encrypt(enterText.encode())

        with open("secret_notes.txt", "a") as f:
            f.write(title + "\n")
            f.write(enterText_encrypted.decode() + "\n")



    #clear for file

    def clear_file(file_name):
            with open(file_name, "w"):
                pass

    #clear_file("secret_notes.txt")

    def decrypt_data():
        key = derive_key(key_entry.get())
        fernet = Fernet(key)
        token = enter_text.get("1.0", END).strip()
        try:
            decrypted_text = fernet.decrypt(token.encode()).decode()
            enter_text.delete("1.0", END)
            enter_text.insert(END, decrypted_text)
        except InvalidToken:
            tkinter.messagebox.showerror("Error", "please make sure of encrypted info or password")

    #space
    space = tkinter.Label(text="")
    space.pack(pady=60)


    #title
    enter_title = tkinter.Label(text="Enter your title", font=("arial", 15))
    enter_title.pack()


    #entry

    enter_entry = tkinter.Entry(width=35)
    enter_entry.pack(pady=15)

    #title2
    enter_title = tkinter.Label(text="Enter your secret", font=("arial", 15))
    enter_title.pack()

    #text
    enter_text = tkinter.Text(height=10, width=40)
    enter_text.pack(pady=15)

    #title3
    enter_title = tkinter.Label(text="Enter master key", font=("arial", 15))
    enter_title.pack()

    #entry

    key_entry = tkinter.Entry(width=35)
    key_entry.pack(pady=15)

    #button_save

    button_save = tkinter.Button(text="Save & Encrypt", command=save_data)
    button_save.pack(pady=5)

    #button_save

    button_decrypt =  tkinter.Button(text="Decrypt", command=decrypt_data)
    button_decrypt.pack(pady=5)




User_interface()
window.mainloop()