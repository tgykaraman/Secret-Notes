from tkinter import *
from PIL import Image, ImageTk
from cryptography.fernet import Fernet
import base64

#Screen configuration
window = Tk()
window.title("Secret Notes")
window.config(padx=50, pady=50)

#Upload Image
logo = Image.open("top secret.png")
logo = logo.resize((100, 100))
logo = ImageTk.PhotoImage(logo)
logo_label = Label(window, image=logo)
logo_label.pack()
logo_label.config()

#Logo ve girdiler arasında boşluk bırakma
space_label = Label()
space_label.config(padx=20, pady=20)
space_label.pack()

result_label=Label(text="")

def blankControl():
    if title_entry.get() == "":
        return "Please enter your title"
    elif masterKey_entry.get() == "":
        return "Please enter your master key"
    elif secret_text.get(1.0, END) == "":
        return "Please enter your secret text"
    elif title_entry.get() == "" and masterKey_entry.get() == "":
        return "Please enter your title and master key"
    elif title_entry.get() == "" and secret_text.get(1.0, END) == "":
        return "Please enter your title and your secret text"
    elif masterKey_entry.get() == "" and secret_text.get(1.0, END) == "":
        return "Please enter your master key and secret text"
    elif masterKey_entry.get() == "" and secret_text.get(1.0, END) == "" and title_entry.get() == "":
        return "Any of master key, title and secret text couldn't be blank"
    else:
        return "Succeed"

def encodeMessage():
    #Kullanıcının boş bırakıp bırakmadığını kontrol etme
    blankControl()
    user_key = masterKey_entry.get()
    user_key_bytes = user_key.encode()
    base64_key = base64.urlsafe_b64encode(user_key_bytes.ljust(32)[:32])
    cipher_suite = Fernet(base64_key)
    message = secret_text.get(1.0, END).encode()
    encrypt_message = cipher_suite.encrypt(message)
    with open("myFile.txt", mode="a") as file:
        file.write("\n")
    with open("myFile.txt",mode="a") as file:
        file.write(title_entry.get())
    with open("myFile.txt", mode="a") as file:
        file.write("\n")
    with open("myFile.txt",mode="a") as file:
        file.write(encrypt_message.decode())
    result_label.config(text=blankControl())
    title_entry.delete(0, END)
    secret_text.delete("1.0", END)
    masterKey_entry.delete(0, END)

def decodeMessage():
    try:
        user_key = masterKey_entry.get()
        user_key_bytes = user_key.encode()
        base64_key = base64.urlsafe_b64encode(user_key_bytes.ljust(32)[:32])
        cipher_suite = Fernet(base64_key)
        message = secret_text.get(1.0, END).encode()
        decrypted_message = cipher_suite.decrypt(message)
        secret_text.delete("1.0", END)
        masterKey_entry.delete(0, END)
        result_label.config(text=decrypted_message.decode())

    except:
        result_label.config(text="Şifrelenmiş mesajınızı ve master key'i belirtin")


title_label = Label(text="Enter your title")
title_label.pack()
title_entry = Entry(width=20)
title_entry.config()
title_entry.pack()

secret_label = Label(text="Enter your secret")
secret_label.pack()
secret_text = Text(width=30, height=20)
secret_text.pack()

masterKey_label = Label(text="Enter master key")
masterKey_label.pack()
masterKey_entry = Entry(width=20)
masterKey_entry.pack()

save_button = Button(text="Save & Encrypt", command=encodeMessage)
save_button.pack()
decrypt_button = Button(text="Decrypt", command=decodeMessage)
decrypt_button.pack()
result_label.pack()

window.mainloop()
