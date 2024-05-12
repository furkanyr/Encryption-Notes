import tkinter
from tkinter import messagebox
import base64


def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


screen = tkinter.Tk()
screen.title("Secret Notes")
screen.minsize(300, 420)
screen.resizable(False, False)


def encrypt_message():
    title = title_entry.get()
    password = key_entry.get()
    message = text_area.get(1.0, tkinter.END)

    if len(title) == 0 or len(message) == 0 or len(password) == 0:
        messagebox.showinfo(title="ERROR!", message="Please fill in the relevant fields completely!")
    else:
        encrypted_message = encode(password, message)

        with open("Notes.txt", "a") as dosya:
            dosya.write(f"{title}\n{encrypted_message}\n")
        
        title_entry.delete(0, tkinter.END)
        text_area.delete(1.0, tkinter.END)
        key_entry.delete(0, tkinter.END)


def decrypt_message():
    password = key_entry.get()
    encrypted_message = text_area.get(1.0, tkinter.END)

    if len(encrypted_message) == 0 or len(password) == 0:
        messagebox.showinfo(title="ERROR!", message="The cipher text and password must be entered completely!")
    else:
        try:
            decrypted_message = decode(password, encrypted_message)
            text_area.delete(1.0, tkinter.END)
            text_area.insert(1.0, decrypted_message)
        except:
            messagebox.showerror(title="ERROR!", message="Please enter the relevant information correctly!")


photo = tkinter.PhotoImage(file="icon.png")
photo_label = tkinter.Label(image=photo, width=100, height=100)
photo_label.pack(pady=20)
title_label = tkinter.Label(text="- Enter Title -")
title_entry = tkinter.Entry(width=40)
text_label = tkinter.Label(text="- Enter Notes -")
text_area = tkinter.Text(width=30, height=15)
key_label = tkinter.Label(text="- Enter Key -")
key_entry = tkinter.Entry(width=40)
encrypt_button = tkinter.Button(text="Save & Encrypt", width=13, command=encrypt_message)
decrypt_button = tkinter.Button(text="Decrypt", width=13, command=decrypt_message)

title_label.pack()
title_entry.pack()
text_label.pack()
text_area.pack()
key_label.pack()
key_entry.pack()
encrypt_button.pack(pady=3)
decrypt_button.pack(pady=3)

screen.mainloop()