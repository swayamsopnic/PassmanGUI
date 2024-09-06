from tkinter import *
import tkinter as tk
import csv
from tkinter import ttk
from tkinter import messagebox
import hashlib
import requests
import secrets
import string
import re
from tkinter import Tk, Label, Entry, Button, messagebox, LEFT, END
from cryptography.fernet import Fernet, InvalidToken
import base64
import binascii
import os


# Function to generate a key and save it into a file
def generate_key(file_path="encryption_key.key"):
    key = Fernet.generate_key()
    with open(file_path, "wb") as key_file:
        key_file.write(key)
    return key

# Function to load the key from the file
def load_key(file_path="encryption_key.key"):
    if not os.path.exists(file_path):
        # If the key file doesn't exist, generate a new key
        return generate_key(file_path)
    with open(file_path, "rb") as key_file:
        return key_file.read()

# Load the key (generate if it doesn't exist)
key = load_key()
cipher = Fernet(key)

# Encryption and Decryption functions
def encrypt_data(data):
    return base64.urlsafe_b64encode(cipher.encrypt(data.encode())).decode()

def decrypt_data(data):
    try:
        decoded_data = binascii.a2b_base64(data.encode())
        cipher = Fernet(key)  # Assuming 'key' is already defined in your code
        return cipher.decrypt(decoded_data).decode()
    except (binascii.Error, ValueError, InvalidToken) as e:
        return f"Decryption failed: {str(e)}"
    





wn=Tk()
wn.protocol("WM_DELETE_WINDOW",'pass')
wn.geometry("1024x768")
wn.title("Login Screen")

img = PhotoImage(file="C:\\Users\\ANUBIS\\Documents\\cyber sec\\Password Manager\\PassMan GUI\\passimg.png")
label = Label(wn,image=img).place(x=0,y=0)
def loginuid():
   f = open("C:\\Users\\ANUBIS\\Documents\\cyber sec\\Password Manager\\PassMan GUI\\uinfo.txt",'r')
   i = f.readline()
   k = i.split()
   uidog = k[0]
   pwdog = k[1]    
   
   uid=userid.get()
   pw=pwd.get()
   data_to_hash = pwd.get()
   hash_algorithm = hashlib.sha256()
   hash_algorithm.update(data_to_hash.encode('utf-8'))
   pw = hash_algorithm.hexdigest()
   if uid!=uidog :
      messagebox.askretrycancel("showinfo", "Username mismatch")
      userid.delete(0,END)
   elif pw!=pwdog:
      messagebox.askretrycancel("showinfo", "Password mismatch")
      pwd.delete(0,END)   
   else:
      messagebox.showinfo("Information","Success")
      wn.destroy()















label1=Label(wn,text="Uid           :",height=1,font=(12),justify= LEFT).place(x=300,y=420)
label2=Label(wn,text="Password :",height=1,font=(12),justify= LEFT).place(x=300,y=450)

userid=Entry(wn, width=20,font=(12))
userid.place(x=420,y=420)

pwd=Entry(wn,width=20,font=(12),show='*')
pwd.place(x=420,y=450)

lgn=Button(wn, text="Login",cursor='hand2',font=(12),command=loginuid)
lgn.place(x=680, y=425)
wn.mainloop()

root = Tk()
root.geometry("1024x768")

root.title("PassMan")
img = PhotoImage(file="C:\\Users\\ANUBIS\\Documents\\cyber sec\\Password Manager\\PassMan GUI\\passimg.png")
label = Label(root,image=img).place(x=0,y=0)


txt_output = Text(root, height=15, width=162 ,font=('Arial', 12),foreground='Black')
#txt_output.place(x=124,y=90)
#widget.pack_forget()

#issue book to teacher *************************



















def get_domain_report():
   window=Tk()
   window.title("Domain Check")
   window.geometry("512x512")
   def display_report(report_data):
      new_window = Tk()
      new_window.title("Domain Report")
      new_window.geometry("600x400")

      report_text = Text(new_window, height=20, width=60, font=("Arial", 12))
      report_text.pack()

      report_text.insert(INSERT, "Domain Report For:\n")
      report_text.insert(INSERT, domain.get())
      report_text.insert(INSERT, "\n")
      report_text.insert(INSERT, "Last Analysis Results:\n\n")

      for engine, result in report_data.items():
         report_text.insert(
               INSERT, f"Engine: {engine}\nCategory: {result['category']}\n"
         )
         report_text.insert(INSERT, f"Result: {result['result']}\n")
         report_text.insert(INSERT, f"Method: {result['method']}\n")
         report_text.insert(INSERT, f"Engine Name: {result['engine_name']}\n\n")

      new_window.mainloop()
   
   def Search():
      
      
      if (domain.get()==''):
         messagebox.showinfo("Information","All fields are mandatory")
         window.destroy()
         
         return
      
      url = f"https://www.virustotal.com/api/v3/domains/{domain.get()}"
      headers = {"x-apikey": 'a3e661ec4aaf9c6ea1849a3cc682dd7d060aefc1890eda2e78eb373c52a27d38'}

      try:
         response = requests.get(url, headers=headers)
         response.raise_for_status()
         data = response.json()

         if "data" in data:
            last_analysis_results = data["data"]["attributes"]["last_analysis_results"]
            print("Domain Report for:", domain)
            display_report(last_analysis_results)
         else:
            print("No data found for the domain.")

      except requests.exceptions.HTTPError as http_err:
         print(f"HTTP error occurred: {http_err}")
      except requests.exceptions.RequestException as req_err:
         print(f"Request error occurred: {req_err}")
      except ValueError as json_err:
         print(f"JSON decoding error occurred: {json_err}")

   def Clear():
      domain.delete(0,END)  

   label2=Label(window,text="Domain          :",font=(12),padx=20,pady=10,justify= LEFT)
   label2.grid(row=1,column=0)

   domain=Entry(window,width=30,borderwidth=3,font=(12))
   domain.grid(row=1,column=1)

   
   save=Button(window,text="Search",cursor='hand2',padx=0,pady=0,command=Search,font=(6))
   clear=Button(window,text="Clear",cursor='hand2',padx=0,pady=0,command=Clear,font=(6))

   save.grid(row=10,column=0)
   clear.grid(row=10,column=1)
   
   window.mainloop()
   

    
    

   

   

   

  


   
def get_username_report():
    window = Tk()
    window.title("Username Lookup")
    window.geometry("512x512")

    def display_report(report_data):
        new_window = Tk()
        new_window.title("Username Report")
        new_window.geometry("600x400")

        report_text = Text(new_window, height=20, width=60, font=("Arial", 12))
        report_text.pack()

        report_text.insert(INSERT, "Username Report For:\n")
        report_text.insert(INSERT, username.get())
        report_text.insert(INSERT, "\n\nBreaches Found:\n\n")

        if report_data:
            for site, details in report_data.items():
                report_text.insert(INSERT, f"Site: {site}\n")
                for breach in details:
                    for key, value in breach.items():
                        report_text.insert(INSERT, f"{key.capitalize()}: {value}\n")
                    report_text.insert(INSERT, "\n")
        else:
            report_text.insert(INSERT, "No breaches found for this username.")

        new_window.mainloop()

    def Search():
        if username.get() == '':
            messagebox.showinfo("Information", "Username field is mandatory")
            return

        url = "https://leak-lookup.com/api/search"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "key": "bcbb3d2d97e33b4a51f649962ff82e2a",
            "type": "username",
            "query": username.get()
        }

        try:
            response = requests.post(url, headers=headers, data=data)
            response.raise_for_status()
            data = response.json()

            if data["error"] == "false":
                display_report(data["message"])
            else:
                messagebox.showinfo("Error", "Error in search query or API key.")

        except requests.exceptions.HTTPError as http_err:
            print(f"HTTP error occurred: {http_err}")
        except requests.exceptions.RequestException as req_err:
            print(f"Request error occurred: {req_err}")
        except ValueError as json_err:
            print(f"JSON decoding error occurred: {json_err}")

    def Clear():
        username.delete(0, END)

    label2 = Label(window, text="Username          :", font=(12), padx=20, pady=10, justify=LEFT)
    label2.grid(row=1, column=0)

    username = Entry(window, width=30, borderwidth=3, font=(12))
    username.grid(row=1, column=1)

    save = Button(window, text="Search", cursor='hand2', padx=0, pady=0, command=Search, font=(6))
    clear = Button(window, text="Clear", cursor='hand2', padx=0, pady=0, command=Clear, font=(6))

    save.grid(row=10, column=0)
    clear.grid(row=10, column=1)

    window.mainloop()
    
   
   

   

   

   




def get_email_report():
    window = Tk()
    window.title("Email Lookup")
    window.geometry("512x512")

    def display_report(report_data):
        new_window = Tk()
        new_window.title("Email Report")
        new_window.geometry("600x400")

        report_text = Text(new_window, height=20, width=60, font=("Arial", 12))
        report_text.pack()

        report_text.insert(INSERT, "Email Report For:\n")
        report_text.insert(INSERT, email.get())
        report_text.insert(INSERT, "\n\nBreaches Found:\n\n")

        if report_data:
            for site, details in report_data.items():
                report_text.insert(INSERT, f"Site: {site}\n")
                for breach in details:
                    for key, value in breach.items():
                        report_text.insert(INSERT, f"{key.capitalize()}: {value}\n")
                    report_text.insert(INSERT, "\n")
        else:
            report_text.insert(INSERT, "No breaches found for this email.")

        new_window.mainloop()

    def Search():
        if email.get() == '':
            messagebox.showinfo("Information", "Email field is mandatory")
            return

        url = "https://leak-lookup.com/api/search"
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "key": "bcbb3d2d97e33b4a51f649962ff82e2a",
            "type": "email_address",
            "query": email.get()
        }

        try:
            response = requests.post(url, headers=headers, data=data)
            response.raise_for_status()
            data = response.json()

            if data["error"] == "false":
                display_report(data["message"])
            else:
                messagebox.showinfo("Error", "Error in search query or API key.")

        except requests.exceptions.HTTPError as http_err:
            print(f"HTTP error occurred: {http_err}")
        except requests.exceptions.RequestException as req_err:
            print(f"Request error occurred: {req_err}")
        except ValueError as json_err:
            print(f"JSON decoding error occurred: {json_err}")

    def Clear():
        email.delete(0, END)

    label2 = Label(window, text="Email Address     :", font=(12), padx=20, pady=10, justify=LEFT)
    label2.grid(row=1, column=0)

    email = Entry(window, width=30, borderwidth=3, font=(12))
    email.grid(row=1, column=1)

    save = Button(window, text="Search", cursor='hand2', padx=0, pady=0, command=Search, font=(6))
    clear = Button(window, text="Clear", cursor='hand2', padx=0, pady=0, command=Clear, font=(6))

    save.grid(row=10, column=0)
    clear.grid(row=10, column=1)

    window.mainloop()





 
   

 
   

def get_password_report():
    window = Tk()
    window.title("Password Check")
    window.geometry("512x512")

    def display_report(report_data):
        new_window = Tk()
        new_window.title("Password Report")
        new_window.geometry("600x400")

        report_text = Text(new_window, height=20, width=60, font=("Arial", 12))
        report_text.pack()

        report_text.insert(INSERT, "Password Report:\n\n")

        if report_data > 0:
            report_text.insert(INSERT, f"⚠️ The password has been found {report_data} times in breaches.\n")
        else:
            report_text.insert(INSERT, "✅ The password has not been found in any known breaches.\n")

        new_window.mainloop()

    def Search():
        if password.get() == '':
            messagebox.showinfo("Information", "All fields are mandatory")
            return

        sha1_password = hashlib.sha1(password.get().encode('utf-8')).hexdigest().upper()
        prefix = sha1_password[:5]
        suffix = sha1_password[5:]

        url = f"https://api.pwnedpasswords.com/range/{prefix}"

        try:
            response = requests.get(url)
            response.raise_for_status()
            hashes = (line.split(':') for line in response.text.splitlines())
            count = next((int(count) for hash_suffix, count in hashes if hash_suffix == suffix), 0)

            display_report(count)

        except requests.exceptions.HTTPError as http_err:
            print(f"HTTP error occurred: {http_err}")
        except requests.exceptions.RequestException as req_err:
            print(f"Request error occurred: {req_err}")
        except ValueError as json_err:
            print(f"JSON decoding error occurred: {json_err}")

    def Clear():
        password.delete(0, END)

    label2 = Label(window, text="Password          :", font=(12), padx=20, pady=10, justify=LEFT)
    label2.grid(row=1, column=0)

    password = Entry(window, width=30, borderwidth=3, font=(12), show="*")
    password.grid(row=1, column=1)

    save = Button(window, text="Search", cursor='hand2', padx=0, pady=0, command=Search, font=(6))
    clear = Button(window, text="Clear", cursor='hand2', padx=0, pady=0, command=Clear, font=(6))

    save.grid(row=10, column=0)
    clear.grid(row=10, column=1)

    window.mainloop()   
   




 
   



# Function to show a record
def show():
    global f
    inp = txt_in.get(1.0, "end-1c").strip()
    inp1 = lbl2_in.get(1.0, "end-1c").strip()
    inp2 = lbsrch1_in.get(1.0, "end-1c").strip()
    inp3 = lbsrch2_in.get(1.0, "end-1c").strip()

    if ((inp == '' and inp1 == '' and inp2 == '' and inp3 == '') or 
        (inp != '' and inp1 != '' and inp2 != '' and inp3 != '')):
        messagebox.askretrycancel("showinfo", "Enter data in only one search box\nTitle, ID, Username, or Password")
        txt_in.delete("1.0", "end")
        lbl2_in.delete("1.0", "end")
        lbsrch1_in.delete("1.0", "end")
        lbsrch2_in.delete("1.0", "end")
        return

    txt_output.place(x=0, y=90)
    txt_output.delete("1.0", "end")

    headers = ["TITLE", "ID", "USERNAME", "PASSWORD"]
    txt_output.insert(INSERT, "\t\t\t".join(headers) + "\n")
    txt_output.insert(INSERT, "-"*80 + "\n")

    search_column = -1
    search_value = None

    if inp != '':
        search_column = 0
        search_value = inp
    elif inp1 != '':
        search_column = 1
        search_value = inp1
    elif inp2 != '':
        search_column = 2
        search_value = inp2
    elif inp3 != '':
        search_column = 3
        search_value = inp3

    if search_value is not None:
        with open('C:\\Users\\ANUBIS\\Documents\\cyber sec\\Password Manager\\PassMan GUI\\records.csv', 'r') as f:
            reader = csv.reader(f)
            next(reader)  # Skip header row
            for data in reader:
                decrypted_data = [decrypt_data(d) for d in data]
                if None not in decrypted_data:  # Ensure all data was decrypted successfully
                    if decrypted_data[search_column] == search_value:
                        txt_output.insert(INSERT, "\t\t\t".join(decrypted_data) + "\n")
                else:
                    print(f"Skipped corrupted record: {data}")

        txt_in.delete("1.0", "end")
        lbl2_in.delete("1.0", "end")
        lbsrch1_in.delete("1.0", "end")
        lbsrch2_in.delete("1.0", "end")



















# Function to add a new record
def recen():
    window = Tk()
    window.title("Data Entry")
    window.geometry("512x512")
    
    main_lst = []

    def Save():
        passe = encrypt_data(password.get())
        lst = [encrypt_data(title.get()), encrypt_data(ID.get()), encrypt_data(username.get()), passe]
        main_lst.append(lst)

        if title.get() == '' or ID.get() == '' or username.get() == '' or password.get() == '':
            messagebox.showinfo("Information", "All fields are mandatory")
            return

        with open("C:\\Users\\ANUBIS\\Documents\\cyber sec\\Password Manager\\PassMan GUI\\records.csv", "a", newline='') as file:
            Writer = csv.writer(file)
            Writer.writerows(main_lst)
            messagebox.showinfo("Information", "Saved successfully")
            window.destroy()

    def Clear():
        title.delete(0, END)
        ID.delete(0, END)
        username.delete(0, END)
        password.delete(0, END)
        strength_label.config(text="")  # Clear the password strength label

    def AutofillPassword():
        generated_password = generate_password()
        password.delete(0, END)  # Clear the password field first
        password.insert(0, generated_password)  # Insert the generated password
        update_password_strength(generated_password)  # Update the password strength

    def update_password_strength(pwd):
        strength = password_strength(pwd)
        strength_label.config(text=f"Password Strength: {strength}")

    def on_password_entry(event):
        pwd = password.get()
        update_password_strength(pwd)

    # Labels
    label1 = Label(window, text="Title       :", font=(12), padx=20, pady=10, justify=LEFT)
    label2 = Label(window, text="ID          :", font=(12), padx=20, pady=10, justify=LEFT)
    label3 = Label(window, text="Username    :", font=(12), padx=20, pady=10, justify=LEFT)
    label4 = Label(window, text="Password    :", font=(12), padx=20, pady=10, justify=LEFT)
    strength_label = Label(window, text="", font=(12), padx=20, pady=10, justify=LEFT, fg="blue")

    label1.grid(row=0, column=0)
    label2.grid(row=1, column=0)
    label3.grid(row=2, column=0)
    label4.grid(row=3, column=0)
    strength_label.grid(row=4, column=1)

    # Entry fields
    title = Entry(window, width=30, borderwidth=3, font=(12))
    ID = Entry(window, width=30, borderwidth=3, font=(12))
    username = Entry(window, width=30, borderwidth=3, font=(12))
    password = Entry(window, show="*", width=30, borderwidth=3, font=(12))

    title.grid(row=0, column=1)
    ID.grid(row=1, column=1)
    username.grid(row=2, column=1)
    password.grid(row=3, column=1)
    
    # Bind password entry to event
    password.bind("<KeyRelease>", on_password_entry)

    # Buttons
    save = Button(window, text="Save", cursor='hand2', padx=0, pady=0, command=Save, font=(6))
    clear = Button(window, text="Clear", cursor='hand2', padx=0, pady=0, command=Clear, font=(6))
    autofill = Button(window, text="Autofill Password", cursor='hand2', padx=0, pady=0, command=AutofillPassword, font=(6))

    save.grid(row=10, column=0)
    clear.grid(row=10, column=1)
    autofill.grid(row=10, column=2)

    window.mainloop()














def chpswd():
    window = Tk()
    window.title("Change Password")
    window.geometry("512x512")

    def Save():
        new_password = password.get()
        id_to_change = ID.get()

        if id_to_change == '' or new_password == '':
            messagebox.showinfo("Information", "All fields are mandatory")
            window.destroy()
            return

        with open("C:\\Users\\ANUBIS\\Documents\\cyber sec\\Password Manager\\PassMan GUI\\records.csv", "r") as file:
            rows = list(csv.reader(file))
        
        for i in range(len(rows)):
            if decrypt_data(rows[i][1]) == id_to_change:
                rows[i][3] = encrypt_data(new_password)

        with open("C:\\Users\\ANUBIS\\Documents\\cyber sec\\Password Manager\\PassMan GUI\\records.csv", "w", newline='') as file:
            writer = csv.writer(file)
            writer.writerows(rows)
        
        messagebox.showinfo("Information", "Password Changed Successfully.")
        window.destroy()

    def Clear():
        ID.delete(0, END)
        password.delete(0, END)

    # Labels and Entry fields
    Label(window, text="ID          :", font=(12), padx=20, pady=10, justify='left').grid(row=1, column=0)
    Label(window, text="New Password:", font=(12), padx=20, pady=10, justify='left').grid(row=3, column=0)

    ID = Entry(window, width=30, borderwidth=3, font=(12))
    password = Entry(window, width=30, borderwidth=3, font=(12))

    ID.grid(row=1, column=1)
    password.grid(row=3, column=1)

    Button(window, text="Save", cursor='hand2', padx=0, pady=0, command=Save, font=(6)).grid(row=10, column=0)
    Button(window, text="Clear", cursor='hand2', padx=0, pady=0, command=Clear, font=(6)).grid(row=10, column=1)

    window.mainloop()




















def chusr():
    window = Tk()
    window.title("Change Username")
    window.geometry("512x512")

    def Save():
        new_username = username.get()
        id_to_change = ID.get()

        if id_to_change == '' or new_username == '':
            messagebox.showinfo("Information", "All fields are mandatory")
            window.destroy()
            return

        with open("C:\\Users\\ANUBIS\\Documents\\cyber sec\\Password Manager\\PassMan GUI\\records.csv", "r") as file:
            rows = list(csv.reader(file))
        
        for i in range(len(rows)):
            if decrypt_data(rows[i][1]) == id_to_change:
                rows[i][2] = encrypt_data(new_username)

        with open("C:\\Users\\ANUBIS\\Documents\\cyber sec\\Password Manager\\PassMan GUI\\records.csv", "w", newline='') as file:
            writer = csv.writer(file)
            writer.writerows(rows)
        
        messagebox.showinfo("Information", "Username Changed Successfully")
        window.destroy()

    def Clear():
        ID.delete(0, END)
        username.delete(0, END)

    # Labels and Entry fields
    Label(window, text="ID          :", font=(12), padx=20, pady=10, justify='left').grid(row=1, column=0)
    Label(window, text="New Username:", font=(12), padx=20, pady=10, justify='left').grid(row=3, column=0)

    ID = Entry(window, width=30, borderwidth=3, font=(12))
    username = Entry(window, width=30, borderwidth=3, font=(12))

    ID.grid(row=1, column=1)
    username.grid(row=3, column=1)

    Button(window, text="Save", cursor='hand2', padx=0, pady=0, command=Save, font=(6)).grid(row=10, column=0)
    Button(window, text="Clear", cursor='hand2', padx=0, pady=0, command=Clear, font=(6)).grid(row=10, column=1)

    window.mainloop()





















def upusr():
   window=Tk()
   window.title("Username Update")
   window.geometry("512x110")
   
   

  
   def Save():
      
      
      if (ID.get()==''):
         messagebox.showinfo("Information","All fields are mandatory")
         window.destroy()
         
         return
         
      f = open("C:\\Users\\ANUBIS\\Documents\\cyber sec\\Password Manager\\PassMan GUI\\uinfo.txt",'r')
      i = f.readline()
      k = i.split()
      k[0] = ID.get()
      f.close() 
      f = open("C:\\Users\\ANUBIS\\Documents\\cyber sec\\Password Manager\\PassMan GUI\\uinfo.txt",'w')
      M = k[0]+" "+k[1]
      f.write(M)    
      f.close()
      messagebox.showinfo("Information","Username Changed.")
      window.destroy()
         #window.mainloop()
         
   def Clear():
      ID.delete(0,END)
      
   # 3 labels, 4 buttons,3 entry fields
   
   label2=Label(window,text="New_Uname:",font=(12),padx=20,pady=10,justify= LEFT)
   label2.grid(row=1,column=0)

   ID=Entry(window,width=30,borderwidth=3,font=(12))
   ID.grid(row=1,column=1)

   
   save=Button(window,text="Save",cursor='hand2',padx=0,pady=0,command=Save,font=(6))
   clear=Button(window,text="Clear",cursor='hand2',padx=0,pady=0,command=Clear,font=(6))

   save.grid(row=10,column=0)
   clear.grid(row=10,column=1)
   
   window.mainloop()





















def uppwd():
   window=Tk()
   window.title("Password Update")
   window.geometry("512x110")
   
   

  
   def Save():
      
      
      if (ID.get()==''):
         messagebox.showinfo("Information","All fields are mandatory")
         window.destroy()
         
         return
         
      f = open("C:\\Users\\ANUBIS\\Documents\\cyber sec\\Password Manager\\PassMan GUI\\uinfo.txt",'r')
      i = f.readline()
      k = i.split()
      data_to_hash = ID.get()
      hash_algorithm = hashlib.sha256()
      hash_algorithm.update(data_to_hash.encode('utf-8'))
      hash_result = hash_algorithm.hexdigest()
      k[1] = hash_result
      f.close() 
      f = open("C:\\Users\\ANUBIS\\Documents\\cyber sec\\Password Manager\\PassMan GUI\\uinfo.txt",'w')
      M = k[0]+" "+k[1]
      f.write(M)    
      f.close()
      messagebox.showinfo("Information","Username Changed.")
      window.destroy()
         #window.mainloop()
         
   def Clear():
      ID.delete(0,END)
      
   # 3 labels, 4 buttons,3 entry fields
   
   label2=Label(window,text="New_Pass:",font=(12),padx=20,pady=10,justify= LEFT)
   label2.grid(row=1,column=0)

   ID=Entry(window,width=30,borderwidth=3,font=(12))
   ID.grid(row=1,column=1)

   
   save=Button(window,text="Save",cursor='hand2',padx=0,pady=0,command=Save,font=(6))
   clear=Button(window,text="Clear",cursor='hand2',padx=0,pady=0,command=Clear,font=(6))

   save.grid(row=10,column=0)
   clear.grid(row=10,column=1)
   
   window.mainloop()   



















# Password Generator
def generate_password(length=12, include_uppercase=True, include_numbers=True, include_symbols=True):
    characters = string.ascii_lowercase
    if include_uppercase:
        characters += string.ascii_uppercase
    if include_numbers:
        characters += string.digits
    if include_symbols:
        characters += string.punctuation
    
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password



















# Password Strength Meter
def password_strength(password):
    length_criteria = len(password) >= 12
    uppercase_criteria = re.search(r'[A-Z]', password) is not None
    lowercase_criteria = re.search(r'[a-z]', password) is not None
    digit_criteria = re.search(r'\d', password) is not None
    symbol_criteria = re.search(r'[!@#$%^&*(),.?":{}|<>]', password) is not None

    score = sum([length_criteria, uppercase_criteria, lowercase_criteria, digit_criteria, symbol_criteria])

    if score == 5:
        return 'Strong'
    elif score >= 3:
        return 'Medium'
    else:
        return 'Weak'


















button=Button(root, text= "Show Record", font=(12),cursor='hand2',command=show)
button.place(x=10, y=450)


lbl2=Label(root,text='ID                ',justify=tk.RIGHT,height=2,font=(12)).place(x=10,y=520)
lbl2_in = Text(root, height=2,width=10 ,font=('Arial', 12),foreground='Blue')
lbl2_in.place(x=160,y=525)
inp1=tk.StringVar()

lbl=Label(root,text='TITLE          ',justify=tk.RIGHT,height=2,
          font=(12)).place(x=10,y=580)
txt_in = Text(root, height=2,width=10 ,font=('Arial', 12),foreground='Red')
txt_in.place(x=160,y=585)
inp=tk.StringVar()


lbsrch1=Label(root,text='USERNAME ',justify=tk.RIGHT,height=2,
          font=(12)).place(x=10,y=640)
lbsrch1_in = Text(root, height=2,width=10,font=('Arial', 12),foreground='Red')
lbsrch1_in.place(x=160,y=645)

lbsrch2=Label(root,text='PASSWORD',justify=tk.RIGHT,height=2,
          font=(12)).place(x=10,y=700)
lbsrch2_in = Text(root, height=2,width=10, font=('Arial', 12),foreground='Blue')
lbsrch2_in.place(x=160,y=705)
















menubar = Menu(root)

filemenu = Menu(menubar, tearoff=0)
filemenu.add_command(label="Enter Record",command=recen)   
menubar.add_cascade(label="file", menu=filemenu,font=("Arial",30))
updtmenu = Menu(menubar, tearoff=0)
updtmenu.add_command(label="Change Username",command=chusr)   
updtmenu.add_command(label="Change Password",command=chpswd)   
menubar.add_cascade(label="update", menu=updtmenu,font=("Arial",30))
login = Menu(menubar, tearoff=0)
login.add_command(label="Change login Username",command=upusr)   
login.add_command(label="Change login Password",command=uppwd)   
menubar.add_cascade(label="login", menu=login,font=("Arial",30))
Security = Menu(menubar, tearoff=0)
Security.add_command(label="Domain Check",command=get_domain_report)     
Security.add_command(label="Email Breach Report",command=get_email_report) 
Security.add_command(label="Password Breach Report",command=get_password_report) 
Security.add_command(label="Username Breach Report",command=get_username_report)
menubar.add_cascade(label="Security", menu=Security,font=("Arial",30))

root.config(menu=menubar)
root.mainloop()
