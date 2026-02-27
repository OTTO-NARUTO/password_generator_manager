import random
import string
import pyperclip
import sqlite3
import bcrypt
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import ctypes  
import time
from threading import Thread

# Function to set up the database
def initialize_db():
    conn = sqlite3.connect("password_manager.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app_name TEXT,
            password TEXT
        )
    """)
    conn.commit()
    conn.close()

# Function to handle user signup
def signup(username, password):
    conn = sqlite3.connect("password_manager.db")
    cursor = conn.cursor()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        messagebox.showinfo("Success", "Signup successful! Please login.")
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "This username is already taken.")
    conn.close()

# Function to verify user credentials
def authenticate(username, password):
    conn = sqlite3.connect("password_manager.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    if result and bcrypt.checkpw(password.encode('utf-8'), result[0]):
        return True
    return False

# Password generation logic
def generate_password():
    try:
        length = int(length_entry.get())
        uppercase = upper_var.get()
        numbers = numbers_var.get()
        special = special_var.get()

        if length <= 0:
            raise ValueError("Password length must be greater than 0.")

        characters = string.ascii_lowercase
        if uppercase:
            characters += string.ascii_uppercase
        if numbers:
            characters += string.digits
        if special:
            characters += string.punctuation

        password = ''.join(random.choice(characters) for _ in range(length))
        password_var.set(password)
    except ValueError as ve:
        messagebox.showerror("Error", str(ve))

# Function to save the password to the manager
def save_password():
    app_name = app_name_entry.get()
    password = password_var.get()
    
    if app_name and password:
        conn = sqlite3.connect("password_manager.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO passwords (app_name, password) VALUES (?, ?)", (app_name, password))
        conn.commit()
        conn.close()
        messagebox.showinfo("Success", "Password saved successfully!")
        app_name_entry.delete(0, tk.END)  # Clear the entry after saving
    else:
        messagebox.showwarning("Warning", "Please enter both the application name and the password.")

# Function to copy password to clipboard
def copy_to_clipboard():
    password = password_var.get()
    if password:
        pyperclip.copy(password)
        ctypes.windll.user32.MessageBoxW(0, "Password copied to clipboard!", "Success", 0x40)

# Fade-in animation for the window
def fade_in(window):
    for i in range(0, 101, 5):
        window.attributes("-alpha", i / 100)
        time.sleep(0.02)

# Initialize and start a thread for animation
def start_animation():
    Thread(target=fade_in, args=(root,)).start()

# Setup for the main window
root = tk.Tk()
root.title("🔒 Password Manager")
root.geometry("600x500")
root.configure(bg="#F7F9FC")  # Light background
root.resizable(True, True)  # Allow resizing of the window
start_animation()

# Custom button styling and behavior
def create_custom_button(parent, text, command):
    button = tk.Button(parent, text=text, font=("Segoe UI", 12, "bold"), bg="#007ACC",
                       fg="#FFFFFF", relief="flat", padx=10, pady=5,
                       command=command)
    
    # Make the button look more like a flat space bar
    button.config(height=1, width=12)  # Adjust height and width to resemble a space bar effect
    button.bind("<Enter>", lambda e: button.config(bg="#005B99"))  # Change color on hover
    button.bind("<Leave>", lambda e: button.config(bg="#007ACC"))  # Change back on leave
    button.pack(pady=3)
    return button

# Display main menu
def show_main_menu():
    for widget in root.winfo_children():
        widget.destroy()

    tk.Label(root, text="Welcome to Password Manager", font=("Segoe UI", 16, "bold"),
             fg="#007ACC", bg="#F7F9FC").pack(pady=10)

    create_custom_button(root, "Password Manager", show_password_manager)
    create_custom_button(root, "Password Generator", show_password_generator)

# Password generator
def show_password_generator():
    global length_entry, password_var, app_name_entry
    for widget in root.winfo_children():
        widget.destroy()

    tk.Label(root, text="Password Generator", font=("Segoe UI", 16, "bold"),
             fg="#007ACC", bg="#F7F9FC").pack(pady=10)

    tk.Label(root, text="Password Length:", font=("Segoe UI", 11),
             fg="#333333", bg="#F7F9FC").pack()

    length_entry = tk.Entry(root, width=5, font=("Segoe UI", 11), relief="flat",
                             highlightbackground="#007ACC", highlightthickness=1,
                             bg="#FFFFFF", fg="#333333")
    length_entry.pack(pady=5)

    global upper_var, numbers_var, special_var
    upper_var = tk.BooleanVar(value=True)
    numbers_var = tk.BooleanVar(value=True)
    special_var = tk.BooleanVar(value=True)

    tk.Checkbutton(root, text="Include Uppercase", variable=upper_var,
                   bg="#F7F9FC", fg="#333333", selectcolor="#FFFFFF").pack(pady=5)
    tk.Checkbutton(root, text="Include Numbers", variable=numbers_var,
                   bg="#F7F9FC", fg="#333333", selectcolor="#FFFFFF").pack(pady=5)
    tk.Checkbutton(root, text="Include Special Characters", variable=special_var,
                   bg="#F7F9FC", fg="#333333", selectcolor="#FFFFFF").pack(pady=5)

    create_custom_button(root, "Generate Password", generate_password)

    password_var = tk.StringVar()
    password_entry = tk.Entry(root, textvariable=password_var, state="readonly", width=35,
                               font=("Segoe UI", 12), justify="center", relief="flat",
                               highlightbackground="#007ACC", highlightthickness=1,
                               bg="#FFFFFF", fg="#333333")
    password_entry.pack(pady=5)

    tk.Label(root, text="Application Name:", bg="#F7F9FC", fg="#333333").pack(pady=5)
    app_name_entry = tk.Entry(root, bg="#FFFFFF", fg="#333333")
    app_name_entry.pack(pady=5)

    create_custom_button(root, "Save Password", save_password)
    create_custom_button(root, "Copy to Clipboard", copy_to_clipboard)

    # Back button added to the password generator
    create_custom_button(root, "Back", show_main_menu)

# Login screen
def show_login():
    for widget in root.winfo_children():
        widget.destroy()
    
    tk.Label(root, text="Login", font=("Segoe UI", 16, "bold"),
             fg="#007ACC", bg="#F7F9FC").pack(pady=10)
    
    tk.Label(root, text="Username:", bg="#F7F9FC", fg="#333333").pack()
    username_entry = tk.Entry(root, bg="#FFFFFF", fg="#333333")
    username_entry.pack(pady=5)
    
    tk.Label(root, text="Password:", bg="#F7F9FC", fg="#333333").pack()
    password_entry = tk.Entry(root, show="*", bg="#FFFFFF", fg="#333333")
    password_entry.pack(pady=5)

    def try_login():
        if authenticate(username_entry.get(), password_entry.get()):
            show_main_menu()  # Show the main menu after successful login
        else:
            messagebox.showerror("Error", "Invalid username or password.")

    create_custom_button(root, "Login", try_login).pack(pady=5)
    create_custom_button(root, "Sign Up", show_signup).pack(pady=5)

# Signup screen
def show_signup():
    for widget in root.winfo_children():
        widget.destroy()
    
    tk.Label(root, text="Sign Up", font=("Segoe UI", 16, "bold"),
             fg="#007ACC", bg="#F7F9FC").pack(pady=10)
    
    tk.Label(root, text="Username:", bg="#F7F9FC", fg="#333333").pack()
    username_entry = tk.Entry(root, bg="#FFFFFF", fg="#333333")
    username_entry.pack(pady=5)
    
    tk.Label(root, text="Password:", bg="#F7F9FC", fg="#333333").pack()
    password_entry = tk.Entry(root, show="*", bg="#FFFFFF", fg="#333333")
    password_entry.pack(pady=5)

    def try_signup():
        signup(username_entry.get(), password_entry.get())
        show_login()

    create_custom_button(root, "Sign Up", try_signup).pack(pady=5)
    create_custom_button(root, "Back to Login", show_login).pack(pady=5)

# Display password manager
def show_password_manager():
    for widget in root.winfo_children():
        widget.destroy()

    tk.Label(root, text="Password Manager", font=("Segoe UI", 16, "bold"),
             fg="#007ACC", bg="#F7F9FC").pack(pady=10)

    # Create a treeview to display saved passwords
    tree = ttk.Treeview(root, columns=("Application", "Password"), show='headings')
    tree.heading("Application", text="Application")
    tree.heading("Password", text="Password")
    tree.pack(expand=True, fill='both', pady=(10, 10))

    # Fetch and display saved passwords
    conn = sqlite3.connect("password_manager.db")
    cursor = conn.cursor()
    cursor.execute("SELECT app_name, password FROM passwords")
    passwords = cursor.fetchall()
    conn.close()

    for app_name, password in passwords:
        tree.insert("", "end", values=(app_name, password))

    create_custom_button(root, "Back to Main Menu", show_main_menu).pack(pady=10)

# Initial database setup and display of the login screen
initialize_db()
show_login()
root.mainloop()
print("testing 8.28 negative case")