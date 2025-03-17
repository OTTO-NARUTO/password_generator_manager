import sqlite3
import os
import bcrypt

# Database path
db_path = "C:\\Users\\TARUN ADITYA\\OneDrive\\Desktop\\password_generator\\password_manager.db"

# Function to initialize the database
def initialize_db():
    if not os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Create the users table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
        """)

        # Create the passwords table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app_name TEXT NOT NULL,
            password TEXT NOT NULL
        )
        """)

        conn.commit()
        conn.close()
        print("Database initialized successfully!")
    else:
        print("Database already exists!")

# Function to handle user signup
def signup(username, password):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

# Function to verify user credentials
def authenticate(username, password):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    if result and bcrypt.checkpw(password.encode('utf-8'), result[0]):
        return True
    return False

# Function to save a password
def save_password(app_name, password):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO passwords (app_name, password) VALUES (?, ?)", (app_name, password))
    conn.commit()
    conn.close()

# Additional function to retrieve passwords (if needed)
def get_passwords():
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT app_name, password FROM passwords")
    passwords = cursor.fetchall()
    conn.close()
    return passwords