import tkinter as tk
from tkinter import messagebox
import sqlite3
import hashlib
import subprocess

# Create or connect to the SQLite database
conn = sqlite3.connect('users.db')
c = conn.cursor()

# Create a users table if it doesn't exist
c.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
)
''')
conn.commit()

def hash_password(password):
    """Hash the password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def switch_to_register():
    """Switch the interface to the registration form."""
    login_frame.pack_forget()
    register_frame.pack(pady=20)

def switch_to_login():
    """Switch the interface to the login form."""
    register_frame.pack_forget()
    login_frame.pack(pady=20)

def register_user():
    """Register a new user."""
    username = register_username_entry.get()
    password = register_password_entry.get()

    if not username or not password:
        messagebox.showerror("Error", "Both fields are required!")
        return

    hashed_password = hash_password(password)

    try:
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        messagebox.showinfo("Success", "Registration successful!")
        switch_to_login()
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "Username already exists!")

def login_user():
    """Log in the user."""
    username = login_username_entry.get()
    password = login_password_entry.get()

    hashed_password = hash_password(password)

    c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hashed_password))
    user = c.fetchone()

    if user:
        messagebox.showinfo("Success", "Login successful!")
        app.destroy()  # Close the login window
        open_main_app()  # Function to open your main app after login
    else:
        messagebox.showerror("Error", "Invalid username or password!")

def open_main_app():
    """Open the main application after successful login."""
    subprocess.Popen(['python', 'final.py'])  # Run the final.py file
    # If you need to run a different Python executable, you can specify the path to it here

# Create the main application window
app = tk.Tk()
app.title("Login and Register")
app.geometry("400x400")

# ---- Login Form ----
login_frame = tk.Frame(app)

login_label = tk.Label(login_frame, text="Login", font=("Cascadia Code SemiBold", 20, "bold"))
login_label.pack(pady=10)

login_username_label = tk.Label(login_frame, text="Username:", font=("Cascadia Code SemiBold", 16))
login_username_label.pack(pady=5)
login_username_entry = tk.Entry(login_frame, font=("Cascadia Code SemiBold", 16))
login_username_entry.pack(pady=5)

login_password_label = tk.Label(login_frame, text="Password:", font=("Cascadia Code SemiBold", 16))
login_password_label.pack(pady=5)
login_password_entry = tk.Entry(login_frame, show='*', font=("Cascadia Code SemiBold", 16))
login_password_entry.pack(pady=5)

login_button = tk.Button(login_frame, text="Login", font=("Cascadia Code SemiBold", 16), command=login_user,bg="light blue")
login_button.pack(pady=10)

switch_to_register_button = tk.Button(login_frame, text="Don't have an account? Sign up", font=("Cascadia Code SemiBold", 14), command=switch_to_register)
switch_to_register_button.pack(pady=5)

login_frame.pack(pady=20)

# ---- Register Form ----
register_frame = tk.Frame(app)

register_label = tk.Label(register_frame, text="Register", font=("Cascadia Code SemiBold", 20, "bold"))
register_label.pack(pady=10)

register_username_label = tk.Label(register_frame, text="Username:", font=("Cascadia Code SemiBold", 16))
register_username_label.pack(pady=5)
register_username_entry = tk.Entry(register_frame, font=("Cascadia Code SemiBold", 16))
register_username_entry.pack(pady=5)

register_password_label = tk.Label(register_frame, text="Password:", font=("Cascadia Code SemiBold", 16))
register_password_label.pack(pady=5)
register_password_entry = tk.Entry(register_frame, show='*', font=("Cascadia Code SemiBold", 16))
register_password_entry.pack(pady=5)

register_button = tk.Button(register_frame, text="Register", font=("Cascadia Code SemiBold", 16), command=register_user,bg="light blue")
register_button.pack(pady=10)

switch_to_login_button = tk.Button(register_frame, text="Already have an account? Login", font=("Cascadia Code SemiBold", 14), command=switch_to_login)
switch_to_login_button.pack(pady=5)

# Start the application with the login form
app.mainloop()

# Close the database connection when the app closes
conn.close()
