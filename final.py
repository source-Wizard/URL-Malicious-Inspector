import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import sqlite3
import requests
import hashlib
import os

# VirusTotal API Key
api_key = "5340b10bbfacba83993e9e5a907f84a0b45a18fe1ce7a5b0bb48d387c3493e1d"

# Define known malware hashes (SHA256)
malware_hashes = [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "44d88612fea8a8f36de82e1278abb02f6a7471b4d2ab9c9606ef8e28f37f6c24",
    "7b8a8cba28b931b025b3e3a678a3cd1d59b1c7d8e8f2304d8fe6c2e6d231e0a4",
    "275a021bbfb6465cb245ddf36ba5e398629d210345bbff33a7f3a950f7d17f07",
    "5e4a087ae12a6a8e0145b9b0f7ae34518f6f751d9b56b6c6f3e9a4100c4b9fa3",
    "c3b46eb9c1761c84d606d118f6fbf6723685a8fdf61424a7c899b2d1b8a7754b",
    "87e6a7a8d0e9c78b6dc2a72a75b1d73f8f8c6e029d6c938e501ace4b117f2a94",
    "efa10c2db50b77c176b6d568a0cce7fe7f4a11d3e09b3c21cf96c244bb2b5b50",
    "fe5ebf94b14937a960b163e70b40b82df2a6f98224e6a19fcb5c9ad6d3448cc3",
    "25f74949ff8b1bff49e6606d4c9dd5ff82ed79dfca874c8f8fc35f3244b6d66e",
]


# Global database connection
conn = None

def get_database_connection():
    global conn
    try:
        if conn is None:
            conn = sqlite3.connect("users.db")
        return conn, conn.cursor()
    except sqlite3.Error as e:
        print(f"Database connection error: {e}")
        return None, None

# Database setup
def setup_database():
    conn, cursor = get_database_connection()
    if conn is not None and cursor is not None:
        try:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    file_path TEXT,
                    url TEXT,
                    positives INTEGER,
                    total INTEGER,
                    scan_date TEXT
                )
            ''')
            conn.commit()
            print("Database setup completed successfully.")
        except sqlite3.Error as e:
            print(f"Error setting up the database: {e}")
    else:
        print("Failed to connect to the database during setup.")

def insert_scan_result(username, file_path, url, positives, total, scan_date):
    """Insert a scan result into the database."""
    conn, cursor = get_database_connection()
    if conn is not None and cursor is not None:
        try:
            cursor.execute('''
                INSERT INTO scans (username, file_path, url, positives, total, scan_date)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, file_path, url, positives, total, scan_date))
            conn.commit()  # Commit the transaction to save the data
            print("Scan result inserted into the database successfully.")
        except sqlite3.Error as e:
            print(f"Error inserting scan result into the database: {e}")

def close_database_connection():
    global conn
    if conn is not None:
        conn.close()
        conn = None
        print("Database connection closed.")

# File handling functions, scanning functions, etc.
# [Include your existing functions here]

def on_closing():
    """Handle application closing event."""
    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        close_database_connection()
        app.destroy()

def calculate_file_hash(file_path):
    """Calculate the SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def is_malicious(file_path):
    """Check if the file hash matches a known malware hash."""
    file_hash = calculate_file_hash(file_path)
    return file_hash in malware_hashes

def browse_file():
    """Open a file dialog to select a file."""
    file_path = filedialog.askopenfilename()
    file_entry.delete(0, tk.END)
    file_entry.insert(0, file_path)

def browse_directory():
    """Open a file dialog to select a directory."""
    directory_path = filedialog.askdirectory()
    directory_entry.delete(0, tk.END)
    directory_entry.insert(0, directory_path)

def scan_file_virustotal(file_path):
    """Scan file using VirusTotal API."""
    url = "https://www.virustotal.com/vtapi/v2/file/scan"
    params = {'apikey': api_key}
    
    with open(file_path, 'rb') as file_to_scan:
        files = {'file': (file_path, file_to_scan)}
        response = requests.post(url, files=files, params=params)

    if response.status_code == 200:
        result = response.json()
        return result['resource']  # Return the resource ID for the file scan report
    else:
        return None

def get_scan_report(resource_id):
    """Get the scan report for a previously scanned file."""
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    params = {'apikey': api_key, 'resource': resource_id}
    
    response = requests.get(url, params=params)
    if response.status_code == 200:
        return response.json()  # Returns the scan report
    else:
        return None

def scan_url_virustotal(url_to_scan):
    """Scan a URL using VirusTotal API."""
    url = "https://www.virustotal.com/vtapi/v2/url/scan"
    params = {'apikey': api_key, 'url': url_to_scan}
    
    response = requests.post(url, params=params)

    if response.status_code == 200:
        scan_result = response.json()
        return scan_result['resource']  # Returns the resource ID for the URL scan report
    else:
        return None

def get_url_report(resource_id):
    """Get the scan report for a previously scanned URL."""
    url = "https://www.virustotal.com/vtapi/v2/url/report"
    params = {'apikey': api_key, 'resource': resource_id}
    
    response = requests.get(url, params=params)
    if response.status_code == 200:
        return response.json()  # Returns the URL scan report
    else:
        return None

def scan_file():
    """Scan the selected file for malware."""
    file_path = file_entry.get()
    if not file_path:
        messagebox.showerror("Error", "Please select a file to scan.")
        return

    if is_malicious(file_path):
        result_label.config(text="Warning: The file is malicious!", fg="red")
    else:
        resource_id = scan_file_virustotal(file_path)
        if resource_id:
            report = get_scan_report(resource_id)
            if report:
                display_report(report)

                # Extract scan details and save to the database
                username = "User"  # You can replace this with the actual username if available
                positives = report.get('positives', 0)
                total = report.get('total', 0)
                scan_date = report.get('scan_date', '')

                insert_scan_result(username, file_path, None, positives, total, scan_date)
            else:
                result_label.config(text="File scan completed. No issues found.", fg="green")
        else:
            result_label.config(text="File scan failed.", fg="red")


def scan_directory():
    """Scan all files in the selected directory."""
    directory_path = directory_entry.get()
    if not directory_path:
        messagebox.showerror("Error", "Please select a directory to scan.")
        return

    # List all files in the directory
    files_in_directory = [os.path.join(directory_path, file) for file in os.listdir(directory_path) if os.path.isfile(os.path.join(directory_path, file))]
    
    if not files_in_directory:
        messagebox.showerror("Error", "The selected directory is empty.")
        return
    
    # Initialize progress bar
    progress_bar['maximum'] = len(files_in_directory)
    progress_bar['value'] = 0

    for idx, file_path in enumerate(files_in_directory):
        if is_malicious(file_path):
            result_label.config(text=f"Malicious file detected: {file_path}", fg="red")
            break
        else:
            resource_id = scan_file_virustotal(file_path)
            if resource_id:
                report = get_scan_report(resource_id)
                if report:
                    # Display and save the report for each file
                    display_report(report)

                    # Extract scan details and save to the database
                    username = "User"  # Replace with actual username if available
                    positives = report.get('positives', 0)
                    total = report.get('total', 0)
                    scan_date = report.get('scan_date', '')

                    # Insert the scan result into the database
                    insert_scan_result(username, file_path, None, positives, total, scan_date)
        
        # Update progress bar
        progress_bar['value'] = idx + 1
        app.update_idletasks()

    result_label.config(text="Directory scan completed.", fg="green")

def scan_url():
    """Scan the entered URL for malware."""
    url_to_scan = url_entry.get()
    if not url_to_scan:
        messagebox.showerror("Error", "Please enter a URL to scan.")
        return
    
    resource_id = scan_url_virustotal(url_to_scan)
    if resource_id:
        report = get_url_report(resource_id)
        if report:
            display_report(report)

            # Extract scan details and save to the database
            username = "User"  # Replace with actual username if available
            positives = report.get('positives', 0)
            total = report.get('total', 0)
            scan_date = report.get('scan_date', '')

            # Insert the scan result into the database
            insert_scan_result(username, None, url_to_scan, positives, total, scan_date)
        else:
            result_label.config(text="URL scan completed. No issues found.", fg="green")
    else:
        result_label.config(text="URL scan failed.", fg="red")

def display_report(report):
    """Display the scan report in the GUI with scrollable functionality."""
    report_text = ""
    
    if report.get("response_code") == 1:  # Check if report is available
        report_text += f"Resource: {report.get('resource')}\n"
        report_text += f"Scan Date: {report.get('scan_date')}\n"
        report_text += f"Positive Count: {report.get('positives')} / {report.get('total')} engines detected.\n"
        report_text += "Details:\n"
        
        for engine, result in report.get('scans', {}).items():
            report_text += f"- {engine}: {'Malicious' if result['detected'] else 'Clean'}\n"
    else:
        report_text = "No report found for this resource."

    # Create a new window for the report
    report_window = tk.Toplevel(app)
    report_window.title("Scan Report")
    report_window.geometry("600x400")# Adjust window size as needed

    # Create a frame to hold the canvas and scrollbar
    container = ttk.Frame(report_window)
    container.pack(fill="both", expand=True)

    # Create a canvas widget
    canvas = tk.Canvas(container)
    canvas.pack(side="left", fill="both", expand=True)

    # Add a vertical scrollbar to the canvas
    scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
    scrollbar.pack(side="right", fill="y")

    # Configure the canvas to work with the scrollbar
    canvas.configure(yscrollcommand=scrollbar.set)
    canvas.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

    # Create a frame inside the canvas to hold the report content
    report_frame = ttk.Frame(canvas)
    canvas.create_window((0, 0), window=report_frame, anchor="nw")

    # Add the report text inside the report_frame
    report_label = tk.Label(report_frame, text=report_text, justify="left", font=("Cascadia Code SemiBold", 12))
    report_label.pack(padx=10, pady=10)

    # Optionally, you can add horizontal scroll support for long lines of text
    # Uncomment the following block if needed
    h_scrollbar = ttk.Scrollbar(container, orient="horizontal", command=canvas.xview)
    h_scrollbar.pack(side="bottom", fill="x")
    canvas.configure(xscrollcommand=h_scrollbar.set)


# Create the main application window
app = tk.Tk()
app.title("URL Malicious Inspector")
app.geometry("700x550")

# Set up the database when the application starts
setup_database()

# Heading
heading_label = tk.Label(app, text="URL & Files Malicious Inspector", font=("Cascadia Code SemiBold", 24, "bold"))
heading_label.pack(pady=20)

# File Scanning Section
file_label = tk.Label(app, text="Select a file to scan:", font=("Cascadia Code SemiBold", 18, "bold"))
file_label.pack(pady=10)

file_entry = tk.Entry(app, width=60, font=("Cascadia Code SemiBold", 16))
file_entry.pack(pady=5)

file_frame = tk.Frame(app)
file_frame.pack(pady=5)

browse_button = tk.Button(file_frame, text="Browse File", font=("Cascadia Code SemiBold", 16), width=20, command=browse_file,bg="light blue")
browse_button.grid(row=0, column=0, padx=5)

scan_button = tk.Button(file_frame, text="Scan File", font=("Cascadia Code SemiBold", 16), width=20, command=scan_file,bg="light green")
scan_button.grid(row=0, column=1, padx=5)

# Directory Scanning Section
directory_label = tk.Label(app, text="Select a directory to scan:", font=("Cascadia Code SemiBold", 18, "bold"))
directory_label.pack(pady=10)

directory_entry = tk.Entry(app, width=60, font=("Cascadia Code SemiBold", 16))
directory_entry.pack(pady=5)

directory_frame = tk.Frame(app)
directory_frame.pack(pady=5)

browse_directory_button = tk.Button(directory_frame, text="Browse Directory", font=("Cascadia Code SemiBold", 16), width=20, command=browse_directory,bg="light blue")
browse_directory_button.grid(row=0, column=0, padx=5)

scan_directory_button = tk.Button(directory_frame, text="Scan Directory", font=("Cascadia Code SemiBold", 16), width=20, command=scan_directory,bg="light green")
scan_directory_button.grid(row=0, column=1, padx=5)

# URL Scanning Section
url_label = tk.Label(app, text="Enter a URL to scan:", font=("Cascadia Code SemiBold", 18, "bold"))
url_label.pack(pady=10)

url_entry = tk.Entry(app, width=60, font=("Cascadia Code SemiBold", 16))
url_entry.pack(pady=5)

url_frame = tk.Frame(app)
url_frame.pack(pady=5)

scan_url_button = tk.Button(url_frame, text="Scan URL", font=("Cascadia Code SemiBold", 16), width=20, command=scan_url,bg="light green")
scan_url_button.grid(row=0, column=0, padx=5)

# Progress Bar
progress_bar = ttk.Progressbar(app, orient="horizontal", length=500, mode="determinate")
progress_bar.pack(pady=20)

# Result Label
result_label = tk.Label(app, text="", font=("Cascadia Code SemiBold", 12))
result_label.pack(pady=20)

# Handle the window close event
app.protocol("WM_DELETE_WINDOW", on_closing)

# Run the application
app.mainloop()

