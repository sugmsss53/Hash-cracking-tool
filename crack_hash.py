import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib
import itertools
import string
import threading
import time

# Dictionary of common hash types and their lengths
HASH_TYPES = {
    32: ["MD5", "NTLM"],
    40: ["SHA-1"],
    64: ["SHA-256"],
    128: ["SHA-512"],
}

# Function to identify hash type(s) based on length
def identify_hash(hash_value):
    length = len(hash_value)
    return HASH_TYPES.get(length, ["Unknown"])

# Function to compute hash for a given text
def compute_hash(text, hash_type):
    hash_funcs = {
        "MD5": hashlib.md5,
        "SHA-1": hashlib.sha1,
        "SHA-256": hashlib.sha256,
        "SHA-512": hashlib.sha512,
        "NTLM": lambda x: hashlib.new("md4", x if isinstance(x, bytes) else x.encode("utf-16le")).hexdigest(),
    }
    
    if hash_type in hash_funcs:
        return hash_funcs[hash_type](text.encode()).hexdigest()
    return None

# Function to crack hash using dictionary attack
def dictionary_attack(hash_value, wordlist, ui_callback):
    possible_hashes = identify_hash(hash_value)

    if "Unknown" in possible_hashes:
        ui_callback("Unsupported Hash Type")
        return

    # Hash table to store computed hashes
    computed_hashes = {}

    for word in wordlist:
        word = word.strip()
        for hash_type in possible_hashes:
            if word not in computed_hashes:
                hashed_word = compute_hash(word, hash_type)
                computed_hashes[word] = hashed_word  # Store in hash table

            if computed_hashes[word] == hash_value:
                ui_callback(f"Hash Cracked: {word} (Algorithm: {hash_type})")
                return
    
    ui_callback("Hash not found in dictionary")

# Function to crack hash using brute force (with verbose UI updates)
def brute_force_attack(hash_value, ui_callback, stop_event, max_length=4):
    possible_hashes = identify_hash(hash_value)
    
    if "Unknown" in possible_hashes:
        ui_callback("Unsupported Hash Type")
        return

    chars = string.ascii_letters + string.digits
    for length in range(1, max_length + 1):
        for attempt in itertools.product(chars, repeat=length):
            if stop_event.is_set():  # Check if stop event is set
                ui_callback("Brute Force Stopped")
                return
            
            attempt = ''.join(attempt)
            ui_callback(f"Trying: {attempt}")  # Update UI with attempt
            time.sleep(0.01)  # Small delay to allow UI to update
            
            for hash_type in possible_hashes:
                hashed_attempt = compute_hash(attempt, hash_type)
                if hashed_attempt and hashed_attempt == hash_value:
                    ui_callback(f"Hash Cracked: {attempt} (Algorithm: {hash_type})")
                    return
    
    ui_callback("Brute Force Failed")

# Function to generate hash for a file
def generate_file_hash(file_path, hash_type="sha256"):
    try:
        hasher = hashlib.new(hash_type)
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        return f"Error: {str(e)}"

# GUI Application
class HashCrackerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Hash Cracker")

        # Hash Input
        tk.Label(root, text="Enter Hash:").grid(row=0, column=0, padx=10, pady=10)
        self.hash_entry = tk.Entry(root, width=50)
        self.hash_entry.grid(row=0, column=1, padx=10, pady=10)

        # Identify Hash Type Button
        tk.Button(root, text="Identify Hash Type", command=self.identify_hash).grid(row=1, column=0, padx=10, pady=10)

        # Dictionary Attack Button
        tk.Button(root, text="Dictionary Attack", command=self.start_dictionary_attack).grid(row=1, column=1, padx=10, pady=10)

        # Brute Force Attack Button
        tk.Button(root, text="Brute Force Attack", command=self.start_brute_force_attack).grid(row=2, column=0, padx=10, pady=10)

        # Stop Brute Force Button
        self.stop_button = tk.Button(root, text="Stop Brute Force", command=self.stop_brute_force_attack, state=tk.DISABLED)
        self.stop_button.grid(row=2, column=1, padx=10, pady=10)

        # File Hash Generator Button
        tk.Button(root, text="Generate File Hash", command=self.generate_file_hash).grid(row=3, column=0, columnspan=2, padx=10, pady=10)

        # Hash Type Display
        self.hash_type_label = tk.Label(root, text="Hash Type: Unknown", fg="black")
        self.hash_type_label.grid(row=4, column=0, columnspan=2, padx=10, pady=10)

        # Result Display (Verbose Output)
        self.result_label = tk.Label(root, text="", fg="blue")
        self.result_label.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

        # Initialize stop event
        self.stop_event = threading.Event()

    def identify_hash(self):
        hash_value = self.hash_entry.get().strip()
        if not hash_value:
            messagebox.showerror("Error", "Please enter a hash.")
            return
        hash_types = identify_hash(hash_value)
        self.hash_type_label.config(text=f"Possible Hash Types: {', '.join(hash_types)}")

    def start_dictionary_attack(self):
        threading.Thread(target=self.dictionary_attack, daemon=True).start()

    def dictionary_attack(self):
        hash_value = self.hash_entry.get().strip()
        if not hash_value:
            messagebox.showerror("Error", "Please enter a hash.")
            return

        file_path = filedialog.askopenfilename(title="Select Wordlist File")
        if not file_path:
            return

        with open(file_path, 'r', encoding="utf-8", errors="ignore") as f:
            wordlist = f.readlines()

        def update_ui(text):
            self.result_label.config(text=text)
            self.root.update_idletasks()  # Ensure the UI updates

        dictionary_attack(hash_value, wordlist, update_ui)

    def start_brute_force_attack(self):
        self.stop_event.clear()  # Clear the stop event
        self.stop_button.config(state=tk.NORMAL)  # Enable the stop button
        threading.Thread(target=self.brute_force_attack, daemon=True).start()

    def stop_brute_force_attack(self):
        self.stop_event.set()  # Set the stop event
        self.stop_button.config(state=tk.DISABLED)  # Disable the stop button

    def brute_force_attack(self):
        hash_value = self.hash_entry.get().strip()
        if not hash_value:
            messagebox.showerror("Error", "Please enter a hash.")
            return

        self.result_label.config(text="Brute force in progress...")

        def update_ui(text):
            self.result_label.config(text=text)
            self.root.update_idletasks()  # Ensure the UI updates

        brute_force_attack(hash_value, update_ui, self.stop_event)

    def generate_file_hash(self):
        file_path = filedialog.askopenfilename(title="Select File")
        if not file_path:
            return

        hash_value = generate_file_hash(file_path)
        self.result_label.config(text=f"File Hash (SHA-256): {hash_value}")

# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = HashCrackerApp(root)
    root.mainloop()