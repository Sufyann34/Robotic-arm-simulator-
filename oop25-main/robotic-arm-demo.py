import tkinter as tk
from tkinter import ttk, messagebox
import math
import pickle
import os

from user import User
from commands import Command, MoveCommand  
from logger_config import Logger

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# === RSA KEY GENERATION ===
sender_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
receiver_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
receiver_public_key = receiver_private_key.public_key()

# === SECURE CHANNEL CLASS ===
class SecureChannel:
    def __init__(self, sender_private_key, receiver_public_key, receiver_private_key):
        self.sender_private_key = sender_private_key
        self.receiver_public_key = receiver_public_key
        self.receiver_private_key = receiver_private_key  

    def send(self, data: bytes) -> bytes:
        return self.receiver_public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def receive(self, encrypted_data: bytes) -> bytes:
        return self.receiver_private_key.decrypt( 
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

# === database ===
USER_DB_FILE = "user_database.pkl"

def load_user_database():
    if os.path.exists(USER_DB_FILE):
        try:
            with open(USER_DB_FILE, "rb") as f:
                return pickle.load(f)
        except EOFError:
            return {}  
    return {}
def save_user_database(db):
    with open(USER_DB_FILE, "wb") as f:
        pickle.dump(db, f)


# === GLOBALS ===
user_database = load_user_database()
secure_channel = SecureChannel(sender_private_key, receiver_public_key, receiver_private_key)
logger = Logger()

# === AUTHENTICATION WINDOW ===
class AuthWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Robotic Arm Login")
        self.root.geometry("300x200")
        self.root.resizable(False, False)
        
        self.create_widgets()
        self.root.mainloop()

    def create_widgets(self):
        style = ttk.Style()
        style.configure("TLabel", padding=5, font=("Arial", 10))
        style.configure("TButton", padding=5, font=("Arial", 10))

        frame = ttk.Frame(self.root, padding=10)
        frame.pack(expand=True, fill="both")

        ttk.Label(frame, text="Username:").grid(row=0, column=0, sticky="w")
        self.username_entry = ttk.Entry(frame)
        self.username_entry.grid(row=0, column=1, pady=5)

        ttk.Label(frame, text="Password:").grid(row=1, column=0, sticky="w")
        self.password_entry = ttk.Entry(frame, show="*")
        self.password_entry.grid(row=1, column=1, pady=5)

        button_frame = ttk.Frame(frame)
        button_frame.grid(row=2, columnspan=2, pady=10)

        ttk.Button(button_frame, text="Register", command=self.register).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Login", command=self.login).pack(side="right", padx=5)

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showerror("Error", "Username and password required")
            return

        if len(username) < 4:
            messagebox.showerror("Error", "Username must be at least 4 characters")
            return

        if len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters")
            return

        if username in user_database:
            messagebox.showerror("Error", "Username already exists")
            return

        user_database[username] = User(username, password)
        save_user_database(user_database)
        logger.log(f"New user registered: {username}", "info")
        messagebox.showinfo("Success", "Registration successful!")
        self.root.destroy()
        RoboticArmSimulator()

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showerror("Error", "Username and password required")
            return

        if username not in user_database:
            logger.log(f"Failed login attempt - user not found: {username}", "warning")
            messagebox.showerror("Error", "User not found")
            return

        if user_database[username].check_password(password):
            logger.log(f"User logged in: {username}", "info")
            messagebox.showinfo("Success", "Login successful!")
            self.root.destroy()
            RoboticArmSimulator()
        else:
            logger.log(f"Failed login attempt - wrong password for: {username}", "warning")
            messagebox.showerror("Error", "Incorrect password")

# === ROBOTIC ARM SIMULATOR ===
class RoboticArmSimulator:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Robotic Arm Control System")
        self.root.geometry("600x600")
        self.root.config(bg='lightblue')

        self.base_x, self.base_y = 300, 300
        self.segments = []

        self.create_segment_input_ui()
        self.canvas = tk.Canvas(self.root, width=600, height=400, bg="white")
        self.canvas.pack()

        self.create_control_ui()
        self.root.mainloop()

    def create_segment_input_ui(self):
        frame = ttk.Frame(self.root, padding=10)
        frame.pack(pady=10)

        ttk.Label(frame, text="Number of segments:").grid(row=0, column=0)
        self.num_segments_entry = ttk.Entry(frame, width=5)
        self.num_segments_entry.grid(row=0, column=1)
        self.num_segments_entry.insert(0, "2")

        ttk.Label(frame, text="Segment lengths (comma separated):").grid(row=1, column=0)
        self.segment_lengths_entry = ttk.Entry(frame, width=20)
        self.segment_lengths_entry.grid(row=1, column=1)
        self.segment_lengths_entry.insert(0, "100,80")

        ttk.Button(frame, text="Set Segments", command=self.set_segments).grid(row=2, columnspan=2, pady=5)

    def set_segments(self):
        try:
            n = int(self.num_segments_entry.get())
            lengths_str = self.segment_lengths_entry.get()
            lengths = [int(l.strip()) for l in lengths_str.split(",")]
            if len(lengths) != n:
                messagebox.showerror("Error", "Number of lengths must match number of segments")
                return
            self.segments = [RoboticArmSegment(length=l) for l in lengths]
            self.draw_arm()
            logger.log(f"Set {n} segments with lengths {lengths}", "info")
        except Exception as e:
            messagebox.showerror("Error", f"Invalid input: {e}")

    def create_control_ui(self):
        control_frame = ttk.Frame(self.root, padding=10)
        control_frame.pack(pady=20)

        ttk.Label(control_frame, text="Segment Index (0-based):", font=("Arial", 12)).grid(row=0, column=0)
        self.segment_index_entry = ttk.Entry(control_frame, width=5, font=("Arial", 12))
        self.segment_index_entry.grid(row=0, column=1)
        self.segment_index_entry.insert(0, "0")

        ttk.Label(control_frame, text="Angle (degrees):", font=("Arial", 12)).grid(row=1, column=0)
        self.angle_entry = ttk.Entry(control_frame, width=10, font=("Arial", 12))
        self.angle_entry.grid(row=1, column=1)
        self.angle_entry.insert(0, "0")

        ttk.Button(control_frame, text="Move Segment", command=self.move_segment).grid(row=2, columnspan=2, pady=10)

    def move_segment(self):  
        try:
            index = int(self.segment_index_entry.get())
            angle = float(self.angle_entry.get())
            if not (0 <= angle <= 360):
                messagebox.showerror("Error", "Angle must be between 0-360 degrees")
                return
            if not (0 <= index < len(self.segments)):
                messagebox.showerror("Error", "Segment index out of range")
                return

            self.segments[index].angle = angle

            cmd = MoveCommand(angle)
            encrypted = cmd.encrypt(secure_channel.receiver_public_key)
            decrypted_cmd = Command.decrypt(encrypted, secure_channel.receiver_private_key)

            logger.log(f"Moved segment {index} to {angle}° (decrypted: {decrypted_cmd})", "info")
            self.draw_arm()

        except Exception as e:
            logger.log(f"Error moving segment: {e}", "error")
            messagebox.showerror("Error", str(e))

    def draw_arm(self):  
        self.canvas.delete("arm")
        x, y = self.base_x, self.base_y
        cumulative_angle = 0
        for segment in self.segments:
            cumulative_angle += segment.angle
            rad_angle = math.radians(cumulative_angle)
            end_x = x + segment.length * math.cos(rad_angle)
            end_y = y - segment.length * math.sin(rad_angle)
            self.canvas.create_line(x, y, end_x, end_y, fill="blue", width=5, tags="arm")
            x, y = end_x, end_y

# === ARM SEGMENT CLASS ===
class RoboticArmSegment:
    def __init__(self, length, angle=0):
        self.length = length
        self.angle = angle

    def get_end_pos(self, start_x, start_y):
        rad_angle = math.radians(self.angle)
        end_x = start_x + self.length * math.cos(rad_angle)
        end_y = start_y - self.length * math.sin(rad_angle)
        return end_x, end_y

# === MAIN ENTRY POINT ===
if __name__ == "__main__":
    AuthWindow()
