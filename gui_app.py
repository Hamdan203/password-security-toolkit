import tkinter as tk
from tkinter import messagebox
from password_toolkit import check_strength

def analyze_password():
    pwd = entry.get()
    if not pwd:
        messagebox.showwarning("Input Error", "Please enter a password.")
        return

    result = check_strength(pwd)

    output_text.set(
        f"Strength: {result['level']}\n"
        f"Score (0-5): {result['score']}\n"
        f"Entropy (bits): {result['entropy_bits']}\n"
        f"Security Score (0-100): {result['security_score']}"
    )

root = tk.Tk()
root.title("Password Security Analyzer")
root.geometry("400x250")

tk.Label(root, text="Enter Password:", font=("Arial", 12)).pack(pady=5)

entry = tk.Entry(root, width=30, show="*")
entry.pack(pady=5)

tk.Button(root, text="Analyze", command=analyze_password).pack(pady=10)

output_text = tk.StringVar()
tk.Label(root, textvariable=output_text, font=("Arial", 10)).pack(pady=10)

root.mainloop()
