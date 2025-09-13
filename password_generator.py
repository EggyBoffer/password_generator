#!/usr/bin/env python3
"""
Password Generator - single-file Tkinter app

Bugfix: removed stray ")" in `on_generate` function.
"""

import os
import sys
import sqlite3
import hashlib
import secrets
import string
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path

APP_NAME = "Password Generator"
DB_FILENAME = Path.home() / ".password_generator_history.db"
MAX_UNIQUE_ATTEMPTS = 100000
DEFAULT_LENGTH = 16
MIN_LENGTH = 4
MAX_LENGTH = 256

# ---------- Database ----------
def init_db():
    conn = sqlite3.connect(DB_FILENAME)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS passwords (
                    id INTEGER PRIMARY KEY,
                    sha256 TEXT UNIQUE,
                    length INTEGER,
                    preset TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )""")
    conn.commit()
    return conn

def password_seen(conn, pwd):
    h = hashlib.sha256(pwd.encode('utf-8')).hexdigest()
    c = conn.cursor()
    c.execute("SELECT 1 FROM passwords WHERE sha256 = ?", (h,))
    return c.fetchone() is not None

def store_password(conn, pwd, length, preset):
    h = hashlib.sha256(pwd.encode('utf-8')).hexdigest()
    c = conn.cursor()
    try:
        c.execute("INSERT INTO passwords (sha256, length, preset) VALUES (?, ?, ?)", (h, length, preset))
        conn.commit()
    except sqlite3.IntegrityError:
        pass

# ---------- Password generation ----------
def make_charset(preset, opts):
    if preset == 'numbers':
        return string.digits
    elif preset == 'windows':
        safe_symbols = "!@#$%&*()-_=+[]{}.,<>;:?"
        return string.ascii_letters + string.digits + safe_symbols
    elif preset == 'symbols':
        all_symbols = """!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"""
        return string.ascii_letters + string.digits + all_symbols
    else:
        chars = ''
        if opts.get('include_lower', True):
            chars += string.ascii_lowercase
        if opts.get('include_upper', True):
            chars += string.ascii_uppercase
        if opts.get('include_digits', True):
            chars += string.digits
        if opts.get('include_symbols', False):
            chars += "!@#$%&*()-_=+[]{}.,<>;:?/\\"
        return chars

def generate_password(length, preset, opts, conn=None):
    if length < MIN_LENGTH or length > MAX_LENGTH:
        raise ValueError(f"length must be between {MIN_LENGTH} and {MAX_LENGTH}")

    charset = make_charset(preset, opts)
    if not charset:
        raise ValueError("Character set is empty. Enable some options.")

    attempts = 0
    while attempts < MAX_UNIQUE_ATTEMPTS:
        attempts += 1
        pwd = ''.join(secrets.choice(charset) for _ in range(length))
        if conn is None:
            return pwd
        if not password_seen(conn, pwd):
            store_password(conn, pwd, length, preset)
            return pwd
    return pwd

# ---------- GUI ----------
class PasswordGeneratorApp(tk.Tk):
    def __init__(self, conn):
        super().__init__()
        self.conn = conn
        self.title(APP_NAME)
        self.geometry('560x360')
        self.resizable(False, False)
        self.create_widgets()

    def create_widgets(self):
        pad = 10
        frm = ttk.Frame(self, padding=pad)
        frm.pack(fill='both', expand=True)

        length_lbl = ttk.Label(frm, text='Length:')
        length_lbl.grid(row=0, column=0, sticky='w')
        self.length_var = tk.IntVar(value=DEFAULT_LENGTH)
        length_spin = ttk.Spinbox(frm, from_=MIN_LENGTH, to=MAX_LENGTH, textvariable=self.length_var, width=6)
        length_spin.grid(row=0, column=1, sticky='w')

        preset_lbl = ttk.Label(frm, text='Preset:')
        preset_lbl.grid(row=1, column=0, sticky='w', pady=(8,0))
        self.preset_var = tk.StringVar(value='windows')
        presets = [('Windows-safe', 'windows'), ('Numbers only', 'numbers'), ('Include symbols', 'symbols'), ('Custom', 'custom')]
        for i,(lab,val) in enumerate(presets):
            r = ttk.Radiobutton(frm, text=lab, value=val, variable=self.preset_var, command=self.on_preset_change)
            r.grid(row=1, column=1+i, sticky='w', padx=(0,6), pady=(8,0))

        self.opts = {
            'include_lower': tk.BooleanVar(value=True),
            'include_upper': tk.BooleanVar(value=True),
            'include_digits': tk.BooleanVar(value=True),
            'include_symbols': tk.BooleanVar(value=False)
        }
        custom_frame = ttk.Frame(frm)
        custom_frame.grid(row=2, column=0, columnspan=5, sticky='w', pady=(8,0))
        ttk.Checkbutton(custom_frame, text='lowercase', variable=self.opts['include_lower']).grid(row=0,column=0, padx=4)
        ttk.Checkbutton(custom_frame, text='UPPERCASE', variable=self.opts['include_upper']).grid(row=0,column=1, padx=4)
        ttk.Checkbutton(custom_frame, text='numbers', variable=self.opts['include_digits']).grid(row=0,column=2, padx=4)
        ttk.Checkbutton(custom_frame, text='symbols', variable=self.opts['include_symbols']).grid(row=0,column=3, padx=4)

        gen_btn = ttk.Button(frm, text='Generate', command=self.on_generate)
        gen_btn.grid(row=3, column=0, pady=(16,0))

        self.result_var = tk.StringVar()
        result_entry = ttk.Entry(frm, textvariable=self.result_var, width=48, font=('Consolas', 12))
        result_entry.grid(row=3, column=1, columnspan=3, padx=(8,0), pady=(16,0))

        copy_btn = ttk.Button(frm, text='Copy', command=self.copy_to_clipboard)
        copy_btn.grid(row=3, column=4, padx=(8,0), pady=(16,0))

        save_btn = ttk.Button(frm, text='Export history...', command=self.export_history)
        save_btn.grid(row=4, column=0, pady=(18,0))

        clear_btn = ttk.Button(frm, text='Clear stored history', command=self.clear_history)
        clear_btn.grid(row=4, column=1, pady=(18,0))

        about_lbl = ttk.Label(frm, text='Note: We store only SHA-256 hashes of generated passwords locally to avoid duplicates.', wraplength=520)
        about_lbl.grid(row=5, column=0, columnspan=5, pady=(18,0))

        self.status_var = tk.StringVar(value='Ready')
        status_lbl = ttk.Label(self, textvariable=self.status_var, relief='sunken', anchor='w')
        status_lbl.pack(side='bottom', fill='x')

        self.on_preset_change()

    def on_preset_change(self):
        preset = self.preset_var.get()
        if preset == 'numbers':
            self.opts['include_lower'].set(False)
            self.opts['include_upper'].set(False)
            self.opts['include_digits'].set(True)
            self.opts['include_symbols'].set(False)
        elif preset == 'windows':
            self.opts['include_lower'].set(True)
            self.opts['include_upper'].set(True)
            self.opts['include_digits'].set(True)
            self.opts['include_symbols'].set(False)
        elif preset == 'symbols':
            self.opts['include_lower'].set(True)
            self.opts['include_upper'].set(True)
            self.opts['include_digits'].set(True)
            self.opts['include_symbols'].set(True)

    def on_generate(self):
        try:
            length = int(self.length_var.get())
        except Exception:
            messagebox.showerror('Invalid length', 'Please provide a valid integer length.')
            return
        preset = self.preset_var.get()
        opts = {k: v.get() for k, v in self.opts.items()}
        try:
            self.status_var.set('Generating...')
            self.update_idletasks()
            pwd = generate_password(length, preset, opts, conn=self.conn)
            self.result_var.set(pwd)
            self.status_var.set('Generated')
        except Exception as e:
            messagebox.showerror('Error', str(e))
            self.status_var.set('Error')

    def copy_to_clipboard(self):
        pwd = self.result_var.get()
        if not pwd:
            return
        self.clipboard_clear()
        self.clipboard_append(pwd)
        self.status_var.set('Copied to clipboard')

    def export_history(self):
        path = filedialog.asksaveasfilename(title='Export history as CSV', defaultextension='.csv', filetypes=[('CSV','*.csv')])
        if not path:
            return
        c = self.conn.cursor()
        c.execute('SELECT sha256, length, preset, created_at FROM passwords ORDER BY created_at DESC')
        rows = c.fetchall()
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write('sha256,length,preset,created_at\n')
                for r in rows:
                    f.write(','.join(map(str, r)) + '\n')
            messagebox.showinfo('Export complete', f'Exported {len(rows)} records to {path}')
        except Exception as e:
            messagebox.showerror('Export failed', str(e))

    def clear_history(self):
        if messagebox.askyesno('Confirm', 'This will remove stored password hashes (history). Continue?'):
            c = self.conn.cursor()
            c.execute('DELETE FROM passwords')
            self.conn.commit()
            messagebox.showinfo('Cleared', 'History cleared.')

# ---------- Main ----------
def main():
    conn = init_db()
    app = PasswordGeneratorApp(conn)
    app.mainloop()

if __name__ == '__main__':
    main()
