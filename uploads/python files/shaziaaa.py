import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
import requests
import os
import threading
import queue
from time import sleep

API_URL = 'https://api.zerobounce.net/v2/validate'

class EmailValidatorApp:
    def init(self, root):
        self.root = root
        self.root.title("Email Validator")
        self.root.geometry("800x600")
        self.log_queue = queue.Queue()
        self.create_widgets()
        self.running = False
        self.check_log_queue()

def create_widgets(self):  
    main_frame = ttk.Frame(self.root, padding=10)  
    main_frame.pack(fill=tk.BOTH, expand=True)  

    ttk.Label(main_frame, text="Input File:").grid(row=0, column=0, sticky=tk.W)  
    self.input_entry = ttk.Entry(main_frame, width=50)  
    self.input_entry.grid(row=0, column=1, padx=5)  
    ttk.Button(main_frame, text="Browse", command=self.browse_input).grid(row=0, column=2)  

    ttk.Label(main_frame, text="Output File:").grid(row=1, column=0, sticky=tk.W)  
    self.output_entry = ttk.Entry(main_frame, width=50)  
    self.output_entry.grid(row=1, column=1, padx=5)  
    ttk.Button(main_frame, text="Browse", command=self.browse_output).grid(row=1, column=2)  

    ttk.Label(main_frame, text="API Key:").grid(row=2, column=0, sticky=tk.W)  
    self.api_key_entry = ttk.Entry(main_frame, width=50, show="*")  
    self.api_key_entry.grid(row=2, column=1, padx=5)  

    ttk.Label(main_frame, text="Delay (seconds):").grid(row=3, column=0, sticky=tk.W)  
    self.delay_entry = ttk.Entry(main_frame, width=10)  
    self.delay_entry.insert(0, "0.5")  
    self.delay_entry.grid(row=3, column=1, sticky=tk.W, padx=5)  

    self.log_area = scrolledtext.ScrolledText(main_frame, height=15)  
    self.log_area.grid(row=4, column=0, columnspan=3, pady=10, sticky=tk.NSEW)  

    self.progress = ttk.Progressbar(main_frame, orient=tk.HORIZONTAL, mode='determinate')  
    self.progress.grid(row=5, column=0, columnspan=3, pady=5, sticky=tk.EW)  

    self.start_btn = ttk.Button(main_frame, text="Start Validation", command=self.start_validation)  
    self.start_btn.grid(row=6, column=1, pady=10)  

    main_frame.rowconfigure(4, weight=1)  
    main_frame.columnconfigure(1, weight=1)  

def browse_input(self):  
    filename = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])  
    if filename:  
        self.input_entry.delete(0, tk.END)  
        self.input_entry.insert(0, filename)  

def browse_output(self):  
    filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])  
    if filename:  
        self.output_entry.delete(0, tk.END)  
        self.output_entry.insert(0, filename)  

def check_log_queue(self):  
    while not self.log_queue.empty():  
        msg, level = self.log_queue.get()  
        self.log_area.insert(tk.END, msg + "\n")  
        self.log_area.see(tk.END)  
    self.root.after(100, self.check_log_queue)  

def thread_safe_log(self, message, level="info"):  
    self.log_queue.put((message, level))  

def validate_email(self, api_key, email):  
    try:  
        response = requests.get(API_URL, params={'api_key': api_key, 'email': email}, timeout=10)  
        response.raise_for_status()  
        return response.json()  
    except Exception as e:  
        self.thread_safe_log(f"API Error: {str(e)}", "error")  
        return {'error': str(e)}  

def start_validation(self):  
    if self.running:  
        return  
          
    input_file = self.input_entry.get()  
    output_file = self.output_entry.get()  
    api_key = self.api_key_entry.get().strip() or os.getenv('ZEROBOUNCE_API_KEY')  
      
    try:  
        delay = max(0.2, float(self.delay_entry.get() or 0.5))  
    except ValueError:  
        delay = 0.5  

    if not api_key:  
        self.thread_safe_log("API Key required", "error")  
        return  
          
    if not input_file or not output_file:  
        self.thread_safe_log("Select input/output files", "error")  
        return  

    self.running = True  
    self.start_btn.config(text="Stop", command=self.stop_validation)  
    self.progress['value'] = 0  
      
    thread = threading.Thread(target=self.process_emails, args=(input_file, output_file, api_key, delay), daemon=True)  
    thread.start()  

def stop_validation(self):  
    self.running = False  
    self.start_btn.config(text="Start", command=self.start_validation)  

def process_emails(self, input_file, output_file, api_key, delay):  
    try:  
        with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:  
            emails = [line.strip() for line in infile if line.strip()]  
            total = len(emails)  
            outfile.write("Email|Status|Suggestion|FreeEmail|MXFound|Error\n\n")  

            processed = 0  
            for email in emails:  
                if not self.running:  
                    break  

                self.thread_safe_log(f"Checking: {email}")  
                result = self.validate_email(api_key, email)  
                sleep(delay)  

                status = result.get('status', 'error').lower()  
                suggestion = result.get('did_you_mean', '') or ''  
                free_email = str(result.get('free_email', False)).lower()  
                mx_found = str(result.get('mx_found', False)).lower()  
                error = result.get('error', '') or ''  

                outfile.write(f"{email}|{status}|{suggestion}|{free_email}|{mx_found}|{error}\n")  
                processed += 1  
                self.progress['value'] = (processed / total) * 100  

    except Exception as e:  
        self.thread_safe_log(f"Error: {str(e)}", "error")  
    finally:  
        self.stop_validation()  
        self.thread_safe_log(f"Completed: {processed}/{total} emails")  
        self.progress['value'] = 100

if name == 'main':
    root = tk.Tk()
    app = EmailValidatorApp(root)
    root.mainloop()
