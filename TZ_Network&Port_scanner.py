import tkinter as tk
from tkinter import ttk, messagebox
import socket
import threading
import queue
import subprocess
import platform
import ipaddress
import time

class FundacionMosqueraScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("TZOOTZ RESEARCH 2025® Network & Port Scanner")
        
        # Colors
        self.colors = {
            'dark_bg': '#1e1e1e',
            'main_pink': '#ff69b4',
            'pearl': '#f5f5f5'
        }
        
        # Configure root window
        self.root.configure(bg=self.colors['dark_bg'])
        
        # Configure style
        style = ttk.Style()
        style.theme_use('default')
        style.configure('Pink.Treeview',
                       background=self.colors['dark_bg'],
                       foreground=self.colors['pearl'],
                       fieldbackground=self.colors['dark_bg'])
        
        # Variables for scanning control
        self.scanning_network = False
        self.scanning_ports = False
        self.network_queue = queue.Queue()
        self.ports_queue = queue.Queue()
        
        # Main frame
        main_frame = tk.Frame(root, bg=self.colors['dark_bg'])
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Network Scanner Frame
        network_frame = tk.LabelFrame(main_frame,
                                    text="Network Scanner",
                                    bg=self.colors['dark_bg'],
                                    fg=self.colors['main_pink'],
                                    font=('Courier New', 12, 'bold'))
        network_frame.pack(fill='both', expand=True)
        
        # Network Controls
        network_controls = tk.Frame(network_frame, bg=self.colors['dark_bg'])
        network_controls.pack(fill='x', padx=5, pady=5)
        
        self.scan_network_btn = tk.Button(network_controls,
                                        text="Scan Network",
                                        command=self.start_network_scan,
                                        bg=self.colors['main_pink'],
                                        fg=self.colors['pearl'],
                                        font=('Courier New', 10),
                                        relief='flat',
                                        cursor='hand2')
        self.scan_network_btn.pack(side='left', padx=5)
        
        self.network_status = tk.Label(network_controls,
                                     text="Ready",
                                     bg=self.colors['dark_bg'],
                                     fg=self.colors['pearl'])
        self.network_status.pack(side='left', padx=5)
        
        # Frame for Network Treeview and Scrollbar
        network_tree_frame = tk.Frame(network_frame, bg=self.colors['dark_bg'])
        network_tree_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Network Results Treeview
        self.network_tree = ttk.Treeview(network_tree_frame,
                                       style='Pink.Treeview',
                                       columns=('IP', 'Status', 'Hostname', 'Response'),
                                       show='headings')
        
        # Configurar ordenamiento para network_tree
        for col in ['IP', 'Status', 'Hostname', 'Response']:
            self.network_tree.heading(col, text=col,
                                    command=lambda c=col: self.treeview_sort_column(self.network_tree, c, False))
            self.network_tree.column(col, width=150)
        
        # Bind selection event
        self.network_tree.bind('<<TreeviewSelect>>', self.on_network_select)
        
        # Network Scrollbar
        network_scroll = ttk.Scrollbar(network_tree_frame,
                                     orient="vertical",
                                     command=self.network_tree.yview)
        self.network_tree.configure(yscrollcommand=network_scroll.set)
        
        # Pack network_tree and scrollbar
        self.network_tree.pack(side='left', fill='both', expand=True)
        network_scroll.pack(side='right', fill='y')
        
        # Port Scanner Frame
        port_frame = tk.LabelFrame(main_frame,
                                 text="Port Scanner",
                                 bg=self.colors['dark_bg'],
                                 fg=self.colors['main_pink'],
                                 font=('Courier New', 12, 'bold'))
        port_frame.pack(fill='both', expand=True)
        
        # Port Scanner Controls
        port_controls = tk.Frame(port_frame, bg=self.colors['dark_bg'])
        port_controls.pack(fill='x', padx=5, pady=5)
        
        # IP Entry
        tk.Label(port_controls,
                text="Target IP:",
                bg=self.colors['dark_bg'],
                fg=self.colors['pearl']).pack(side='left', padx=5)
        
        self.ip_entry = tk.Entry(port_controls,
                               bg=self.colors['dark_bg'],
                               fg=self.colors['pearl'],
                               insertbackground=self.colors['pearl'])
        self.ip_entry.pack(side='left', padx=5)
        
        # Port Range
        tk.Label(port_controls,
                text="Ports:",
                bg=self.colors['dark_bg'],
                fg=self.colors['pearl']).pack(side='left', padx=5)
        
        self.start_port = tk.Entry(port_controls,
                                 width=6,
                                 bg=self.colors['dark_bg'],
                                 fg=self.colors['pearl'])
        self.start_port.pack(side='left', padx=2)
        self.start_port.insert(0, "1")
        
        tk.Label(port_controls,
                text="to",
                bg=self.colors['dark_bg'],
                fg=self.colors['pearl']).pack(side='left', padx=2)
        
        self.end_port = tk.Entry(port_controls,
                               width=6,
                               bg=self.colors['dark_bg'],
                               fg=self.colors['pearl'])
        self.end_port.pack(side='left', padx=2)
        self.end_port.insert(0, "1000")
        
        self.scan_ports_btn = tk.Button(port_controls,
                                      text="Scan Ports",
                                      command=self.toggle_port_scan,
                                      bg=self.colors['main_pink'],
                                      fg=self.colors['pearl'],
                                      font=('Courier New', 10),
                                      relief='flat',
                                      cursor='hand2')
        self.scan_ports_btn.pack(side='left', padx=10)
        
        # Frame for Port Treeview and Scrollbar
        port_tree_frame = tk.Frame(port_frame, bg=self.colors['dark_bg'])
        port_tree_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Port Results Treeview
        self.port_tree = ttk.Treeview(port_tree_frame,
                                    style='Pink.Treeview',
                                    columns=('Port', 'Status', 'Service', 'Response'),
                                    show='headings')
        
        # Configurar ordenamiento para port_tree
        for col in ['Port', 'Status', 'Service', 'Response']:
            self.port_tree.heading(col, text=col,
                                 command=lambda c=col: self.treeview_sort_column(self.port_tree, c, False))
            self.port_tree.column(col, width=150)
        
        # Port Scrollbar
        port_scroll = ttk.Scrollbar(port_tree_frame,
                                  orient="vertical",
                                  command=self.port_tree.yview)
        self.port_tree.configure(yscrollcommand=port_scroll.set)
        
        # Pack port_tree and scrollbar
        self.port_tree.pack(side='left', fill='both', expand=True)
        port_scroll.pack(side='right', fill='y')
        
        # Añadir marca de fabricante en el encabezado
        header_label = tk.Label(root, text="TZOOTZ RESEARCH 2025®", bg=self.colors['dark_bg'], fg=self.colors['pearl'])
        header_label.pack(side='top', pady=5)
 
    def treeview_sort_column(self, tv, col, reverse):
        """Función para ordenar las columnas del Treeview"""
        l = [(tv.set(k, col), k) for k in tv.get_children('')]
        
        try:
            # Intenta convertir a número si es posible (para columnas como Port o IP)
            if col in ('Port', 'IP'):
                # Para IPs, convertir a tupla de números para ordenamiento correcto
                if col == 'IP':
                    l = [(tuple(map(int, k[0].split('.'))), k[1]) for k in l]
                else:
                    l = [(int(k[0]) if k[0].isdigit() else k[0], k[1]) for k in l]
        except ValueError:
            # Si no se puede convertir, mantener como string
            pass
        
        # Ordenar la lista
        l.sort(reverse=reverse)
        
        # Reorganizar elementos en el treeview
        for index, (val, k) in enumerate(l):
            tv.move(k, '', index)
        
        # Cambiar el orden la próxima vez que se haga clic
        tv.heading(col, command=lambda: self.treeview_sort_column(tv, col, not reverse))

    def on_network_select(self, event):
        selected_items = self.network_tree.selection()
        if selected_items:
            item = selected_items[0]
            ip = self.network_tree.item(item)['values'][0]
            self.ip_entry.delete(0, tk.END)
            self.ip_entry.insert(0, ip)

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def ping_host(self, ip):
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', ip]
        try:
            # Modificamos la decodificación para manejar errores
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, timeout=1)
            try:
                output = output.decode('utf-8', errors='ignore')
            except UnicodeDecodeError:
                output = output.decode('latin-1', errors='ignore')

            if platform.system().lower() == 'windows':
                if 'TTL=' in output:
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except:
                        hostname = 'Unknown'
                    return True, hostname, "Host is up"
            else:  # Para Linux/Mac
                if ' 0% packet loss' in output:
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except:
                        hostname = 'Unknown'
                    return True, hostname, "Host is up"
            return False, 'Unknown', "Host is down"
        except subprocess.TimeoutExpired:
            return False, 'Unknown', "Timeout"
        except Exception as e:
            return False, 'Unknown', "Error scanning host"

    def start_network_scan(self):
        if self.scanning_network:
            self.scanning_network = False
            self.network_status.config(text="Scan stopped")
            self.scan_network_btn.config(text="Scan Network")
            return
        
        self.scanning_network = True
        self.network_tree.delete(*self.network_tree.get_children())
        self.network_status.config(text="Scanning network...")
        self.scan_network_btn.config(text="Stop Scan")
        
        try:
            local_ip = self.get_local_ip()
            network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
            
            # Limpiar la cola antes de empezar
            while not self.network_queue.empty():
                self.network_queue.get()
            
            # Añadir IPs a la cola
            for ip in network.hosts():
                self.network_queue.put(str(ip))
            
            # Iniciar hilos de escaneo
            for _ in range(20):  # Aumentado a 20 hilos para más velocidad
                thread = threading.Thread(target=self.network_scanner_worker)
                thread.daemon = True
                thread.start()
                
        except Exception as e:
            self.network_status.config(text=f"Error: {str(e)}")
            self.scanning_network = False
            self.scan_network_btn.config(text="Scan Network")

    def network_scanner_worker(self):
        while self.scanning_network:
            try:
                ip = self.network_queue.get(timeout=1)
                is_up, hostname, response = self.ping_host(ip)
                status = "Up" if is_up else "Down"
                # Mostrar todas las IPs, no solo las activas
                self.network_tree.after(0, lambda i=ip, s=status, h=hostname, r=response: 
                    self.network_tree.insert('', 'end', values=(i, s, h, r)))
            except queue.Empty:
                break
            except Exception as e:
                print(f"Error scanning {ip}: {str(e)}")
        
        if self.network_queue.empty():
            self.scanning_network = False
            self.network_status.after(0, lambda: self.network_status.config(text="Scan complete"))
            self.scan_network_btn.after(0, lambda: self.scan_network_btn.config(text="Scan Network"))

    def scan_port(self, ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                result = s.connect_ex((ip, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "Unknown"
                    return "Open", service
                elif result in [111, 113]:  # Conexión rechazada o sin ruta
                 return "Closed", "N/A"
                elif result in [10061, 10051]:  # Errores específicos de red para Windows
                 return "Filtered", "N/A"
                else:
                 return "Filtered", "N/A"
        except socket.timeout:
            return "Filtered", "Timeout"
        except Exception as e:
            return "Error", str(e)

    def toggle_port_scan(self):
        if self.scanning_ports:
            self.scanning_ports = False
            self.scan_ports_btn.config(text="Scan Ports")
            return

        try:
            start = int(self.start_port.get())
            end = int(self.end_port.get())
            ip = self.ip_entry.get().strip()
            
            if not ip:
                raise ValueError("IP address is required")
            if start < 1 or start > 65535 or end < 1 or end > 65535:
                raise ValueError("Ports must be between 1 and 65535")
            if start > end:
                raise ValueError("Start port must be less than end port")
            
            socket.inet_aton(ip)
            
            self.scanning_ports = True
            self.scan_ports_btn.config(text="Stop Scan")
            self.port_tree.delete(*self.port_tree.get_children())
            
            # Limpiar la cola antes de empezar
            while not self.ports_queue.empty():
                self.ports_queue.get()
            
            for port in range(start, end + 1):
                self.ports_queue.put(port)
            
            for _ in range(min(50, end - start + 1)):  # Aumentado a 50 hilos
                thread = threading.Thread(target=self.port_scanner_worker, args=(ip,))
                thread.daemon = True
                thread.start()
                
        except ValueError as e:
            messagebox.showerror("Error", str(e))
            self.scanning_ports = False
            self.scan_ports_btn.config(text="Scan Ports")

    def port_scanner_worker(self, ip):
        while self.scanning_ports:
            try:
                port = self.ports_queue.get_nowait()
                status, service = self.scan_port(ip, port)
                response = f"Port {port} is {status}"
                
                # Mostrar todos los puertos, independientemente de su estado
                self.port_tree.after(0, lambda p=port, s=status, srv=service, r=response: 
                    self.port_tree.insert('', 'end', values=(p, s, srv, r)))
                
            except queue.Empty:
                break
            except Exception as e:
                print(f"Error scanning port: {str(e)}")
        
        if self.ports_queue.empty():
            self.scanning_ports = False
            self.scan_ports_btn.after(0, lambda: self.scan_ports_btn.config(text="Scan Ports"))

def main():
    root = tk.Tk()
    app = FundacionMosqueraScanner(root)
    root.mainloop()

if __name__ == "__main__":
    main()
