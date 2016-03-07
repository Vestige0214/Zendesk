from tkinter import *;
from tkinter import filedialog;
class IOC_GUI:
    import IOC_Controller;
    from tkinter import ttk;

    def __init__(self, mainframe):
        from tkinter import ttk;
        self.ioc_controller = self.IOC_Controller.IOC_Controller();
        root.title('IOC Scanner');
        mainframe = ttk.Frame(root, padding="3 3 12 12")
        mainframe.grid(column=0, row=0, sticky=(N, W, E, S))
        mainframe.columnconfigure(0, weight=1)
        mainframe.rowconfigure(0, weight=1)

        url = StringVar();
        ip = StringVar();
        self.file_path = StringVar();

        #Creating UI for scanning url/ip
        self.url_entry = ttk.Entry(mainframe, width=30, textvariable=url);
        self.url_entry.grid(column=2, row=1, sticky=(W, E));
        ttk.Label(mainframe, text='Url or IP Address').grid(column=1, row=1, sticky=E);
        scan_url_button = ttk.Button(mainframe, text='Scan URL or IP against VirusTotal', command=self.run_url_scanner);
        scan_url_button.grid(column = 3, row = 1, sticky = W);

        #Creating UI for scanning ip to honeypot
        self.ip_entry = ttk.Entry(mainframe, width=30, textvariable=ip);
        self.ip_entry.grid(column=2, row=2, sticky=(W, E));
        ttk.Label(mainframe, text='IP Address').grid(column=1, row=2, sticky=E);
        scan_ip_button = ttk.Button(mainframe, text='Scan IP against Honeypot Database', command=self.run_ip_scanner);
        scan_ip_button.grid(column = 3, row = 2, sticky = W);

        #Creating UI for file scan
        self.file_entry = ttk.Entry(mainframe, width=20);
        self.file_entry.grid(column = 2, row = 3, sticky = W);
        self.file_entry.config(state = DISABLED);
        ttk.Label(mainframe, text='File').grid(column=1, row=3, sticky=E);
        navigate_button = ttk.Button(mainframe, text='Choose File', command=self.choose_dialog);
        navigate_button.grid(column = 3, row = 3, sticky = W);
        self.scan_file_button = ttk.Button(mainframe, text='Scan File', command=self.run_file_scanner);
        self.scan_file_button.grid(column = 3, row = 3, sticky = E);
        self.scan_file_button.config(state=DISABLED);

        for child in mainframe.winfo_children(): child.grid_configure(padx=5, pady=5);
        self.url_entry.focus();
        root.mainloop();


    def run_url_scanner(self):
        input = self.url_entry.get();
        input = input.split(',');
        self.ioc_controller.run_url_scan(input);
        return;


    def run_ip_scanner(self):
        input = self.ip_entry.get();
        input = input.split(',');
        self.ioc_controller.run_ip_scan(input);
        return;

    def run_file_scanner(self):
        self.scan_file_button.config(state=DISABLED);
        self.file_entry.config(state=NORMAL);
        self.file_entry.delete(0, END);
        self.file_entry.config(state=DISABLED);
        self.ioc_controller.run_file_scan(self.file_path);
        return;

    def choose_dialog(self):
        import os
        self.file_path = filedialog.askopenfilename();
        if self.file_path:
            self.file_entry.config(state=WRITABLE);
            file_name = os.path.basename(self.file_path); #Creating the file name to display on the textbox
            self.file_entry.insert(0, file_name);
            self.file_entry.config(state=DISABLED);
            self.scan_file_button.config(state='Normal');
        return;


root = Tk();
ioc_gui = IOC_GUI(root);

