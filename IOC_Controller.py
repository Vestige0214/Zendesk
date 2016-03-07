class IOC_Controller:
    import IOC_URL;
    import IOC_IP;
    import IOC_File;
    def run_url_scan(self, url_array):
        # [("http://" + url) if len(url) != 6 or url[0:6] != 'http://' else url for url in url_array];
        for index, url in enumerate(url_array):
            r = len(url);
            d = url[0:7];
            if len(url) < 7 or url[0:7] != 'http://':
                url_array[index] = 'http://' + url;
        scan_id = [];
        ioc_url = self.IOC_URL.IOC_URL();
        scan_id = ioc_url.scan_virustotal(url_array);
        if scan_id:
            ioc_url.report_virustotal(scan_id);
        return;


    def run_ip_scan(self, ip_array):
        scan_id = [];
        ioc_ip = self.IOC_IP.IOC_IP();
        scan_id = ioc_ip.scan_ip(ip_array);
        return;

    def run_file_scan(self, file_path):
        ioc_file = self.IOC_File.IOC_File();
        data_id, rest_ip = ioc_file.scan_file(file_path);
        if data_id and rest_ip:
            ioc_file.retrieve_report(data_id, rest_ip);
        return;
