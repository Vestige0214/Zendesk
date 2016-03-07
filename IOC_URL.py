class IOC_URL:
    import IOC_Helper
    import requests
    virustotal_url = "https://www.virustotal.com";
    virustotal_apikey = "5774a9be1829251dec549faf861bdffed45266bf988e138b625a20595a3f995b";

    def scan_virustotal(self, valid_url_array):
        ioc_helper = self.IOC_Helper;
        result = [];
        path = "/vtapi/v2/url/scan";
        headers = None;
        scan_url = self.virustotal_url + path;
        for url in valid_url_array:
            url = ioc_helper.check_url(url);
            if url != -1: #Check will return the url with proper scheme, only when netloc is missing will it return -1
                body = {'url': url, 'apikey': self.virustotal_apikey};
                r = self.IOC_Helper.post(scan_url, body, None);
                if r != -1 and r.status_code == 200:
                        r = self.IOC_Helper.deserialize(r.content);
                        if r['response_code'] == -1:
                            ioc_helper.log_error(r['verbose_msg'] + " URL: " + url);
                        else:
                            result.append(r['scan_id']);
        return result;

    def report_virustotal(self, scan_id_array):
        import time
        ioc_helper = self.IOC_Helper;
        report_url = self.virustotal_url + "/vtapi/v2/url/report";
        with open('IOC_URL_Results[' + self.IOC_Helper.print_date_string() + '].txt', 'w') as result_file:
            for scan_id in scan_id_array:
                body = {'resource': scan_id, 'apikey': self.virustotal_apikey};
                time_out = time.time() + 60*5; #provided by stackoverflow Andrew Clark
                while True:
                    r = self.IOC_Helper.post(report_url, body, None);
                    if r.status_code == 200:
                        r = self.IOC_Helper.deserialize(r.content);
                        if r['response_code'] == 1:
                            self.__print_result(result_file, r);
                            break;
                        if r['response_code'] == 0:
                            result_file.write("The" + r['url'] + "is not in VirusTotal database");
                            break;
                    if (time.time() > time_out): #set to timeout after 5minutes
                        ioc_helper.log_error('Timed out at 5 minutes for URL Scanning');
                        break;
        return;

    def __print_result(self, fd, r):
        ioc_helper = self.IOC_Helper;
        scan_result = r['positives'];
        if scan_result != 0:
            fd.write('Compromised Url: ' + r['url'] + '\n');
            fd.write('Scan date: ' + r['scan_date'] + '\n');
            scans = r['scans'];
            for scan in scans:
                if scans[scan]['detected'] == True:
                    fd.write('Source: ' + scan + '\n');
                    fd.write('Result: ' + scans[scan]['result'] + '\n\n');
        else:
            fd.write('Url: ' + r['url'] + ' is safe\n\n');