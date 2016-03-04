class IOC_URL:
    import IOC_Helper
    import requests
    virustotal_url = "https://www.virustotal.com";
    virustotal_apikey = "5774a9be1829251dec549faf861bdffed45266bf988e138b625a20595a3f995b";

    def scan_virustotal(self, *valid_url_array):
        path = "/vtapi/v2/url/scan";
        headers = None;
        scan_url = self.virustotal_url + path;
        for url in valid_url_array:
            body = {'url': url, 'apikey': self.virustotal_apikey};
            r = self.IOC_Helper.post(scan_url, body, None);
            r = self.IOC_Helper.deserialize(r.content);
            return r['scan_id'];

    def report_virustotal(self, scan_id):
        report_url = self.virustotal_url + "/vtapi/v2/url/report";
        body = {'resource': scan_id, 'apikey': self.virustotal_apikey};
        while True:
            r = self.IOC_Helper.post(report_url, body, None);
            r = self.IOC_Helper.deserialize(r.content);
            if r['response_code'] == 1:
                break;
        return;
d = IOC_URL();
r = d.scan_virustotal('http://www.google.com');
d.report_virustotal(r);