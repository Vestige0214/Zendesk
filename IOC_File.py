class IOC_File():
    apikey = 'd30793883fe463a65da276742c7df887';
    host = "https://scan.metadefender.com";
    import IOC_Helper
    import collections
    import requests
    def scan_file(self, file_path):
        ioc_helper = self.IOC_Helper;
        import os
        exceptions = self.requests.exceptions;
        file_name = os.path.basename(file_path);
        if os.path.isfile(file_path) == False:
            ioc_helper.log_error("The file does not exist");
            return;
        path = '/v2/file';
        url = self.host + path;
        headers = {'apikey' : self.apikey, 'filename' : file_name};
        with open(file_path, 'rb') as file:
            r = self.IOC_Helper.post(url, file, headers);
            if r != -1:
                response_dict = self.IOC_Helper.deserialize(r.content);
                data_id = response_dict['data_id'];
                rest_ip = response_dict['rest_ip'];
                return data_id, rest_ip;
            return;

    def retrieve_report(self, data_id, rest_ip):
        import time;
        ioc_helper = self.IOC_Helper;
        headers = {'apikey' : self.apikey};
        path = '/v2/file/' + data_id;
        url = self.host + path;
        time_out = time.time() + 60*5; #provided by stackoverflow Andrew Clark
        while True:
            r = self.IOC_Helper.get(url, headers);
            if r == -1:
                break;
            r = self.IOC_Helper.deserialize(r.content);
            if r['scan_results']['progress_percentage'] == 100:
                self.__print_result(r);
                break;
            if time.time() > time_out:
                ioc_helper.log_error('Timed out at 5 minutes for file scanning');
        return;

    def __print_result(self, r):
        ioc_helper = self.IOC_Helper;
        scan_results = r['scan_results'];
        file_info = r['file_info'];
        import datetime
        if scan_results['scan_all_result_i'] == 11:
            ioc_helper.log_error('Scan was aborted');
            return;
        if scan_results['scan_all_result_i'] == 1:
            with open('IOC_File_Result[' + ioc_helper.print_date_string() + '].txt', 'w') as result_file:
                result_file.write('File Name: ' + file_info['display_name'] + '\n');
                result_file.write('File Description: ' + file_info['file_type_description'] + '\n');
                result_file.write('File Size: ' + str(file_info['file_size']) + ' bytes\n\n');
                for element in scan_results['scan_details']:
                    scanner = scan_results['scan_details'][element];
                    if scanner['scan_result_i'] == 1:
                        result_file.write('Threat Found: ' + scanner['threat_found'] + '\n');
                        result_file.writelines('Source: ' + element + '\n\n');
        else:
            with open('IOC_File_Result[' + ioc_helper.print_date_string() + '].txt', 'w') as result_file:
                result_file.write(file_info['display_name'] + ' is clean\n');

