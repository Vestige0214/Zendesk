class IOC_File():
    apikey = 'd30793883fe463a65da276742c7df887';
    host = "https://scan.metadefender.com";
    import IOC_Helper
    import collections

    def scan_file(self, file_path):
        import os
        exceptions = self.requests.exceptions;
        file_name = os.path.basename(file_path);
        if os.path.isfile(file_path) == False:
            print("The file does not exist");
            return;
        path = '/v2/file';
        url = self.host + path;
        headers = {'apikey' : self.apikey, 'filename' : file_name};
        with open(file_path, 'rb') as file:
            r = self.post(url, file, headers);
        response_dict = self.deserialize(r.content);
        data_id = response_dict['data_id'];
        rest_ip = response_dict['rest_ip'];
        return data_id, rest_ip;

    def retrieve_report(self, data_id, rest_ip):
        headers = {'apikey' : self.apikey};
        path = '/v2/file/' + data_id;
        url = self.host + path;
        while True:
            r = self.get(url, headers);
            r = self.deserialize(r.content);
            if r['scan_results']['progress_percentage'] == 100:
                break;
        self.__print_result(r);
        return;

    def __print_result(self, r):
        scan_results = r['scan_results'];
        file_info = r['file_info'];
        import datetime
        if scan_results['scan_all_result_i'] == 11:
            print('Scan was aborted');
            return;
        if scan_results['scan_all_result_i'] == 1:
            with open('IOC_File_Result[' + str(datetime.datetime.now()) + '].txt', 'w') as result_file:
                result_file.write('File Name: ' + file_info['display_name'] + '\n');
                result_file.write('File Description: ' + file_info['file_type_description'] + '\n');
                result_file.write('File Size: ' + str(file_info['file_size']) + ' bytes\n\n');
                for element in scan_results['scan_details']:
                    scanner = scan_results['scan_details'][element];
                    if scanner['scan_result_i'] == 1:
                        result_file.write('Threat Found: ' + scanner['threat_found'] + '\n');
                        result_file.writelines('Source: ' + element + '\n\n');


    def __check_result(self, response):
        dict_error = {400 : 'Bad Request', 401 : 'Invalid API Key', 403 : 'Scan limit reached',
                      403 : 'No private scanning for account', 500 : 'Server temporarily unavailable',
                      503 : 'Server unable to handle request or too busy'}
        if response.status_code != self.requests.codes.ok:
            print(dict_error[response.status_code]);
            exit(0);

d = IOC_File();
data_id, rest_ip = d.scan_file('/Users/patterson/Downloads/dummyvir');
d.retrieve_report(data_id, rest_ip);


