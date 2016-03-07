class IOC_IP():
    import IOC_Helper
    import requests

    def scan_ip(self, *ip_list):
        ioc_helper = self.IOC_Helper;
        import ipaddress
        valid_ip_array = [];
        for ip in ip_list:  # skipping any invalid ip addresses
            try:
                valid_ip_array.append(str(ipaddress.ip_address(ip)));
            except ValueError:
                ioc_helper.log_error('%s is not a valid IP address' % ip);
                continue;
        if not valid_ip_array:
            ioc_helper.log_error('no valid IP addresses were provided');
            return;
        scan_id = self.scan_honeypot(valid_ip_array);

    def scan_honeypot(self, valid_ip_array):  # puts single items into a list with only that single item
        import json  # when a list is given, we dont want it in a list again so we unpack it using *
        import collections
        import datetime
        honeypot = 'honeypot.json';
        parsed_data = [];
        payload = [];
        with open('IOC_IP_Result[' + str(datetime.datetime.now()) + '].txt', 'w') as result_file:
            with open(honeypot, 'r') as content_file:  # running check against honeypot database
                for line in content_file:
                    parsed_line = json.loads(line);
                    result = parsed_line['payload'].translate("\\");
                    parsed_line['payload'] = json.loads(result);
                    var = collections.OrderedDict();
                    var = self.__match_ip_(valid_ip_array, parsed_line['payload']);
                    if var is not None:  # to increase efficiency result will be printed as we go through the database
                        var['Time stamp'] = parsed_line['timestamp']['$date'].split('T')[0];
                        for key in var:
                            result_file.write(key + ': ' + var[key] + '\n');
                        result_file.write('\n');

    def __match_ip_(self, valid_ip_array,
                    payload):  # function to find matches in ip from the current json item in honeypot
        import collections
        if 'victimIP' in payload:
            for ip in valid_ip_array:
                if payload['victimIP'] == ip:
                    victim = collections.OrderedDict();
                    victim['Information for Victim IP'] = ip;
                    victim['Attacker IP'] = payload['attackerIP'];
                    victim['Connection Type'] = payload['connectionType'];
                    victim['Source'] = 'Honeypot';
                    return victim;


g = IOC_IP();
g.scan_ip(*['4', '172.31.13.124', '54']);
