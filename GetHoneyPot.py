class GetHoneyPot():
    #code
    def Retrieve_HoneyPot(ip_list):
        import json
        from pprint import pprint
        from IPy import IP
        for ip in ip_list


        honeypot = 'honeypot.json';
        parsed_data = [];
        payload = [];
        with open(honeypot, 'r') as content_file:
            for line in content_file:
                parsed_line = json.loads(line);
                result = parsed_line['payload'].translate("\\");
                parsed_line['payload'] = json.loads(result);
                payload.append(parsed_line['payload']);
                parsed_data.append(parsed_line);
        pprint(payload);
        return;
g = GetHoneyPot();
g.Retrieve_HoneyPot();
