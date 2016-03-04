import requests
import json
def check_result(response):
    dict_error = {400: 'Bad Request', 401: 'Invalid API Key', 403: 'Scan limit reached',
                  403: 'No private scanning for account', 500: 'Server temporarily unavailable',
                  503: 'Server unable to handle request or too busy'}
    if response.status_code != requests.codes.ok:
        print(dict_error[response.status_code]);
        exit(0);


def post(url, body, headers):
    if headers == None:
        r = requests.post(url, body);
    else:
        r = requests.post(url, body, headers=headers);
    check_result(r);
    return r;


def get(url, headers):
    r = requests.get(url, headers=headers);
    check_result(r);
    return r;


def deserialize(content):
    return json.loads(content.decode('utf-8'));
