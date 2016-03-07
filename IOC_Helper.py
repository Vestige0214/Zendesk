import requests
import json
import datetime
import logging
def check_result(response):
    try:
        response.raise_for_status();
    except requests.exceptions.HTTPError as e:
        log_exception(str(e.args));
        return True;


def post(url, body, headers):
    if headers == None:
        r = requests.post(url, body);
    else:
        r = requests.post(url, body, headers=headers);
    if check_result(r) == True:
        return -1;
    return r;


def get(url, headers):
    r = requests.get(url, headers=headers);
    if check_result(r) == True:
        return -1;
    return r;


def deserialize(content):
    return json.loads(content.decode('utf-8'));

def print_date_string():
    return str(datetime.datetime.now());

def get_time():
    return (datetime.time.now());

def check_url(url):
    from urllib.parse import urlparse
    result = urlparse(url);
    if (result[0] == '' or result[1] == ''):
        if result[0] == '':
            log_error("invalid url: " + url + " missing scheme\n");
        else:
            log_error("invalid url: " + url + " missing netloc\n");
        return False;
    return True;

def log_error(message):
    logging.error('[' + print_date_string() + ']' + message);

def log_exception(message):
    logging.exception('[' + print_date_string() + ']' + message);


# def write_entry(fd, result_dict, tuple):
#     for item in tuple:
#         fd.write(result_format(tuple, result_dict[tuple]));
#     fd.write('\n');
#
# def result_format(item, result):
#     return (item + ': ' + result + '\n');