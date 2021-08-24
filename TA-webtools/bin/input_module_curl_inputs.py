# encoding = utf-8

import json
import requests
from distutils import util
'''
    IMPORTANT
    Edit only the validate_input and collect_events functions.
    Do not edit any other part in this file.
    This file is generated only once when creating the modular input.
'''
'''
# For advanced users, if you want to create single instance mod input, uncomment this method.
def use_single_instance_mode():
    return True
'''

def validate_input(helper, definition):
    """Implement your own validation logic to validate the input stanza configurations"""
    # This example accesses the modular input variable
    # http_method = definition.parameters.get('http_method', None)
    # uri = definition.parameters.get('uri', None)
    # verify_ssl = definition.parameters.get('verify_ssl', None)
    # payload = definition.parameters.get('payload', None)
    # username = definition.parameters.get('username', None)
    # password = definition.parameters.get('password', None)
    pass

def collect_events(helper, ew):
    method = helper.get_arg('http_method')
    uri = helper.get_arg('uri')
    verifyssl = bool(int(helper.get_arg('verify_ssl')))
    header = helper.get_arg('request_headers')
    payload = helper.get_arg('payload')
    user = helper.get_arg('username')
    passwd = helper.get_arg('password')
    auth = (user, passwd)    
    if method.lower() in ("get","g"):
        method = "get"
    if method.lower() in ("post","put","p"):
        method = "post"
    if method.lower() in ("delete","del","d"):
        method = "delete"
    if len(payload)>0:
        payload = json.loads(payload)
    else:
        payload = None
    if len(header)>0:
        headers=json.loads(header)
    else:
        headers=None
    if (bool(user)==False and bool(passwd)==False):
        auth=None
    
    data = {}
    data['curl_uri'] = uri
    data['curl_method'] = method
    data['curl_header'] = headers        
    data['curl_verifyssl'] = verifyssl
    data['curl_payload'] = payload
    
    try:
        r = requests.request(method, uri, auth=auth, data=payload, headers=headers, cookies=None, verify=verifyssl, cert=None, timeout=None)
        data['curl_response'] = r.text
        data['curl_status'] = r.status_code

    except Exception as e:
        data = {}
        data['curl_response'] = str(e)
        data['curl_status'] = "An exception occured when attempting the request.  The exception will be shown in the curl_response field."


    event = helper.new_event(source=helper.get_input_type(), index=helper.get_output_index(), sourcetype=helper.get_sourcetype(), data=json.dumps(data, sort_keys=True))
    ew.write_event(event)
