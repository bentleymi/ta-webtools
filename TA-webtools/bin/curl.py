### Author: Michael Camp Bentley aka JKat54
### Contributors: Bert Shuler, Alex Cerier, Gareth Anderson
### Copyright 2019 Michael Camp Bentley
###
### Licensed under the Apache License, Version 2.0 (the "License");
### you may not use this file except in compliance with the License.
### You may obtain a copy of the License at
###
###    http://www.apache.org/licenses/LICENSE-2.0
###
### Unless required by applicable law or agreed to in writing, software
### distributed under the License is distributed on an "AS IS" BASIS,
### WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
### See the License for the specific language governing permissions and
### limitations under the License.
###
### SCRIPT NAME: curl.py
### Description: splunk search command for posting or getting from external api's.
### Doesnt use the HTTP_PROXY or HTTPS_PROXY defined in splunk-launch.conf

import json
import requests
import splunk.Intersplunk
import splunk.mining.dcutils as dcu
import traceback

logger = dcu.getLogger()

def getResponse(r,uri):
    if r.status_code <= 399:
        response = {}
        response['status'] = r.status_code
        response['message'] = r.text
        response['url'] = r.url
        return(response)
    else:
        response = {}
        response['status'] = r.status_code
        response['message'] = r.text
        response['url'] = r.url
        return(response)

def getException(e,uri):
    response = {}
    response['status'] = 408
    response['message'] = str(e)
    response['url'] = uri
    return(response)

def get(uri,sessionKey,verifyssl,headers=None,payload=None,user=None,password=None,timeout=60):
    try:
        if sessionKey == None:
            if user == None and password == None:
                r = requests.get(uri,params=payload,verify=verifyssl, headers=headers, timeout=timeout)
            else:
                r = requests.get(uri,auth=(user,password),params=payload,verify=verifyssl,headers=headers,timeout=timeout)
        else:
            headers = {}
            headers["Authorization"] = "Splunk %s" % sessionKey
            r = requests.get(uri,params=payload,verify=verifyssl,headers=headers,timeout=timeout)
        return(getResponse(r,uri))
    except requests.exceptions.RequestException as e:
        return(getException(e,uri))

def head(uri,sessionKey,verifyssl,headers=None,payload=None,user=None,password=None,timeout=60):
    try:
        if sessionKey == None:
            if user == None and password == None:
                r = requests.head(uri,params=payload,verify=verifyssl, headers=headers, timeout=timeout)
            else:
                r = requests.head(uri,auth=(user,password),params=payload,verify=verifyssl,headers=headers,timeout=timeout)
        else:
            headers = {}
            headers["Authorization"] = "Splunk %s" % sessionKey
            r = requests.head(uri,params=payload,verify=verifyssl,headers=headers,timeout=timeout)
        return(getResponse(r,uri))
    except requests.exceptions.RequestException as e:
        return(getException(e,uri))

def post(uri,sessionKey,verifyssl,headers=None,payload=None,user=None,password=None,timeout=60):
    try:
        if sessionKey == None:
            if user == None and password == None:
                r = requests.post(uri,data=payload,verify=verifyssl, headers=headers, timeout=timeout)
            else:
                r = requests.post(uri,auth=(user,password),data=payload,verify=verifyssl,headers=headers,timeout=timeout)
        else:
            headers = {}
            headers["Authorization"] =  'Splunk %s' % sessionKey
            r = requests.post(uri,data=payload,verify=verifyssl,headers=headers,timeout=timeout)
        return(getResponse(r,uri))
    except requests.exceptions.RequestException as e:
        return(getException(e,uri))

def put(uri,sessionKey,verifyssl,headers=None,payload=None,user=None,password=None,timeout=60):
    try:
        if sessionKey == None:
            if user == None and password == None:
                r = requests.put(uri,data=payload,verify=verifyssl, headers=headers, timeout=timeout)
            else:
                r = requests.put(uri,auth=(user,password),data=payload,verify=verifyssl,headers=headers,timeout=timeout)
        else:
            headers = {}
            headers["Authorization"] =  'Splunk %s' % sessionKey
            r = requests.put(uri,data=payload,verify=verifyssl,headers=headers,timeout=timeout)
        return(getResponse(r,uri))
    except requests.exceptions.RequestException as e:
        return(getException(e,uri))


def delete(uri,sessionKey,verifyssl,headers=None,payload=None,user=None,password=None,timeout=60):
    try:
        if sessionKey == None:
            if user == None and password == None:
                r = requests.delete(uri,data=payload,verify=verifyssl, headers=headers, timeout=timeout)
            else:
                r = requests.delete(uri,auth=(user,password),data=payload,verify=verifyssl,headers=headers,timeout=timeout)
        else:
            headers = {}
            headers["Authorization"] = 'Splunk %s' % sessionKey
            r = requests.delete(uri,data=payload,verify=verifyssl,headers=headers,timeout=timeout)
        return(getResponse(r,uri))
    except requests.exceptions.RequestException as e:
        return(getException(e,uri))

def error():
    results = None
    stack =  traceback.format_exc()
    e = "syntax: curl uri=<uri> " \
    + "[ optional: method=<get | head | post | delete> verifyssl=<true | false> datafield=<field_name> "\
    + "data=<data> user=<user> pass=<password> debug=<true | false> splunkauth=<true | false> "\
    + "splunkpasswdname=<username_in_passwordsconf> splunkpasswdcontext=<appcontext (optional)> timeout=30 ]" \
    + "\texample: curl method=get verifyssl=true uri=https://localhost:8089 " \
    + 'data="TEST" user="username" pass="password" splunkauth="true"'
    splunk.Intersplunk.generateErrorResults(str(e))
    logger.error(str(e) + ". Traceback: " + str(stack))

def execute():
    try:

        # get the keywords suplied to the curl command
        keywords, options = splunk.Intersplunk.getKeywordsAndOptions()

        # get the previous search results
        results,dummyresults,settings = splunk.Intersplunk.getOrganizedResults()

        # some options are required, raise error and give syntax if they are not given
        if 'uri' not in options:
            results = None
            error()
        else:
            # default to get method if none specified
            if 'method' not in options:
                method = "get"
            else:
                method = str(options['method'])

            # default to timeout=60
            if 'timeout' in options:
                timeout = float(options['timeout'])
            else:
                timeout = 60

            # uri must be provided else you couldnt make it here, so then get the URI from the options provided
            uri = str(options['uri'])

            # verifyssl variable is required, so if not specified, it should = False
            if 'verifyssl' not in options:
                verifyssl = False
            else:
                if options['verifyssl'].lower() in ("y","yes", "true", "t", "1"):
                    verifyssl = True
                else:
                    verifyssl = False

            # user variable is required, so if not specified, it should = None
            if 'user' not in options:
                user = None
            else:
                user = options['user']

            # passwd variable is required, so if not specified, it should = None
            if 'pass' not in options:
                # handle if user gives "password" instead of "pass"
                if 'password' in options:
                    passwd = options['password']
                passwd = None
            else:
                passwd = options['pass']

            # splunkpasswdcontext variable is optional, defaults to -
            if 'splunkpasswdcontext' not in options:
                splunkpasswdcontext = "-"
            else:
                splunkpasswdcontext = options['splunkpasswdcontext']

            # splunkpasswdname variable is optional, defaults to None
            if 'splunkpasswdname' not in options:
                splunkpasswdname = None
            else:
                splunkpasswdname = options['splunkpasswdname']
                sessionKey = settings['sessionKey']
                headers={'Authorization': 'Splunk ' + sessionKey }
                url = "https://localhost:8089/servicesNS/-/" + splunkpasswdcontext + "/storage/passwords?output_mode=json&search=username%3D" + splunkpasswdname
                json = requests.get(url, verify=False, headers=headers).json()
                if len(json['messages']) != 0:
                   if json['messages'][0]['type'] != "INFO":
                       splunk.Intersplunk.generateErrorResults(str(json['messages']) + " occurred while querying URL: " + url)
                       return
                if len(json['entry']) == 0:
                    splunk.Intersplunk.generateErrorResults("Username: " + splunkpasswdname + " not found in passwords.conf. URL: " + url)
                    return

                # At this point we did not get an error and we have zero or more results, cycle through and confirm we have a match
                passwd = None
                for entry in json['entry']:
                    if entry['content']['username'] == splunkpasswdname:
                        passwd = entry['content']['clear_password']
                        break
                if passwd is None:
                    splunk.Intersplunk.generateErrorResults("Username: " + splunkpasswdname + " not found in passwords.conf. URL: " + url)
                    return

                if user is None:
                    user = splunkpasswdname

            # use splunk session key / auth or not
            if 'splunkauth' not in options:
                sessionKey = None
                splunkauth = False
            else:
                if options['splunkauth'].lower() in ("y","yes", "true", "t", "1"):
                    sessionKey = settings['sessionKey']
                    splunkauth = True
                else:
                    sessionKey = None

            # STREAMING Use Case: iterate through results and run curl commands
            if len(results) > 0:
                for result in results:
                    # use JSON encoded header string if provided
                    if 'headerfield' in options:
                        headers = json.loads(result[options['headerfield']])
                    else:
                        headers = None

                    # if data in options, set data = options['data']
                    if 'data' in options:
                        data = str(options['data'])

                    # if datafield in options, set datafield = options['datafield']
                    if 'datafield' in options:
                        try:
                            data = json.loads(result[options['datafield']])
                        except:
                            data = str(result[options['datafield']])
                    else:
                        data = None

                    # debugging option
                    if 'debug' in options:
                        if options['debug'].lower() in ("yes", "true", "t", "1"):
                            # for debugging we add results which show the options \
                            # that were sent to the curl command
                            result['curl_method'] = method
                            result['curl_verifyssl'] = verifyssl
                            result['curl_uri'] = uri
                            result['curl_splunkauth'] = splunkauth
                            if data != None:
                                result['curl_data_payload'] = data
                            if headers:
                                result['curl_header'] = headers

                    # based on method, execute appropriate function
                    if method.lower() in ("get","g"):
                        Result = get(uri,sessionKey,verifyssl,headers,data,user,passwd,timeout)
                    if method.lower() in ("head","h"):
                        Result = head(uri,sessionKey,verifyssl,headers,data,user,passwd,timeout)
                    if method.lower() in ("post","p"):
                        Result = post(uri,sessionKey,verifyssl,headers,data,user,passwd,timeout)
                    if method.lower() in ("put"):
                        Result = put(uri,sessionKey,verifyssl,headers,data,user,passwd,timeout)
                    if method.lower() in ("delete","del","d"):
                        Result = delete(uri,sessionKey,verifyssl,headers,data,user,passwd,timeout)

                    # append the result to results in the splunk search pipeline
                    result['curl_status'] = Result['status']
                    result['curl_message'] = Result['message']
                    result['curl_response_url'] = Result['url']

            # NON-STREAMING Use Case: do not iterate through results, just run curl command
            # this mode doesnt support headers
            else:
                # build splunk result payload
                result={}
                results=[]

                # if user specifed data manually
                if 'data' in options:
                    data = str(options['data'])
                else:
                    data = None

                # debug option
                if 'debug' in options:
                    if options['debug'].lower() in ("yes", "true", "t", "1"):
                        # for debugging we add results which show the options \
                        # that were sent to the curl command
                        result['curl_method'] = method
                        result['curl_verifyssl'] = verifyssl
                        result['curl_uri'] = uri
                        result['curl_splunkauth'] = splunkauth
                        if data!=None:
                            result['curl_data_payload'] = data

                # based on method, esecute appropriate function
                if method.lower() in ("get","g"):
                    Result = get(uri,sessionKey,verifyssl,None,data,user,passwd,timeout)
                if method.lower() in ("head","h"):
                    Result = head(uri,sessionKey,verifyssl,None,data,user,passwd,timeout)
                if method.lower() in ("post","p"):
                    Result = post(uri,sessionKey,verifyssl,None,data,user,passwd,timeout)
                if method.lower() in ("put"):
                    Result = put(uri,sessionKey,verifyssl,None,data,user,passwd,timeout)
                if method.lower() in ("delete","del","d"):
                    Result = delete(uri,sessionKey,verifyssl,None,data,user,passwd,timeout)

                # append the result to splunk result payload
                result['curl_status'] = Result['status']
                result['curl_message'] = Result['message']
                result['curl_response_url'] = Result['url']
                results.append(result)

        #output results
        splunk.Intersplunk.outputResults(results)

    except Exception, e:
        stack =  traceback.format_exc()
        splunk.Intersplunk.generateErrorResults(str(e))
        logger.error(str(e) + ". Traceback: " + str(stack))

if __name__ == '__main__':
    execute()

