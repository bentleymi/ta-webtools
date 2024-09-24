
import json
import requests
import splunk.Intersplunk
import splunk.mining.dcutils as dcu
import time
import traceback
import re
import sys
import socket 

logger = dcu.getLogger()

def getResponse(r,uri):
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

def get(uri,sessionKey,cert,token=None,headers=None,payload=None,user=None,password=None,timeout=60):
    try:
        if sessionKey == None and token == None:
            if user == None and password == None:
                r = requests.get(uri,params=payload,verify=True,cert=cert,headers=headers,timeout=timeout)
            else:
                r = requests.get(uri,auth=(user,password),params=payload,verify=True,cert=cert,headers=headers,timeout=timeout)
        elif token != None:
            headers = {}
            headers["Authorization"] = "Bearer %s" % token
            r = requests.get(uri,params=payload,verify=True,cert=cert,headers=headers,timeout=timeout)
        else:
            headers = {}
            headers["Authorization"] = "Splunk %s" % sessionKey
            r = requests.get(uri,params=payload,verify=True,cert=cert,headers=headers,timeout=timeout)
        return(getResponse(r,uri))
    except requests.exceptions.RequestException as e:
        return(getException(e,uri))

def head(uri,sessionKey,cert,token=None,headers=None,payload=None,user=None,password=None,timeout=60):
    try:
        if sessionKey == None and token == None:
            if user == None and password == None:
                r = requests.head(uri,params=payload,verify=True,cert=cert,headers=headers,timeout=timeout)
            else:
                r = requests.head(uri,auth=(user,password),params=payload,verify=True,cert=cert,headers=headers,timeout=timeout)
        elif token != None:
            headers = {}
            headers["Authorization"] = "Bearer %s" % token
            r = requests.head(uri,params=payload,verify=True,cert=cert,headers=headers,timeout=timeout)                
        else:
            headers = {}
            headers["Authorization"] = "Splunk %s" % sessionKey
            r = requests.head(uri,params=payload,verify=True,cert=cert,headers=headers,timeout=timeout)
        return(getResponse(r,uri))
    except requests.exceptions.RequestException as e:
        return(getException(e,uri))

def patch(uri,sessionKey,cert,token=None,headers=None,payload=None,user=None,password=None,timeout=60):
    try:
        if sessionKey == None and token == None:
            if user == None and password == None:
                r = requests.patch(uri,data=payload,verify=True,cert=cert,headers=headers,timeout=timeout)
            else:
                r = requests.patch(uri,auth=(user,password),data=payload,verify=True,cert=cert,headers=headers,timeout=timeout)
        elif token != None:
            headers = {}
            headers["Authorization"] = "Bearer %s" % token
            r = requests.patch(uri,params=payload,verify=True,cert=cert,headers=headers,timeout=timeout)                
        else:
            headers = {}
            headers["Authorization"] =  "Splunk %s" % sessionKey
            r = requests.patch(uri,data=payload,verify=True,cert=cert,headers=headers,timeout=timeout)
        return(getResponse(r,uri))
    except requests.exceptions.RequestException as e:
        return(getException(e,uri))

def post(uri,sessionKey,cert,token=None,headers=None,payload=None,user=None,password=None,timeout=60):
    try:
        if sessionKey == None and token == None:
            if user == None and password == None:
                r = requests.post(uri,data=payload,verify=True,cert=cert,headers=headers,timeout=timeout)
            else:
                r = requests.post(uri,auth=(user,password),data=payload,verify=True,cert=cert,headers=headers,timeout=timeout)
        elif token != None:
            headers = {}
            headers["Authorization"] = "Bearer %s" % token
            r = requests.post(uri,params=payload,verify=True,cert=cert,headers=headers,timeout=timeout)                
        else:
            headers = {}
            headers["Authorization"] =  "Splunk %s" % sessionKey
            r = requests.post(uri,data=payload,verify=True,cert=cert,headers=headers,timeout=timeout)
        return(getResponse(r,uri))
    except requests.exceptions.RequestException as e:
        return(getException(e,uri))

def put(uri,sessionKey,cert,token=None,headers=None,payload=None,user=None,password=None,timeout=60):
    try:
        if sessionKey == None and token == None:
            if user == None and password == None:
                r = requests.put(uri,data=payload,verify=True,cert=cert,headers=headers,timeout=timeout)
            else:
                r = requests.put(uri,auth=(user,password),data=payload,verify=True,cert=cert,headers=headers,timeout=timeout)
        elif token != None:
            headers = {}
            headers["Authorization"] = "Bearer %s" % token
            r = requests.put(uri,params=payload,verify=True,cert=cert,headers=headers,timeout=timeout)                
        else:
            headers = {}
            headers["Authorization"] =  "Splunk %s" % sessionKey
            r = requests.put(uri,data=payload,verify=True,cert=cert,headers=headers,timeout=timeout)
        return(getResponse(r,uri))
    except requests.exceptions.RequestException as e:
        return(getException(e,uri))


def delete(uri,sessionKey,cert,token=None,headers=None,payload=None,user=None,password=None,timeout=60):
    try:
        if sessionKey == None and token == None:
            if user == None and password == None:
                r = requests.delete(uri,data=payload,verify=True,cert=cert,headers=headers,timeout=timeout)
            else:
                r = requests.delete(uri,auth=(user,password),data=payload,verify=True,cert=cert,headers=headers,timeout=timeout)
        elif token != None:
            headers = {}
            headers["Authorization"] = "Bearer %s" % token
            r = requests.delete(uri,params=payload,verify=True,cert=cert,headers=headers,timeout=timeout)                
        else:
            headers = {}
            headers["Authorization"] = 'Splunk %s' % sessionKey
            r = requests.delete(uri,data=payload,verify=True,cert=cert,headers=headers,timeout=timeout)
        return(getResponse(r,uri))
    except requests.exceptions.RequestException as e:
        return(getException(e,uri))

def syntaxErr():
    results = None
    stack =  traceback.format_exc()
    e = "syntax: | curl [ choice: uri=<uri> OR urifield=<urifield> ] " \
    + "[ optional: method=<get | head | patch | post | put | delete> datafield=<datafield> "\
    + "data=<data> user=<user> pass=<password> debug=<true | false> splunkauth=<true | false> "\
    + "splunkpasswdname=<username_in_passwordsconf> splunkpasswdcontext=<appcontext> timeout=<float> "\
    + "token=<splunk_auth_token> ]"
    splunk.Intersplunk.generateErrorResults(str(e))
    logger.error(str(e) + ". Traceback: " + str(stack))
    return

def errorMsg(msg="This is the default error message"):
    results = None
    stack =  traceback.format_exc()
    splunk.Intersplunk.generateErrorResults(str(msg))
    logger.error(str(msg) + ". Traceback: " + str(stack))

def enforceHTTPS(uri=None):
    try:
        if re.search("^https:\/\/",uri) == None:
            errorMsg('uri field must start with "https://" and curl was provided with the following uri: "' + str(uri) + '"')
            quit()
    except Exception as e:
        errorMsg(str(e))
        quit()

def execute():
    try:
        # get the keywords suplied to the curl command
        argv = splunk.Intersplunk.win32_utf8_argv() or sys.argv

        # for each arg
        first = True
        options = {}
        pattern=re.compile("^\s*([^=]+)=(.*)")
        for arg in argv:
            if first:
                first = False
                continue
            else:
                result = pattern.match(arg)
                options[result.group(1)] = result.group(2)

        # get the previous search results
        results,dummyresults,settings = splunk.Intersplunk.getOrganizedResults()

        # some options are required, raise error and give syntax if they are not given
        if 'uri' not in options and 'urifield' not in options:
            results = None
            syntaxErr()
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

            # default uri to None and force https
            if 'uri' in options:
                uri = str(options['uri'])
            else:
                uri = None
            
            # use client certificate
            if 'clientcert' in options and 'certkey' in options:
                cert = options['clientcert'], options['certkey']
            elif 'clientcert' in options and not 'certkey' in options:
                cert = options['clientcert']
            else:
                cert = None

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
                hostname = socket.gethostname()
                url = "https://" + hostname + ":8089/servicesNS/-/" + splunkpasswdcontext + "/storage/passwords?output_mode=json&search=username%3D" + splunkpasswdname
                json_res = requests.get(url, verify=True, headers=headers).json()
                if len(json_res['messages']) != 0:
                   if json_res['messages'][0]['type'] != "INFO":
                       splunk.Intersplunk.generateErrorResults(str(json_res['messages']) + " occurred while querying URL: " + url)
                       return
                if len(json_res['entry']) == 0:
                    splunk.Intersplunk.generateErrorResults("Username: " + splunkpasswdname + " not found in passwords.conf. URL: " + url)
                    return

                # At this point we did not get an error and we have zero or more results, cycle through and confirm we have a match
                passwd = None
                for entry in json_res['entry']:
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
            if 'headers' in options:
                user_headers = json.loads(options['headers'])
            else:
                user_headers = None

            if 'token' in options:
                token = options['token']
            else:
                token = None

            # STREAMING Use Case: iterate through results and run curl commands
            if len(results) > 0:
                #https://github.com/bentleymi/ta-webtools/issues/4$
                #use sleep if provided sleep the defined amount after the first iteration$
                sleepCounter=0

                for result in results:
                    #https://github.com/bentleymi/ta-webtools/issues/4
                    #use sleep if provided sleep the defined amount after the first iteration
                    if 'sleep' in options:
                        sleep=int(options['sleep'])
                        if sleepCounter>0:
                            time.sleep(sleep)
                        sleepCounter=sleepCounter+1
                    else:
                        sleep=None

                    # use urifield if provided
                    if 'urifield' in options:
                        uri = result[options['urifield']]

                    # use JSON encoded header string if provided
                    if 'headerfield' in options:
                        headers = json.loads(result[options['headerfield']])
                    elif 'headers' in options:
                        headers = user_headers
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
                            result['curl_verifyssl'] = "Forced to be True for Splunk Cloud Compatibility"
                            result['curl_uri'] = uri
                            result['curl_splunkauth'] = splunkauth
                            if data != None:
                                result['curl_data_payload'] = data
                            if headers:
                                result['curl_header'] = headers
                            if user_headers:
                                result['user_headers'] = user_headers
                            if sleep:
                                result['curl_sleep'] = sleep
                            if cert:
                                if type(cert) is tuple:
                                    result['curl_cert'] = cert[0]
                                    result['curl_certkey'] = cert[1]
                                else:
                                    result['curl_cert'] = cert

                    # enforce HTTPS in uri field
                    enforceHTTPS(uri)

                    # based on method, execute appropriate function
                    if method.lower() in ("get","g"):
                        Result = get(uri,sessionKey,cert,token,headers,data,user,passwd,timeout)
                    if method.lower() in ("head","h"):
                        Result = head(uri,sessionKey,cert,token,headers,data,user,passwd,timeout)
                    if method.lower() in ("patch"):
                        Result = patch(uri,sessionKey,cert,token,headers,data,user,passwd,timeout)
                    if method.lower() in ("post","p"):
                        Result = post(uri,sessionKey,cert,token,headers,data,user,passwd,timeout)
                    if method.lower() in ("put"):
                        Result = put(uri,sessionKey,cert,token,headers,data,user,passwd,timeout)
                    if method.lower() in ("delete","del","d"):
                        Result = delete(uri,sessionKey,cert,token,headers,data,user,passwd,timeout)

                    # append the result to results in the splunk search pipeline
                    result['curl_status'] = Result['status']
                    result['curl_message'] = Result['message']

            # NON-STREAMING Use Case: do not iterate through results, just run curl command
            # this mode doesnt support headerfield but supports the header=<json> field
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
                        result['curl_verifyssl'] = "Forced to be True for Splunk Cloud compatibility"
                        result['curl_uri'] = uri
                        result['curl_splunkauth'] = splunkauth
                        if data!=None:
                            result['curl_data_payload'] = data
                        if user_headers:
                            result['user_headers'] = user_headers
                        if cert!=None:
                            if type(cert) is tuple:
                                result['curl_cert'] = cert[0]
                                result['curl_certkey'] = cert[1]
                            else:
                                result['curl_cert'] = cert

                # enforce HTTPS in uri field
                enforceHTTPS(uri)

                # based on method, esecute appropriate function
                if method.lower() in ("get","g"):
                    Result = get(uri,sessionKey,cert,token,user_headers,data,user,passwd,timeout)
                if method.lower() in ("head","h"):
                    Result = head(uri,sessionKey,cert,token,user_headers,data,user,passwd,timeout)
                if method.lower() in ("patch"):
                    Result = patch(uri,sessionKey,cert,token,user_headers,data,user,passwd,timeout)
                if method.lower() in ("post","p"):
                    Result = post(uri,sessionKey,cert,token,user_headers,data,user,passwd,timeout)
                if method.lower() in ("put"):
                    Result = put(uri,sessionKey,cert,token,user_headers,data,user,passwd,timeout)
                if method.lower() in ("delete","del","d"):
                    Result = delete(uri,sessionKey,cert,token,user_headers,data,user,passwd,timeout)

                # append the result to splunk result payload
                result['curl_status'] = Result['status']
                result['curl_message'] = Result['message']
                results.append(result)

        #output results
        splunk.Intersplunk.outputResults(results)

    except Exception as e:
        stack =  traceback.format_exc()
        splunk.Intersplunk.generateErrorResults(str(e))
        logger.error(str(e) + ". Traceback: " + str(stack))

if __name__ == '__main__':
    execute()

