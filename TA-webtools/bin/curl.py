import sys
import traceback
import socket
import time
import re
import json
import requests
from typing import List, Dict, Optional, Union, Any
import splunk.Intersplunk
import splunk.mining.dcutils as dcu
from splunk.clilib import cli_common as cli

logger = dcu.getLogger()

# Template strings dictionary
url_templates = {
    "passwords": "https://%s:8089/servicesNS/-/%s/storage/passwords?output_mode=json&search=username%3D%s"
}

# Method aliases for shorthand reference
# Redundant but convenient
METHOD_ALIASES = {
    "get": "get", "g": "get",
    "head": "head", "h": "head",
    "patch": "patch",
    "post": "post", "p": "post",
    "put": "put",
    "delete": "delete", "del": "delete", "d": "delete"
}

def is_true(s) -> bool:
    """
    Determines whether the input value represents a boolean True.

    :param s: The value to evaluate. Can be a boolean or a string.
    :type s: Any
    :return: True if the input is a boolean True or a string representing a true value
    :rtype: bool
    """
    if type(s) is bool:
        return s
    if type(s) is not str:
        s = str(s)
    return s.lower() in ("yes", "y", "true", "t", "1")

# Get the keywords supplied to the command
def parse_args() -> Dict[str, str]:
    """
    Parses command-line arguments into a dictionary of option-value pairs.

    The function retrieves arguments either from Splunk's win32_utf8_argv or from sys.argv.
    Each argument should be in the format 'key=value'. Arguments are parsed and stored
    in a dictionary, where the key is the option name and the value is the corresponding value.
    Does not support quoted string values(?).

    :returns: Dictionary containing parsed option-value pairs from the command-line arguments.
    :rtype: dict
    """
    argv = splunk.Intersplunk.win32_utf8_argv() or sys.argv
    options = {}
    pattern = re.compile(r"^\s*([^=]+)=(.*)")
    if len(argv) > 1:
        for arg in argv[1:]:
            result = pattern.match(arg)
            if result:
                options[result.group(1)] = result.group(2)
    return options

def build_auth_headers(sessionKey=None, token=None) -> Dict[str, str]:
    """
    Builds authentication headers for HTTP requests using either a session key or a bearer token.

    :param sessionKey: The Splunk session key to use for authentication. If provided and `token` is not specified, the header will use the Splunk authentication scheme.
    :type sessionKey: str, optional
    :param token: The bearer token to use for authentication. If provided, the header will use the Bearer authentication scheme.
    :type token: str, optional

    :return: A dictionary containing the appropriate Authorization header. Returns an empty dictionary if neither `sessionKey` nor `token` is provided.
    :rtype: dict
    """
    if token:
        return {"Authorization": f"Bearer {token}"}
    elif sessionKey:
        return {"Authorization": f"Splunk {sessionKey}"}
    return {}

def getResponse(r) -> Dict[str, str]:
    """
    Constructs a response dictionary from a requests.Response object.

    :param r: The response object returned by the requests library.
    :type r: requests.Response

    :return: A dictionary containing the status code, response text, and URL.
    :rtype: dict
    """
    response = {
        'status': r.status_code,
        'message': r.text,
        'url': r.url
    }
    return response

def getException(e, uri):
    print(f"Caught exception accessing {uri}", file=sys.stderr)
    print(f"Exception details: {e}", file=sys.stderr)
    response = {'status': 408, 'message': str(e), 'url': uri}
    return(response)

def http_request(
    method: str,
    uri: str,
    sessionKey: Optional[str] = None,
    cert: Optional[Union[str, tuple]] = None,
    token: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    payload: Optional[Any] = None,
    timeout: int = 60,
    user: Optional[str] = None,
    password: Optional[str] = None
) -> Dict[str, Any]:
    """
    Executes an HTTP request using the specified parameters.

    :param method: The HTTP method to use (e.g., 'get', 'post', etc.).
    :type method: str
    :param uri: The target URI for the HTTP request.
    :type uri: str
    :param sessionKey: Splunk session key for authentication (optional).
    :type sessionKey: str, optional
    :param cert: Client certificate or (cert, key) tuple for SSL authentication (optional).
    :type cert: str or tuple, optional
    :param token: Bearer token for authentication (optional).
    :type token: str, optional
    :param headers: Additional HTTP headers to include in the request (optional).
    :type headers: dict, optional
    :param payload: Data or parameters to send with the request (optional).
    :type payload: Any, optional
    :param timeout: Timeout for the HTTP request in seconds (default is 60).
    :type timeout: int, optional
    :param user: Username for HTTP Basic authentication (optional).
    :type user: str, optional
    :param password: Password for HTTP Basic authentication (optional).
    :type password: str, optional

    :return: Dictionary containing the HTTP response status, message, and URL.
    :rtype: dict
    """
    try:
        allowed_methods = {"get", "post", "put", "delete", "patch", "head", "options"}
        method = METHOD_ALIASES.get(method.lower(), str(method.lower()))

        req_headers = headers if headers else {}
        req_headers.update(build_auth_headers(sessionKey, token))
        req_args = {
            "url": uri,
            "verify": True,
            "cert": cert,
            "headers": req_headers,
            "timeout": timeout
        }
        if user and password:
            req_args["auth"] = (user, password)
        if method in ["get", "head"]:
            req_args["params"] = payload
        else:
            req_args["data"] = payload

        if method in allowed_methods:
            r: requests.Response = getattr(requests, method)(**req_args)
            return getResponse(r)
        else:
            raise ValueError(f"HTTP method '{method}' is not allowed")
    except requests.exceptions.RequestException as e:
        return getException(e, uri)

def syntaxErr():
    """
    Handles and logs syntax errors for the curl command, generating an error result for Splunk.

    This function captures the current exception traceback, constructs a usage message for the curl command,
    sends the error to Splunk's Intersplunk error handler, and logs the error with the traceback.

    :returns: None
    :rtype: None
    :raises: This function does not raise exceptions but handles and logs them internally.
    """
    stack =  traceback.format_exc()
    e = "syntax: | curl [ choice: uri=<uri> OR urifield=<urifield> ] " \
        + "[ optional: method=<get | head | patch | post | put | delete> datafield=<datafield> "\
        + "data=<data> debug=<true | false> splunkauth=<true | false> "\
        + "splunkpasswdname=<username_in_passwordsconf> splunkpasswdcontext=<appcontext> timeout=<float> "\
        + "token=<splunk_auth_token> ]"
    splunk.Intersplunk.generateErrorResults(str(e))
    logger.error(str(e) + ". Traceback: " + str(stack))

def errorMsg(msg="This is the default error message"):
    """
    Logs an error message and generates error results for Splunk.

    This function captures the current exception traceback, logs the error message along with the traceback,
    and generates error results using Splunk's Intersplunk module.

    :param msg: The error message to log and display. Defaults to "This is the default error message".
    :type msg: str, optional

    :return: None

    :notes: This function assumes that `traceback`, `splunk.Intersplunk`, and `logger` are available in the scope.
    """
    stack =  traceback.format_exc()
    splunk.Intersplunk.generateErrorResults(str(msg))
    logger.error(str(msg) + ". Traceback: " + str(stack))

def enforceHTTPS(uri: Optional[str]=None):
    """
    Enforces that the given URI uses HTTPS protocol for Splunk Cloud instances.

    If the application is running in a Splunk Cloud environment, this function checks
    that the provided URI starts with "https://". If not, it logs an error and exits
    the program. If the URI is not a string or is empty, the function returns without action.

    :param uri: The URI to validate for HTTPS enforcement.
    :type uri: Optional[str]
    """
    if not isinstance(uri, str) or len(uri.strip()) == 0 or not cli.isCloudInstanceType():
        return
    # Enforce HTTPS for Splunk Cloud instance clients
    try:
        if not uri.startswith("https://"):
            errorMsg(f'uri field must start with "https://" and curl was provided with the following uri: "{str(uri)}"')
            quit()
    except Exception as e:
        errorMsg(str(e))
        quit()

def execute():
    """
    Execute the main logic for the curl.py Splunk custom search command.
    This function parses command-line arguments, retrieves previous search results,
    and performs HTTP requests (GET, POST, etc.) to specified URIs, optionally using
    credentials stored in Splunk or provided via arguments. It supports streaming and
    generating search modes, custom headers, data payloads, client certificates, and
    Splunk authentication. The results of the HTTP requests are appended to the Splunk
    search results, with optional debugging information.
    
    Raises:
        AssertionError: If the results or settings are not of the expected types.
        Exception: For any unexpected errors during execution, which are logged and
            reported as Splunk error results.
    Side Effects:
        - Outputs results to Splunk using `splunk.Intersplunk.outputResults`.
        - Logs errors and tracebacks using the logger.
        - May sleep between requests if the 'sleep' option is provided.
    Notes:
        - Requires options such as 'uri' or 'urifield' to be specified.
        - Handles Splunk credential retrieval and session authentication.
        - Enforces HTTPS for all outgoing requests for security (Splunk Cloud only).
        - Supports both static and per-result dynamic request parameters.
    """
    try:
        options = parse_args()
        user = None
        passwd = None
        results: List[Dict[str, Any]] = []
        settings: Dict[str, Any] = {}

        # get the previous search results
        results, _, settings = splunk.Intersplunk.getOrganizedResults()
        
        assert isinstance(results, list), "Results must be a list"
        assert isinstance(settings, dict), "Settings must be a dictionary"

        # some options are required, raise error and give syntax if they are not given
        if 'uri' not in options and 'urifield' not in options:
            results = []
            syntaxErr()
        else:
            # default to get method if none specified
            method: str = options.get('method', "get")
            # default to timeout=60
            timeout: int = int(options.get('timeout', 60))
            # default uri to None and force https
            uri: Optional[str] = options.get('uri')

            # use client certificate
            if 'clientcert' in options:
                cert: Optional[tuple] = (options.get('clientcert'), options.get('certkey'))
            else:
                cert = None

            # splunkpasswdcontext variable is optional, defaults to -
            splunkpasswdcontext = options.get('splunkpasswdcontext', "-")

            # splunkpasswdname variable is optional, defaults to None
            splunkpasswdname = options.get('splunkpasswdname')
            if splunkpasswdname:
                # Make a request to Splunk to get the specified credential
                headers = {}

                # Set the authentication header for the Splunk session key
                sessionKey = settings.get('sessionKey')
                if sessionKey:
                    headers = headers.update(build_auth_headers(sessionKey=sessionKey))
                hostname = socket.gethostname() or 'localhost'
                
                # Get the username and password for authentication
                url = url_templates['passwords'] % (hostname, splunkpasswdcontext, splunkpasswdname)
                json_res = requests.get(url, verify=True, headers=headers).json()
                if len(json_res['messages']) != 0:
                   if json_res['messages'][0]['type'] != "INFO":
                       splunk.Intersplunk.generateErrorResults(f"{str(json_res['messages'])} occurred while querying URL: {url}")
                       return
                if len(json_res['entry']) == 0:
                    splunk.Intersplunk.generateErrorResults(f"Username: {splunkpasswdname} not found in passwords.conf. URL: {url}")
                    return

                # At this point we did not get an error and we have zero or more results, cycle through and confirm we have a match
                passwd = None
                for entry in json_res['entry']:
                    if entry['content']['username'] == splunkpasswdname:
                        passwd = entry['content']['clear_password']
                        break
                if passwd is None:
                    splunk.Intersplunk.generateErrorResults(f"Username: {splunkpasswdname} not found in passwords.conf. URL: {url}")
                    return

                user = splunkpasswdname if user is None else user

            # If splunkauth is true, we use the sessionKey for authentication
            splunkauth = is_true(options.get('splunkauth', False))
            sessionKey = settings['sessionKey'] if splunkauth \
                    and 'splunkpasswdname' not in options \
                    else None

            user_headers = None
            if 'headers' in options:
                try:
                    # Parse the text as JSON
                    user_headers = json.loads(options['headers'])
                except json.JSONDecodeError:
                    user_headers = None
            
            token = options.get('token')
        
        # Determine results and search_mode
        if len(results) > 0:
            search_mode = 'streaming'
        else:
            search_mode = 'generating'
            # For non-streaming, create a single blank result
            results = [{}]

        sleepCounter = 0
        sleep = int(options['sleep']) if 'sleep' in options else None

        for result in results:
            # Sleep logic (only applies after first iteration and if 'sleep' is set)
            #https://github.com/bentleymi/ta-webtools/issues/4$
            #use sleep if provided sleep the defined amount after the first iteration$
            if sleep and sleepCounter > 0:
                time.sleep(sleep)
            sleepCounter += 1

            # URI logic
            if 'urifield' in options:
                uri_field: str = options['urifield']
                if uri_field and uri_field in result:
                    uri = result.get(uri_field)
                else:
                    continue
            elif 'uri' in options:
                uri = options.get('uri')
            if uri is None:
                continue

            # Headers logic
            if 'headerfield' in options and search_mode == 'streaming':
                header_field: str = options['headerfield']
                try:
                    headers = json.loads(result[header_field])
                except Exception:
                    headers = result[header_field]

            elif 'headers' in options:
                headers = user_headers
            else:
                headers = None

            # Data logic
            data: Union[None, dict, str] = None
            if 'data' in options:
                data = str(options.get('data', ''))
                if (data.startswith('[') and data.endswith(']')) or (data.startswith('{') and data.endswith('}')):
                    try:
                        # Parse the data as JSON, if possible
                        data = json.loads(data)
                    except Exception:
                        pass
            if 'datafield' in options and search_mode == 'streaming':
                # Parse the datafield as JSON
                data_field = options.get('datafield')
                if data_field and data_field in result:
                    data_text = str(result[data_field])
                    try:
                        data_field_data = json.loads(data_text)
                        # Update supplied data with the data field data
                        if isinstance(data, dict):
                            data.update(data_field_data)
                        else:
                            # Overwrite if not valid JSON format for both
                            data = data_field_data
                    except Exception:
                        data = data_text

            curl_result = {}
            if not uri in [None, ""]:
                # Check the uri and quit if not HTTPS (Splunk Cloud only)
                enforceHTTPS(uri)
                # Invoke the HTTP request
                curl_result = http_request(
                    method,
                    uri,
                    sessionKey,
                    cert,
                    token,
                    headers,
                    data,
                    timeout,
                    user,
                    passwd
                )

            # Debugging info
            if 'debug' in options and is_true(options['debug']):
                # Add debug fields to the result only if they have values
                for k, v in [
                    ('curl_method', method),
                    ('curl_uri', uri),
                    ('curl_splunkauth', splunkauth),
                    ('curl_data_payload', data),
                    ('curl_header', headers),
                    ('user_headers', user_headers),
                    ('curl_sleep', sleep),
                    ('curl_cert', cert[0] if cert and type(cert) is tuple else None),
                    ('curl_certkey', cert[1] if cert and type(cert) is tuple and cert[1] is not None else None),
                    ('curl_verifyssl', "Forced to be True for Splunk Cloud Compatibility" if cli.isCloudInstanceType() else None)
                ]:
                    if v is not None:
                        result[k] = v

                # Log the result URL as curl_redirect if it differs from the original
                if curl_result.get('url') != uri and not uri in [None, ""]:
                    curl_redirect = curl_result.get('url')
                    if curl_redirect:
                        result['curl_redirect'] = curl_redirect
            
            # Log the final curl status and message (content)
            result.update({
                'curl_status': curl_result.get('status'),
                'curl_message': curl_result.get('message')
            })

        # Write results to the Splunk search output
        splunk.Intersplunk.outputResults(results)

    except Exception as e:
        stack =  traceback.format_exc()
        splunk.Intersplunk.generateErrorResults(str(e))
        logger.error(str(e) + ". Traceback: " + str(stack))

if __name__ == '__main__':
    execute()
