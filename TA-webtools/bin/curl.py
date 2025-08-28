import sys
import os
import traceback
import socket
import time
import re
import json
import urllib3
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

# region: Functions

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

def is_str_bool(s: str, include_numbers: bool = False) -> bool:
    if include_numbers:
        return s.lower() in ("yes", "y", "true", "t", "no", "n", "false", "f", "1", "0")
    return s.lower() in ("yes", "y", "true", "t", "1", "no", "n", "false", "f")

def is_str_obj(s: str) -> bool:
    return (s[:1] == '[' and s[-1:] == ']') or (s[:1] == '{' and s[-1:] == '}')

def str_to_type(s: str) -> Union[str, int, float, bool, List[Any], Dict[str, Any]]:
    # Object/list
    if is_str_obj(s):
        try:
            return json.loads(s)
        except json.JSONDecodeError:
            return s
    else:
        # Try to convert to int
        try:
            return int(s)
        except ValueError:
            # Try to convert to float
            try:
                return float(s)
            except ValueError:
                if is_str_bool(s, include_numbers=True):
                    return is_true(s)
                return s

def merge_two_dicts(x, y) -> dict:
    """ Merge two dictionaries """
    try:
        # Python 3.9+
        return x | y
    except:
        try:
            return {**x, **y}
        except Exception as e:
            print("Error merging dictionaries", file=sys.stderr)
            raise e

# Get the keywords supplied to the command
def parse_args() -> Dict[str, Union[str, int, float, bool, List[Any], Dict[str, Any]]]:
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
    options: Dict[str, Union[str, int, float, bool, List[Any], Dict[str, Any]]] = {}
    pattern = re.compile(r"^\s*([^=]+)=(.*)")
    if len(argv) > 1:
        for arg in argv[1:]:
            result = pattern.match(arg)
            if result:
                options[result.group(1)] = str_to_type(result.group(2))
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

def get_proxy_settings() -> Dict[str, str]:
    """ Get the proxy settings from the configuration """
    proxy_config = cli.getConfStanza('server', 'proxyConfig')
    proxy_setting_keys = ['http_proxy', 'https_proxy', 'no_proxy']
    proxy_settings = {}
    for k in proxy_setting_keys:
        # Use the environment variable if not found in the config
        env_setting = os.environ.get(k.upper(), None)
        splunk_serverconf_setting = proxy_config.get(k, None)
        if env_setting or splunk_serverconf_setting:
            proxy_settings[k] = splunk_serverconf_setting if splunk_serverconf_setting else env_setting
    return proxy_settings

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

def http_request(
    method: str,
    uri: str,
    payload: Optional[str] = None,
    verify: bool = True,
    proxies: Optional[Dict[str, str]] = None,
    **kwargs
) -> Dict[str, Any]:
    """
    Executes an HTTP request using the specified parameters.

    :param method: The HTTP method to use (e.g., 'get', 'post', etc.).
    :type method: str
    :param uri: The target URI for the HTTP request.
    :type uri: str
    :param payload: Data or parameters to send with the request (optional).
    :type payload: Any, optional
    :param user: Username for HTTP Basic authentication (optional).
    :type user: Optional[str]
    :param password: Password for HTTP Basic authentication (optional).
    :type password: Optional[str]
    :param **kwargs: Additional keyword arguments passed to the underlying requests method.
        - cert (str or tuple, optional): Client certificate or (cert, key) tuple for SSL authentication.
        - headers (dict, optional): HTTP headers to include in the request.
        - timeout (int, optional): Timeout for the HTTP request in seconds (default is 60).
        - proxies (dict, optional): Proxy configuration for the request.
        - verify (bool or str, optional): Whether to verify the server's TLS certificate or path to a CA bundle.
        - allow_redirects (bool, optional): Set to True by default for GET/OPTIONS/HEAD requests.
        - stream (bool, optional): Whether to stream the response content.
        - any other keyword arguments supported by the requests library.
    
    :returns: Dictionary containing the HTTP response status, message, and URL.
    :raises ValueError: If the HTTP method is not allowed.
    :return: Dictionary containing the HTTP response status, message, and URL.
    :rtype: dict
    """
    try:
        allowed_methods = {"get", "post", "put", "delete", "patch", "head", "options"}
        method = METHOD_ALIASES.get(method.lower(), str(method.lower()))

        # Identify if the request is local
        # Extract host (without port) from URI, supporting IPv6 and other hosts
        match = re.match(r'^https?://(\[[^\]]+\]|[^:/]+)', uri)
        url_host = match.group(1) if match else ''
        url_host = url_host.strip('[]')
        is_local = url_host in ['localhost', '127.0.0.1', '::1']
        
        proxies = proxies if proxies is not None else {}
        if is_local:
            # Disable SSL verification for local requests
            verify = False
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            if proxies:
                # Set no_proxy to ignore localhost and loopback IP range
                if proxies.get("no_proxy") is None:
                    proxies.update({"no_proxy": f"{socket.gethostname()},localhost,127.0.0.1,::1"})
        

        if method in ["get", "head"] and payload is not None:
            payload_field = 'params'
        elif payload is not None:
            payload_field = 'data'

        req_args: Dict[str, Union[str, int, tuple, Dict]] = {
            "url": uri,
            "proxies": proxies,
            "verify": verify,
        }
        if payload is not None:
            req_args[payload_field] = payload

        # Merge argument dicts
        all_args = merge_two_dicts(req_args, kwargs)
        if method in allowed_methods:
            r: requests.Response = getattr(requests, method)(**all_args)
            return getResponse(r)
        else:
            raise ValueError(f"HTTP method '{method}' is not allowed")
    except requests.exceptions.RequestException as e:
        return getException(e, uri)

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

# region: Error handling

def getException(e, uri):
    print(f"Caught exception accessing {uri}", file=sys.stderr)
    print(f"Exception details: {e}", file=sys.stderr)
    response = {'status': 408, 'message': str(e), 'url': uri}
    return(response)

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

# region: Main

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
        user: Optional[str] = None
        passwd: Optional[str] = None
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
            method: str = str(options.get('method', "get"))
            # default to timeout=60
            timeout = options.get('timeout', 60)
            # default uri to None and force https
            uri: Optional[str] = str(options['uri']) if 'uri' in options else None
            verifyssl: bool = bool(options.get('verifyssl', True)) if not cli.isCloudInstanceType() else True

            cert: Optional[tuple] = None
            # use client certificate
            if 'clientcert' in options:
                cert: Optional[tuple] = (str(options.get('clientcert')), str(options.get('certkey')))

            # splunkpasswdcontext variable is optional, defaults to -
            splunkpasswdcontext: str = str(options.get('splunkpasswdcontext', "-"))

            # splunkpasswdname variable is optional, defaults to None
            splunkpasswdname: Optional[str] = str(options['splunkpasswdname']) if 'splunkpasswdname' in options else None
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
            
            # Get the auth options from the search string
            token = options.get('token')
            sessionKey = settings['sessionKey'] if splunkauth \
                    and 'splunkpasswdname' not in options \
                    else None

            base_headers = {}
            if 'headers' in options:
                if not isinstance(options['headers'], dict):
                    errorMsg("Invalid JSON format in 'headers' option")
                    return
                base_headers.update(options['headers'])

            if splunkauth:
                base_headers.update(build_auth_headers(sessionKey=sessionKey, token=token))
        
        # Determine results and search_mode
        if len(results) > 0:
            search_mode = 'streaming'
        else:
            search_mode = 'generating'
            # For non-streaming, create a single blank result
            results = [{}]

        sleepCounter = 0
        sleep: Optional[float] = float(options['sleep']) if 'sleep' in options else None # type: ignore
        clean_result: Optional[bool] = bool(options.get('clean', False))

        ran_request = False
        for result in results:
            # Sleep logic (only applies after first iteration and if 'sleep' is set)
            # https://github.com/bentleymi/ta-webtools/issues/4$
            # Sse sleep if provided sleep the defined amount after the first iteration$
            if sleep and sleepCounter > 0 and ran_request:
                time.sleep(sleep)
            sleepCounter += 1

            # URI logic
            if 'urifield' in options:
                uri_field: Optional[str] = options.get('urifield') # type: ignore
                if uri_field and uri_field in result and len(result[uri_field]) > 0:
                    uri = result[uri_field]
                else:
                    # Skip this result
                    continue
            if uri is None:
                continue

            # Headers logic
            event_headers = {}
            if 'headerfield' in options and search_mode == 'streaming':
                header_field: str = str(options['headerfield'])
                try:
                    event_headers = json.loads(result[header_field])
                except Exception:
                    event_headers = result[header_field]

            headers = merge_two_dicts((base_headers if base_headers else {}), event_headers)
            # Data logic
            data: Optional[Union[Dict[str, Any], List[Any], str, int, float, bool]] = None
            if 'data' in options:
                # Already parsed and typed
                data = options['data']
            if 'datafield' in options and search_mode == 'streaming':
                # Parse the datafield as JSON
                data_field = options.get('datafield')
                if data_field and data_field in result and result[data_field] is not None:
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
            
            data_str: Optional[str] = None
            # Handle parsed object data before applying it as a payload
            if isinstance(data, (dict, list)):
                data_str = json.dumps(data)
                # Create the header object to apply/add to headers
                ct_header = {
                    'Content-Type': 'application/json',
                    'Content-Length': str(len(data))
                }
                # Set the Content-Type header to application/json (if not already set)
                if isinstance(headers, dict):
                    headers_content_type_set = False
                    for k in headers:
                        if k.lower() == 'content-type':
                            headers_content_type_set = True
                    if not headers_content_type_set:
                        headers.update(ct_header)
            else:
                data_str = str(data) if data is not None else None

            # Auth logic
            auth: Optional[tuple] = (user, passwd) if user and passwd else None

            curl_result = {}
            ran_request = False
            if not uri in [None, ""]:
                # Check the uri and quit if not HTTPS (Splunk Cloud only)
                enforceHTTPS(uri)
                # Invoke the HTTP request
                curl_result = http_request(
                    method,
                    uri,
                    data_str,
                    verifyssl,
                    headers=headers,
                    timeout=timeout,
                    cert=cert,
                    auth=auth
                )
                # Set a flag so the next loop will sleep as configured
                ran_request = True

            # Debugging info
            if 'debug' in options and is_true(options['debug']):
                # Add debug fields to the result only if they have values
                for k, v in [
                    ('curl_method', method),
                    ('curl_uri', uri),
                    ('curl_splunkauth', splunkauth),
                    ('curl_data_payload', data),
                    ('curl_header', headers),
                    #('user_headers', user_headers),
                    ('curl_sleep', sleep),
                    ('curl_cert', cert[0] if cert and type(cert) is tuple else None),
                    ('curl_certkey', cert[1] if cert and type(cert) is tuple and cert[1] is not None else None),
                    ('curl_verifyssl', "Forced to True for Splunk Cloud Compatibility" if cli.isCloudInstanceType()
                            else verifyssl)
                ]:
                    if v is not None:
                        result[k] = v

                # Log the result URL as curl_redirect if it differs from the original
                if curl_result.get('url') != uri and not uri in [None, ""]:
                    curl_redirect = curl_result.get('url')
                    if curl_redirect:
                        result['curl_redirect'] = curl_redirect
            
            # Log the final curl status and message (content)
            result['curl_status'] = curl_result.get('status')
            curl_message = curl_result.get('message')

            # Clean the curl message (if enabled)
            if curl_message is not None and len(curl_message) > 0:
                if clean_result:
                    try:
                        clean_html = curl_message
                        # Remove HTML comments using regex
                        clean_html = re.sub(r'<!--[\s\S]*?(?<!<!)-->', '', clean_html)

                        # Remove script and style tags
                        clean_html = re.sub(r'<(script|style|link|meta)[^>]*?(?:\/>|>[\s\S]*?<\/\1>)', '', clean_html)

                        # Remove leading and trailing whitespace
                        clean_html = re.sub(r'(?<=[<>\n])(?:[\t ]+)|(?:[\t ]+)(?=[<>\n])', '', clean_html)
                        # Remove multiple newlines
                        clean_html = re.sub(r'(?<=\n)[\r\n]*', '', clean_html)
                        # Remove extra whitespace
                        clean_html = re.sub(r'([\t ])\1+', '\1', clean_html)
                        
                        result['curl_message'] = clean_html
                    except Exception as e:
                        result['curl_message'] = curl_message
                        logger.exception(f"Error cleaning HTML content: {curl_message[:100]}... " + str(e))
                else:
                    result['curl_message'] = curl_message

        # Write results to the Splunk search output
        splunk.Intersplunk.outputResults(results)

    except Exception as e:
        stack =  traceback.format_exc()
        splunk.Intersplunk.generateErrorResults(str(e))
        logger.error(str(e) + ". Traceback: " + str(stack))

if __name__ == '__main__':
    execute()
