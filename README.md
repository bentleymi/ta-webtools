# TA-webtools
Contains source code for TA-webtools Splunk Add-on

## Splunk Commands

### curl
The `curl` command allows you to make HTTP requests from within Splunk searches.

#### Required Parameters (One of the following must be specified)
- `uri`: The HTTPS URL to send the request to
- `urifield`: Field name containing the HTTPS URL to send the request to

#### Optional Parameters
- `method`: HTTP method to use (default: get)
  - Supported values: get/g, head/h, patch, post/p, put, delete/del/d
- `datafield`: Field name containing the data payload to send
- `data`: Static data payload to send
- `debug`: Enable debug output (true/false)
- `splunkauth`: Use Splunk authentication (true/false)
- `splunkpasswdname`: Username from passwords.conf to use for authentication
- `splunkpasswdcontext`: App context for passwords.conf lookup (default: -)
- `timeout`: Request timeout in seconds (default: 60)
- `token`: Bearer token for authentication
- `headers`: JSON string containing request headers
- `headerfield`: Field containing JSON formatted request headers
- `clientcert`: Path to client certificate file
- `certkey`: Path to certificate key file
- `sleep`: Time to sleep between requests in seconds (when processing multiple events)
- `proxy`: Proxy URL to use for requests
- `proxy_auth`: Proxy authentication in format username:password

#### Security Notes
- All URIs must use HTTPS protocol
- SSL verification is enforced for Splunk Cloud compatibility

#### Output Fields
The command adds the following fields to your events:
- `curl_status`: HTTP status code of the response
- `curl_message`: Response body or error message

When debug=true, additional fields are added showing the command configuration:
- `curl_method`: HTTP method used
- `curl_verifyssl`: SSL verification status
- `curl_uri`: Request URL
- `curl_splunkauth`: Whether Splunk authentication was used
- `curl_data_payload`: Data payload sent (if any)
- `curl_header`: Headers used (if any)
- `curl_cert`: Client certificate path (if used)
- `curl_certkey`: Certificate key path (if used)
- `curl_sleep`: Sleep duration between requests (if configured)

#### Example Usage
```spl
| makeresults 
| eval url="https://api.example.com/data"
| curl uri=url method=get
```

### urlencode
The `urlencode` command allows you to URL encode field values within your Splunk searches. This is useful when preparing values for use in URLs or API calls.

#### Usage
The command takes field names as arguments and updates the contents to be URL encoded values.

#### Example Usage
```spl
| makeresults 
| eval my_field="hello world 123"
| urlencode my_field
```

This will update the value of my_field to `hello%20world%20123` 
