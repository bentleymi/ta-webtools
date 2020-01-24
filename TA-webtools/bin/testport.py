### Author: Michael Camp Bentley aka JKat54 
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
### SCRIPT NAME: testport.py
### Description: splunk search command for testing ports.
### Doesnt use the HTTP_PROXY or HTTPS_PROXY defined in splunk-launch.conf

import socket
import splunk.Intersplunk
import splunk.mining.dcutils as dcu
import traceback

logger = dcu.getLogger()

def buildResponse(status, address, port, count, timeout):
	response={}
	response["testport_status"] = status
	response["testport_port"] = port
	response["testport_address"] = address
	response["testport_timeout"] = timeout
	response["testport_count"] = count
	return(response)

def testPort(address, port, count, timeout):
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.settimeout(timeout)
	result = sock.connect_ex((address,port))
	if result == 0:
		return(buildResponse("OPEN", address, port, count, timeout))
	else:
		return(buildResponse("CLOSED", address, port, count, timeout))

def execute():
	try:
		# get the keywords suplied to the curl command
		keywords, options = splunk.Intersplunk.getKeywordsAndOptions()
		
		# get the previous search results
		results,dummyresults,settings = splunk.Intersplunk.getOrganizedResults()
		
		# some options are required, raise error and give syntax if they are not given
		if 'address' not in options or 'port' not in options:
			results = None
			stack =  traceback.format_exc()
			e = "syntax: testport address=<ip> port=<port> [ Optional: count=<number_of_tests> timeout=<timeout_in_seconds> ]" \
			+ "\texample: testport address=127.0.0.1 port=8000 count=5 timeout=2" 
			splunk.Intersplunk.generateErrorResults(str(e))
			logger.error(str(e) + ". Traceback: " + str(stack))

		else:
			address = str(options['address'])
			port = int(options['port'])
			if 'timeout' in options:
				timeout = float(options['timeout'])
			else:
				timeout = 2 
			if 'count' in options:
				count = int(options['count'])
			else:
				count = 1
            		result={}
			results=[]
			results.append(testPort(address,port,count,timeout))


		#output results
		splunk.Intersplunk.outputResults(results)

	except Exception, e:
		stack =  traceback.format_exc()
		splunk.Intersplunk.generateErrorResults(str(e))
		logger.error(str(e) + ". Traceback: " + str(stack))

if __name__ == '__main__':
	execute()
