### Author: Michael Camp Bentley aka JKat54
### Contributors: Bert Shuler, Alex Cerier, Gareth Anderson
### Copyright 2020 Michael Camp Bentley
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
### SCRIPT NAME: openssl.py
### Description: splunk search command for running data through openssl binary.

import json
import splunk.Intersplunk
import splunk.mining.dcutils as dcu
import traceback
import sys
import os
import subprocess
import re

logger = dcu.getLogger()

def execute():
	
	try:
		logger = dcu.getLogger()
	except Exception as e:
		splunk.Intersplunk.generateErrorResults(str("Unable to initialize logging.")+str(e))

	try:
		argv = splunk.Intersplunk.win32_utf8_argv() or sys.argv
		first = True
		options = {}
		pattern=re.compile('^\s*([^=]+)=(.*)')
		for arg in argv:
			if first:
				first = False
				continue
			else:
				result = pattern.match(arg)
				if result:
					options[result.group(1)] = result.group(2)
	except Exception as e:
		splunk.Intersplunk.generateErrorResults(str("Did not receive list of options with openssl command."+ str(e)))

	try:
		# get the previous search results
		results,dummyresults,settings = splunk.Intersplunk.getOrganizedResults()

		if len(results) == 0:
			splunk.Intersplunk.generateErrorResults(str("Did not receive a list of results in the pipeline.")+str(e))
	
		if len(results) > 0:
			for result in results:
				#do work
				pathToOpenSSL = os.path.join(os.getcwd(),"..","..","..","..","bin","openssl")
				argv.pop(0)				
				args = [pathToOpenSSL] + argv
				if 'certfield' in options:
					for b in args:
						if re.match("certfield\=.*",b):
							args.remove(b)
					cert = result[options['certfield']]
					p1 = subprocess.Popen(["echo", cert], stdout=subprocess.PIPE)
					p2 = subprocess.Popen(args, stdin=p1.stdout, stdout=subprocess.PIPE)
				else:
					p2 = subprocess.Popen(args, stdout=subprocess.PIPE)
				p2.wait()
				output = p2.stdout.read()
				result['openssl'] = output
		#output results
		splunk.Intersplunk.outputResults(results)

	except Exception as e:
		stack =  traceback.format_exc()
		splunk.Intersplunk.generateErrorResults(str(e))
		logger.error(str(e) + ". Traceback: " + str(stack))
	

if __name__ == '__main__':
	execute()

