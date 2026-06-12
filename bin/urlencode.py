### Author: Michael Camp Bentley aka JKat54
### Copyright 2017 Michael Camp Bentley
###
### Licensed under the Apache License, Version 2.0 (the "License");
### you may not use this file except in compliance with the License.
### You may obtain a copy of the License at
###
###             http://www.apache.org/licenses/LICENSE-2.0
###
### Unless required by applicable law or agreed to in writing, software
### distributed under the License is distributed on an "AS IS" BASIS,
### WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
### See the License for the specific language governing permissions and
### limitations under the License.
### SCRIPT NAME: urlencode.py

import six.moves.urllib.request, six.moves.urllib.parse, six.moves.urllib.error, six.moves.urllib.parse
import splunk.Intersplunk
import splunk.mining.dcutils as dcu
import traceback

# Setup logging/logger
logger = dcu.getLogger()

def encode(s):
        try:
                return six.moves.urllib.parse.quote_plus(s)

        except Exception as e:
                stack = traceback.format_exc()
                splunk.Intersplunk.generateErrorResults(str(e))
                logger.error(str(e) + ". Traceback: " + str(stack))

def execute():
        try:
                # get the keywords and options passed to this command
                keywords, options = splunk.Intersplunk.getKeywordsAndOptions()

                # get the previous search results
                results,dummyresults,settings = splunk.Intersplunk.getOrganizedResults()

                # if no keywords, send error results through
                if len(keywords) == 0:
                        results = []
                        results.append({"error":"syntax: urlencode <field_1> <field_2> <field_n> ..."})
                        results.append({"error":"example: urlencode punct"})

                # else encode the fields provided
                if len(keywords) >= 1:
                        for keyword in keywords:
                                for result in results:
                                        result[keyword] = encode(result[keyword])

                # return the results
                results.sort()
                splunk.Intersplunk.outputResults(results)

        except Exception as e:
                stack = traceback.format_exc()
                splunk.Intersplunk.generateErrorResults(str(e))
                logger.error(str(e) + ". Traceback: " + str(stack))

if __name__ == '__main__':
        execute()
