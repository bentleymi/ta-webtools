This is an add-on powered by the Splunk Add-on Builder and the source code can be found here:
https://github.com/bentleymi/Splunk/tree/master/TA-webtools

You can find the Splunk Add-on Builder templates available for importing the project here:
https://github.com/bentleymi/Splunk/tree/master/AoB/ProjectExports/

When commiting code, please be sure the code doesnt break the Add-on Builder components.  You can do so by downloading the latest package from https://github.com/bentleymi/Splunk/tree/master/AoB/ProjectExports/, importing the package in your AoB, increment the version, add your changes, validate the package, and then export the package from the AoB.

If you've changed a command syntax, be sure to update splunkbase.* files found here https://github.com/bentleymi/Splunk/tree/master/TA-webtools/ so that we can update the documentation on splunkbase when we release your code.
