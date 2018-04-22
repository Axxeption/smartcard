First open Eclipse and start the JCWDE simulator.

Secondly, there are 3 jars that need to be started in 3 different (Windows) command lines in the following order:
	- cd to the workspace\TimestampService folder here run the following command: 
		java -jar -Djavax.net.ssl.keyStore=sslKeyStore -Djavax.net.ssl.keyStorePassword=jonasaxel 1_TimestampService.jar
	-cd to the workspace\Middleware folder, here run the following command:
		java -jar -Djavax.net.ssl.trustStore=sslKeyStore -Djavax.net.ssl.trustStorePassword=jonasaxel 2_MiddleWare.jar 
		(there will be a UI popping up, but the next jar must be started to fully load this one) 
	- in the workspace folder, here run the following command: 
		java -jar 3_ServiceProviders.jar 