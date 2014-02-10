nagios-xenserver
================

Nagios check plugin for xenserver
---------------------------------

	Usage: ./check_xenserver.py <XenServer IP or FQDN> <username> <password> <warning level %> <critical level %> <check_{sr,mem,cpu,hosts}>
or, if using config file to store username or password
	Usage: ./check_xenserver.py <XenServer IP or FQDN> <config file> <warning level %> <critical level %> <check_{sr,mem,cpu,hosts}>

Config file follows ini format. A section is the XenServer IP or FQDN you are calling, values are username and password.
Example :
```
[127.0.0.1]
username: root
password: root	
[10.0.0.1]
username: nagios
password: nagios
```	
 - Uses https to connect to XenServer, if you have a pool, use a poolmaster IP/FQDN
 - Uses (python) XenAPI, download it from XenServer http://www.xenserver.org/partners/developing-products-for-xenserver.html and parse_rrd

Credit for most of the code goes to ppanula, check http://exchange.nagios.org/directory/Plugins/System-Metrics/Storage-Subsystem/check_sr-2Epy/details for original code

Dated: 10/02/2014
Version: 1.2

Version history:
----------------
 - v1.0: Initial release
 - v1.1: Config file support + return code for check_hosts
 - v1.2: Bug fixes : return status for SRs and Mem, perfdata format
		 Features : service output for SRs and Mem, 
 

Todo:
-----
 - Add single SR check
 - Add VMs status checK 
 - Add Multipath enable checking

nagios command definition: 
--------------------------
	 define command{
	        command_name    check_xenserver_sr
        	command_line    $USER1$/check_xenserver.py $ARG1$ "$USER15$" "$USER16$" "$ARG2$" $ARG3$ check_sr
 	 }

 	define command{
        	command_name    check_xenserver_mem
        	command_line    $USER1$/check_xenserver.py $ARG1$ "$USER15$" "$USER16$" "$ARG2$" $ARG3$ check_mem
 	}

USER16 and USER15 are username and password in resource.cfg
