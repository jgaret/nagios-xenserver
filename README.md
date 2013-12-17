nagios-xenserver
================

Nagios check plugin for xenserver
---------------------------------

	Usage: ./check_xenserver.py <XenServer IP or FQDN> <username> <password> <warning level %> <critical level %> <check_{sr,mem,cpu,hosts}>

 - Uses https to connect to XenServer, if you have a pool, use a poolmaster IP/FQDN
 - Uses (python) XenAPI, download it from XenServer http://www.xenserver.org/partners/developing-products-for-xenserver.html and parse_rrd

Credit for most of the code goes to ppanula, check http://exchange.nagios.org/directory/Plugins/System-Metrics/Storage-Subsystem/check_sr-2Epy/details for original code

Dated: 12/16/2013
Version: 1.0

Version history:
----------------
 - v1.0: Initial release
 

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
