nagios-xenserver
================

Nagios check plugin for xenserver
---------------------------------

	Usage: ./check_xenserver.py <pool_name> <config_file> <check_{sr,mem,cpu,hosts}> [warning level %] [critical level %]
see online help for more informations

Config file follows ini format. In the [general] section, define the performance data format : can be "pnp4nagios" or other.
The name of the other sections are references, mandatory fields are :
 - host: ip or name of the pool master
 - username
 - password
 - exclude_SRs: <list of SRs you want to exclude>

Example :
```
[general]
perfdata_format: pnp4nagios

[Production1]
host: xenserver-prod01.servers.domain.com
username: nagios
password: nagios
exclude_srs: SR1, SR2

[Dev]
host: 192.168.0.1
username: nagios
password: nagios
```	
 - Uses https to connect to XenServer, if you have a pool, use a poolmaster IP/FQDN
 - Uses (python) XenAPI, download it from XenServer http://www.xenserver.org/partners/developing-products-for-xenserver.html and parse_rrd

Credit for most of the code goes to ppanula, check http://exchange.nagios.org/directory/Plugins/System-Metrics/Storage-Subsystem/check_sr-2Epy/details for original code

Dated: 03/05/2014
Version: 1.3

Version history:
----------------
 - v1.0: Initial release
 - v1.1: Config file support + return code for check_hosts
 - v1.2: Bug fixes : return status for SRs and Mem, perfdata format
		 Features : service output for SRs and Mem,
 - v1.3: Rewrite of the argument parsing
         Code refactoring
         Ability to check a single SR
 
Todo:
-----
 - Add VMs status check 
 - Add Multipath enable checking
