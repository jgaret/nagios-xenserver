#!/usr/bin/env python
#
# Check XenServer
# (c) copyright Julien Garet
# Licence: GPLv2 or later
# Author: Julien Garet email: julien@garet.info
# Contact if bugs, etc.
#
# Usage: ./check_xenserver.py <XenServer IP or FQDN> <username> <password> <warning level %> <critical level %> <check_{sr,mem,cpu,hosts}>
#
# - Uses https to connect to XenServer, if you have a pool, use a poolmaster IP/FQDN
# - Uses (python) XenAPI, download it from XenServer http://www.xenserver.org/partners/developing-products-for-xenserver.html and parse_rrd
#
# Credit for most of the code goes to ppanula, check http://exchange.nagios.org/directory/Plugins/System-Metrics/Storage-Subsystem/check_sr-2Epy/details for original code
#
# Dated: 10/02/2013
# Version: 1.2
#
# Version history:
# - v1.0: Initial release
# - v1.1: Config file support + return code for check_hosts
# - v1.2: Bug fixes : return status for SRs and Mem, perfdata format
#		  Features : service output for SRs and Mem, 
# 
# nagios command definition: 
#
# define command{
#        command_name    check_xenserver_sr
#        command_line    $USER1$/check_xenserver.py $ARG1$ "$USER15$" "$USER16$" "$ARG2$" $ARG3$ check_sr
# }
#
# define command{
#        command_name    check_xenserver_mem
#        command_line    $USER1$/check_xenserver.py $ARG1$ "$USER15$" "$USER16$" "$ARG2$" $ARG3$ check_mem
# }
#
# USER16 and USER15 are username and password in resource.cfg


from __future__ import division
import sys, time, atexit
import XenAPI

# CHANGE PERFORMANCE DATA FORMAT 
performancedata_format = "pnp4nagios" # choose this if you use pnp4nagios or compatible
# performancedata_format = "centreon" # choose this if you use   centreon or compatible

def logout():
    try:
        session.xenapi.session.logout()
    except:
        pass

atexit.register(logout)

def humanize_bytes(bytes, precision=2, suffix=True, format="pnp4nagios"):

    if format == "pnp4nagios":
        abbrevs = (
            (1<<30L, 'Gb'),
            (1<<20L, 'Mb'),
            (1<<10L, 'kb'),
            (1,      'b')
        )
    else:
        abbrevs = (
            (1<<50L, 'P'),
            (1<<40L, 'T'),
            (1<<30L, 'G'),
            (1<<20L, 'M'),
            (1<<10L, 'k'),
            (1,      'b')
        )

    if bytes == 1:
        return '1 b'
    for factor, _suffix in abbrevs:
        if bytes >= factor:
            break

    if suffix:
        return '%.*f%s' % (precision, bytes / factor, _suffix)
    else:
        return '%.*f' % (precision, bytes / factor)

def performancedata(sr_name, suffix, total, alloc, warning, critical, performancedata_format="pnp4nagios"):

    if performancedata_format == "pnp4nagios":
		performance_line = "'"+sr_name + suffix + "'=" + str(alloc).replace(".",",") + ";" + str(warning).replace(".",",") + ";" + str(critical).replace(".",",") + ";0.00;" + str(total).replace(".",",") +""
    else:
		performance_line = "size=" + str(total) + "B " + "used=" + str(alloc) + "B"+ ";" + str(warning) + ";" + str(critical) + ";0;" + str(total) +""

    return(performance_line)

def compute(name, size, util, free, warning, critical, performancedata_format, format_suffix):

	gb_factor=1073741824
	mb_factor=1024*1024
	total_bytes_gb   = int(size)      / gb_factor
	total_bytes_mb   = int(size)      / mb_factor
	total_bytes_b    = int(size)
	total_alloc_gb   = int(util) / gb_factor
	total_alloc_mb   = int(util) / mb_factor
	total_alloc_b    = int(util)
	free_space_gb    = int(free) / gb_factor
	free_space_mb    = int(free) / mb_factor
	free_space_b	 = int(free)
	used_percent     = 100*float(total_alloc_b)/float(total_bytes_b)
	warning_gb       = (float(total_bytes_gb)     / 100) * float(warning)
	warning_mb       = (float(total_bytes_mb)     / 100) * float(warning)
	warning_b        = int((int(total_bytes_b)    / 100) * float(warning))
	critical_gb      = (float(total_bytes_gb)     / 100) * float(critical)
	critical_mb      = (float(total_bytes_mb)     / 100) * float(critical)
	critical_b       = int((float(total_bytes_b)  / 100) * float(critical))
	if performancedata_format == "pnp4nagios":
		performance = performancedata(name, format_suffix,
					humanize_bytes(total_bytes_b, precision=1, suffix=False, format=performancedata_format),
					humanize_bytes(total_alloc_b, precision=1,               format=performancedata_format),
					humanize_bytes(warning_b,     precision=1, suffix=False, format=performancedata_format),
					humanize_bytes(critical_b,    precision=1, suffix=False, format=performancedata_format),
					performancedata_format)
	else:
		performance = performancedata(name, format_suffix, 
					total_bytes_b,
					total_alloc_b,
					warning_b,
					critical_b,
					performancedata_format)

	info = {}
	info['service'] =  "%s %s%%, size %s, used %s, free %s" % (name,
									str(round(used_percent,2)), 
									str(humanize_bytes(total_bytes_b, precision=0)), 
									str(humanize_bytes(total_alloc_b, precision=0)), 
									str(humanize_bytes(free_space_b, precision=0))
									)
	info['performance'] = performance

	return (used_percent, info, total_bytes_b, total_alloc_b)
	
def sr(session, sr_name, warning, critical, performancedata_format):

	sr = session.xenapi.SR.get_by_name_label(sr_name)
	if sr:
		sr_size          = session.xenapi.SR.get_physical_size(sr[0])
		sr_phys_util     = session.xenapi.SR.get_physical_utilisation(sr[0])
		sr_virtual_alloc = session.xenapi.SR.get_virtual_allocation(sr[0])
		
		used_percent, outputdata , total, alloc = compute(sr_name, sr_size, sr_phys_util, str(int(sr_size) - int(sr_phys_util)), warning, critical, performancedata_format, "_used_space")

		if float(used_percent) >= float(critical):
			status = "CRITICAL: SR "+ sr_name
			exitcode = 2
		elif float(used_percent) >= float(warning):
			status = "WARNING: SR "+ sr_name
			exitcode = 1
		else:
			status = "OK: SR "+ sr_name
			exitcode = 0

		return(exitcode, status, outputdata['service'], outputdata['performance'], total, alloc)		

	else:
		print "CRITICAL: Cant get SR, check SR name! SR =", sr_name
		sys.exit(2)

def check_sr(session, warning, critical):

	finalexit = 0
	output = {}
	total_disk = 0
	total_alloc = 0
	critical_srs = []
	warning_srs = []

	srs = session.xenapi.SR.get_all()
	for cur_sr in srs:
		sr_name = session.xenapi.SR.get_name_label(cur_sr)
		if session.xenapi.SR.get_shared(cur_sr) and session.xenapi.SR.get_type(cur_sr) != 'iso':
			exitcode, status, servicedata, perfdata, total, alloc = sr(session, sr_name, warning, critical, performancedata_format)
			if exitcode > finalexit:
				finalexit = exitcode
				
			if exitcode == 2:
				critical_srs.append(sr_name)
			if exitcode == 1:
				warning_srs.append(sr_name)

			output[sr_name] = {}
			output[sr_name]['service'] = servicedata
			output[sr_name]['perf'] = perfdata
			
			total_disk += total
			total_alloc += alloc

	
	if performancedata_format == "pnp4nagios":
		performance = performancedata("Total", "_used_space",
					humanize_bytes(total_disk, precision=1, suffix=False, format=performancedata_format),
					humanize_bytes(total_alloc, precision=1, suffix=False, format=performancedata_format),
					humanize_bytes((total_disk/100)*float(warning), precision=1, suffix=False, format=performancedata_format),
					humanize_bytes((total_disk/100)*float(critical), precision=1, suffix=False, format=performancedata_format),
					performancedata_format)
	else:
		performance = performancedata("Total", format_suffix, 
					total_disk,
					total_alloc,
					(total_disk/100)*float(warning),
					(total_disk/100)*float(critical),
					performancedata_format)

			
	if finalexit == 2:
		prefix = "CRITICAL: SR Space"
		prefix += " / Critical SRs = ["+", ".join(critical_srs)+"]"
		prefix += " / Warning SRs = ["+", ".join(warning_srs)+"]"
	elif finalexit == 1:
		prefix = "WARNING: SR Space"
		prefix += " / Warning SRs = ["+", ".join(warning_srs)+"]"
	else:
		prefix = "OK: SR Space"
		

	print prefix + ' | ' + performance + "\n" + ";\n".join([output[disk_srs]['service'] for disk_srs in output]) +	"; | " + " ".join([output[disk_srs]['perf'] for disk_srs in output])

	sys.exit(finalexit)
		
def mem(session, host, warning, critical, performancedata_format):

	if host:
		hostname          = session.xenapi.host.get_name_label(host)
		mem_size          = session.xenapi.host_metrics.get_record(session.xenapi.host.get_record(host)['metrics'])['memory_total']
		mem_free          = session.xenapi.host_metrics.get_record(session.xenapi.host.get_record(host)['metrics'])['memory_free']
		
		used_percent, outputdata , total, alloc = compute(hostname, mem_size, str(int(mem_size) - int(mem_free)), mem_free, warning, critical, performancedata_format, "_used_space")

		if float(used_percent) >= float(critical):
			status = "CRITICAL: MEM "+ hostname
			exitcode = 2
		elif float(used_percent) >= float(warning):
			status = "WARNING: MEM "+ hostname
			exitcode = 1
		else:
			status = "OK: MEM "+ hostname
			exitcode = 0

		return(exitcode, status, outputdata['service'], outputdata['performance'], total, alloc)		

	else:
		print "CRITICAL: Cant get host, check configuration"
		sys.exit(3)
 
 
def check_mem(session, warning, critical):

	finalexit = 0
	output = {}
	total_mem = 0
	total_used = 0
	critical_hosts = []
	warning_hosts = []

	hosts = session.xenapi.host.get_all()
	for host in hosts:
		hostname = session.xenapi.host.get_name_label(host)
		exitcode, status, servicedata, perfdata, total, used = mem(session, host, warning, critical, performancedata_format)
		if exitcode > finalexit:
			finalexit = exitcode

		if exitcode == 2 :
			critical_hosts.append(hostname)
		
		if exitcode == 1 :
			warning_hosts.append(hostname)
			
		output[hostname] = {}
		output[hostname]['service'] = servicedata
		output[hostname]['perf'] = perfdata
		
		total_mem += total
		total_used += used

	
	if performancedata_format == "pnp4nagios":
		performance = performancedata("Total", "_mem_used",
					humanize_bytes(total_mem, precision=1, suffix=False, format=performancedata_format),
					humanize_bytes(total_used, precision=1, suffix=False, format=performancedata_format),
					humanize_bytes((total_mem/100)*float(warning), precision=1, suffix=False, format=performancedata_format),
					humanize_bytes((total_mem/100)*float(critical), precision=1, suffix=False, format=performancedata_format),
					performancedata_format)
	else:
		performance = performancedata("Total", "_mem_used", 
					total_mem,
					total_used,
					(total_mem/100)*float(warning),
					(total_mem/100)*float(critical),
					performancedata_format)

			
	if finalexit == 2:
		prefix = "CRITICAL: Memory Usage "
		prefix += " / Critical Hosts = ["+", ".join(critical_hosts)+"]"
		prefix += " / Warning Hosts = ["+", ".join(warning_hosts)+"]"
	elif finalexit == 1:
		prefix = "WARNING: Memory Usage"
		prefix += " / Warning Hosts = ["+", ".join(warning_hosts)+"]"
	else:
		prefix = "OK: Memory Usage"

	print prefix + ' | ' + performance + "\n" + ";\n".join([output[hostname]['service'] for hostname in output]) +	"; | " + " ".join([output[hostname]['perf'] for hostname in output])
	
	sys.exit(finalexit)

def check_hosts(session, warning, critical):
	#work out which hosts in the pool are alive, and which dead
	hosts=session.xenapi.host.get_all()
	hosts_with_status=[(session.xenapi.host.get_name_label(x),session.xenapi.host_metrics.get_live( session.xenapi.host.get_metrics(x) )) for x in hosts]

	live_hosts=[name for (name,status) in hosts_with_status if (status==True)]
	dead_hosts=[name for (name,status) in hosts_with_status if not (status==True)]
	status=""
	if len(live_hosts) == 0:
		status = "Critical"
		exit = 2
	elif len(dead_hosts) > 1:
		status = "Warning"
		exit = 1
	else:
		status = "OK"
		exit = 0
	print status, ": live hosts", live_hosts, "dead hosts", dead_hosts,	

	sys.exit(exit)

def check_cpu(session, warning, critical):

	import parse_rrd
	params = {}
	hosts = session.xenapi.host.get_all_records()
	
	params['cf'] = "AVERAGE"
	params['start'] = int(time.time()) - 300
	params['interval'] = 5
	params['host'] = "true"
	
	perfdata = {}
	for host in hosts:
		v= []
		url = 'https://'+session.xenapi.host.get_address(host)
		rrd_updates = parse_rrd.RRDUpdates()
		rrd_updates.refresh(session.handle, params, url)
		paramList = ['cpu'+session.xenapi.host_cpu.get_record(i)['number'] for i in session.xenapi.host_cpu.get_all_records() if host in session.xenapi.host_cpu.get_record(i)['host'] ]
		for param in rrd_updates.get_host_param_list():
			if param in paramList:
				max_time=0
				data = ""
				for row in range(rrd_updates.get_nrows()):
					epoch = rrd_updates.get_row_time(row)
					dv = str(rrd_updates.get_host_data(param,row))
					if epoch > max_time:
						max_time = epoch
						data = dv
				v.append(float(data))
		perfdata[session.xenapi.host.get_name_label(host)] = reduce(lambda x, y: x+y, v)/len(v)
	
	exitcode = 0
	globalperf = 0
	for perf in perfdata:
		globalperf += perfdata[perf]
		if perfdata[perf] > float(critical)/100:
			exitcode = 2
			prefix = "CRITICAL: CPU "
		elif perfdata[perf] > float(warning)/100:
			exitcode = 1
			prefix = "WARNING: CPU "
		else:
			exitcode = 0
			prefix = "OK: CPU "
			
	globalperf = globalperf / len(perfdata)
	print prefix + "| 'used_cpu'="+str(round(globalperf, 2))+"%;" + str(float(warning)/100)+";" + str(float(critical)/100)+";0;100;\n"+\
	";\n".join([host+" Used CPU = "+str(round(perfdata[host],2)) for host in perfdata]) + "; |" +\
	" ".join(["'"+host+"_used_cpu'="+str(round(perfdata[host],2))+"%"+str(float(warning)/100)+";" + str(float(critical)/100)+";0;100" for host in perfdata])
	
	sys.exit(exitcode)
		
		
if __name__ == "__main__":
	if len(sys.argv) < 6 or len(sys.argv) > 7:
		print "Usage:"
		print sys.argv[0], " <XenServer poolmaster ip or fqdn> <username> <password> <warning %> <critical %> check_{sr,mem,hosts,cpu}"
		print sys.argv[0], " or "
		print sys.argv[0], " <XenServer poolmaster ip or fqdn> <config> <warning %> <critical %> check_{sr,mem,hosts,cpu}"
		sys.exit(3)

	url = sys.argv[1]
		
	# If 7 args : username + password given
	if len (sys.argv) == 7:
		username = sys.argv[2]
		password = sys.argv[3]
		warning  = sys.argv[4]
		critical = sys.argv[5]
		call = sys.argv[6]
		
	# If 6 args : config file given
	if len (sys.argv) == 6:
		import ConfigParser, os
		config = ConfigParser.ConfigParser()
		config.readfp(open(sys.argv[2]))
		
		username = config.get(url,"username")
		password = config.get(url,"password")
		warning  = sys.argv[3]
		critical = sys.argv[4]
		call = sys.argv[5]
	

	options  = {
		'check_sr': check_sr,
		'check_mem': check_mem,
		'check_hosts': check_hosts,
		'check_cpu': check_cpu
	}
	
	# First acquire a valid session by logging in:
	try:
		session = XenAPI.Session("https://"+url)
		session.xenapi.login_with_password(username, password)
	except XenAPI.Failure, e:
		if e.details[0] == "HOST_IS_SLAVE":
			session=XenAPI.Session('https://'+e.details[1])
			session.xenapi.login_with_password(username, password)
		else:
			raise			
			
	options[call](session, warning, critical)
			
	
