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
        performance_line = "'"+sr_name + suffix + "'=" + \
            str(humanize_bytes(alloc,    precision=1, suffix=True, format=performancedata_format)).replace(".",",") + ";" + \
            str(humanize_bytes(warning,  precision=1, suffix=True, format=performancedata_format)).replace(".",",") + ";" + \
            str(humanize_bytes(critical, precision=1, suffix=True, format=performancedata_format)).replace(".",",") + ";0.00;" + \
            str(humanize_bytes(total,    precision=1, suffix=True, format=performancedata_format)).replace(".",",") +""
    else:
        performance_line = "'"+sr_name + suffix + "'=" + \
            str(alloc).replace(".",",") + "B;" + \
            str(warning).replace(".",",")+ ";" + \
            str(critical).replace(".",",") + ";0;" + \
            str(total).replace(".",",") +""

    return(performance_line)

def compute(name, size, util, free, warning, critical, performancedata_format, format_suffix):

    total_bytes_b    = int(size)
    total_alloc_b    = int(util)
    free_space_b	 = int(free)
    used_percent     = 100*float(total_alloc_b)/float(total_bytes_b)
    warning_b        = int((int(total_bytes_b)    / 100) * float(warning))
    critical_b       = int((float(total_bytes_b)  / 100) * float(critical))

    info = {}
    info['performance'] = performancedata(name, format_suffix, 
        total_bytes_b,
        total_alloc_b,
        warning_b,
        critical_b,
        performancedata_format)

    info['service'] =  "%s %s%%, size %s, used %s, free %s" % (name,
                                    str(round(used_percent,2)), 
                                    str(humanize_bytes(total_bytes_b, precision=0)), 
                                    str(humanize_bytes(total_alloc_b, precision=0)), 
                                    str(humanize_bytes(free_space_b, precision=0))
                                    )

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

def check_sr(session, args):

    warning = args["warning"]
    critical = args["critical"]
    exclude_srs = args["exclude_srs"]
    performancedata_format = args["perfdata"]
    
    finalexit = 0
    output = {}
    total_disk = 0
    total_alloc = 0
    critical_srs = []
    warning_srs = []

    if not args['sr_name']:
        sr_list = session.xenapi.SR.get_all()
    else:
        sr_list  = session.xenapi.SR.get_by_name_label(args['sr_name'])
        
    for cur_sr in sr_list:
        sr_name = session.xenapi.SR.get_name_label(cur_sr)
        if sr_name not in exclude_srs:
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

    performance = performancedata("Total", "_used_space", 
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
        
        used_percent, outputdata , total, alloc = compute(hostname, mem_size, str(int(mem_size) - int(mem_free)), mem_free, warning, critical, performancedata_format, "_used_mem")

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
        print "CRITICAL: Cant get mem, check configuration"
        sys.exit(3)
 
 
def check_mem(session, args):
    
    warning =args["warning"]
    critical = args["critical"]
    performancedata_format = args["perfdata"]
    
    # Initialiaze local variables
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
    
    performance = performancedata("Total", "_mem_used", 
                total_mem,
                total_used,
                (total_mem/100)*float(warning),
                (total_mem/100)*float(critical),
                performancedata_format)

            
    if finalexit == 2:
        prefix = "CRITICAL: Memory Usage "
        prefix += " / Critical on Hosts = ["+", ".join(critical_hosts)+"]"
        prefix += " / Warning on Hosts = ["+", ".join(warning_hosts)+"]"
    elif finalexit == 1:
        prefix = "WARNING: Memory Usage"
        prefix += " / Warning on Hosts = ["+", ".join(warning_hosts)+"]"
    else:
        prefix = "OK: Memory Usage"

    print prefix + " | " + performance + "\n" + ";\n".join([output[hostname]['service'] for hostname in output]) +	"; | " + " ".join([output[hostname]['perf'] for hostname in output])
    
    sys.exit(finalexit)

def check_hosts(session, args):
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

def check_cpu(session, args):

    warning = args["warning"]
    critical = args["critical"]

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
                if data == "":
                    data = 0
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
    print prefix + "| 'used_cpu'="+str(round(globalperf, 2))+"%;" + str(warning)+"%;" + str(critical)+"%;0%;100%;\n"+\
    ";\n".join([host+" Used CPU = "+str(round(perfdata[host],2)) for host in perfdata]) + "%; |" +\
    " ".join(["'"+host+"_used_cpu'="+str(round(perfdata[host],2))+"%;"+str(warning)+"%;" + str(critical)+"%;0%;100%" for host in perfdata])
    
    sys.exit(exitcode)
        
        
if __name__ == "__main__":

    ### Arguments definition ###
    import argparse
    
    parser = argparse.ArgumentParser()	
    # Top level parser
    parser.add_argument("pool",help="Pool Name as defined in config file or master IP address")
    parser.add_argument("config",help="Path to the config file")

    subparsers = parser.add_subparsers(help="checks help", dest="check")
    
    # Common top level parser for warning and critical level
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument("warning",help="Warning level as percentage", type=int)
    common_parser.add_argument("critical",help="Critical level as percentage", type=int)
    
    #Check sr parser
    parser_sr = subparsers.add_parser("check_sr", help="Check for an SR or all SRs", parents=[common_parser])
    parser_sr.add_argument("--name", help="Optionnaly check a specific SR")
    
    #Check mem parser
    parser_mem = subparsers.add_parser("check_mem", help="Check for mem usage on all hosts", parents=[common_parser])
    
    #Check hosts parser
    parser_hosts = subparsers.add_parser("check_hosts", help="Check if hosts are alive or not")
    
    #Check cpu parser
    parser_cpu = subparsers.add_parser("check_cpu",help="Check cpu usage", parents=[common_parser])
    args = parser.parse_args()

    ### Configuration parsing ###
    import ConfigParser, os
    config = ConfigParser.ConfigParser()
    config.readfp(open(args.config))
    
    host = config.get(args.pool,'host')
    
    username = config.get(args.pool,"username")
    password = config.get(args.pool,"password")

    # We store the arguments in a dict to send them to the checks
    check_args = {}
    
    check_args["perfdata"] = config.get("general","perfdata_format")
    
    if hasattr(args,"warning"):
        check_args["warning"]  = args.warning
    if hasattr(args,"critical"):
        check_args["critical"] = args.critical
    
    if args.check == "check_sr" and hasattr(args, "name"):
        check_args['sr_name'] = args.name
    
    # Test if exclude_srs is defined and add the list to the check_args dict
    if config.has_option(args.pool,"exclude_srs"):
        exclude_srs = config.get(args.pool,"exclude_srs").split(',')
        [x.strip() for x in exclude_srs]
        check_args["exclude_srs"] = exclude_srs
    
    # First acquire a valid session by logging in:
    try:
        session = XenAPI.Session("https://"+host)
        session.xenapi.login_with_password(username, password)
    except XenAPI.Failure, e:
        if e.details[0] == "HOST_IS_SLAVE":
            session=XenAPI.Session('https://'+e.details[1])
            session.xenapi.login_with_password(username, password)
        else:
            print "CRITICAL - XenAPI Error : " + e.details[0]
            sys.exit(2)
            
    except:
        print "CRITICAL - Connection Error"
        sys.exit(2)

    options = {
        "check_sr": check_sr,
        "check_mem": check_mem,
        "check_hosts": check_hosts,
        "check_cpu": check_cpu
    }

    options[args.check](session,check_args)

    sys.exit(0)
