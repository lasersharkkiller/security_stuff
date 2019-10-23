#!/usr/bin/python -u
# 2013/7/11 add option -c and -o, to search for hostname only and filter by the mac address
# 2014/10/13 add option -i, to search for host ip address
# 2014/12/18 disable including the interface data
# 2014/12/31 Ignore the VPN log without session end timestamp, '10.79.100.104    10.224.241.26    -      06-19-2014 05:34:22 UTC  [NO DISCONNECT LOG]
# 2015/05/26 - add options -v (get detailed flow info like TCP flags, hostgroup and interface), -r (search for ip range) and -g (search for hostgroup id)
#            - use the available host-name field in flow data to replace the dns query on ip address
# 2017/03/16 Marcin made the following change (v1.1 - v1.3) to support NAT data due to the NGDMZ upgrade
# v1.1 2017/02/24 - changed output format to pipe-separated.. 
# v1.2 2017/02/27 - added -p option to filter based on NAT port number (filters display only)
# v1.3 2017/03/15 - added -q option tp filter output based on destinaion port number (filters output only)
# 2017/05/31 - added option {-w|--port} to support port filtering
import os, re, time, sys, getopt, smtplib, getpass, subprocess, urllib2, base64
import xml.dom.minidom, xml.dom
from email.MIMEMultipart import MIMEMultipart
from email.Utils import formatdate
from email.MIMEText import MIMEText

def sendMail(to, subject, text):
    server='localhost'
    fro = 'noreply@cisco.com'
    msg = MIMEMultipart()
    msg['From'] = fro
    msg['To'] = to
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject
    msg.attach(MIMEText(text))

    smtp = smtplib.SMTP(server)
    smtp.sendmail(fro, to, msg.as_string())
    smtp.close()

# get local seconds from epoch, dtime is from dhcp log in format of, MM/DD/YYYY HH:MM:SS
def getsec(dtime, ltz):
   os.environ['TZ']=ltz
   time.tzset()

   if re.search(r'\d{1,2}/\d{1,2}/\d{4}', dtime):
      return int(time.mktime(time.strptime(dtime, "%m/%d/%Y %H:%M:%S")))
   if re.search(r'\d{4}-\d{1,2}-\d{1,2}', dtime):
      return int(time.mktime(time.strptime(dtime, "%Y-%m-%d %H:%M:%S")))
   if re.search(r'\d{1,2}-\d{1,2}-\d{4}', dtime):
      return int(time.mktime(time.strptime(dtime, "%m-%d-%Y %H:%M:%S")))

# convert to lancope time format, YYYY-MM-DDThh:mm:ssZ
def getLancopeTime(dtime, ltz):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime(getsec(dtime, ltz)))

# get epoch second from Lancope time
def getLancopeSec(ltime):
   return int(time.mktime(time.strptime(ltime, "%Y-%m-%dT%H:%M:%SZ")))

# find out the hostname from user id
def gethostname(userid):
   cmd='/usr/local/bin/dce-cli'
   proc=subprocess.Popen([cmd, userid+'-*'], stdout=subprocess.PIPE)
   return proc.communicate()

def genxmlGetFlow(mr, did, iid, orderby):
   doc = xml.dom.minidom.Document()
   envelope = doc.createElementNS("http://schemas.xmlsoap.org/soap/envelope/", "soapenc:Envelope")
   envelope.setAttribute("xmlns:soapenc", "http://schemas.xmlsoap.org/soap/envelope/")
   doc.appendChild(envelope)
   body = doc.createElement("soapenc:Body")
   envelope.appendChild(body)
   getflow = doc.createElement("getFlows")
   body.appendChild(getflow)
   flowfilter = doc.createElement("flow-filter")
   if mr != "None": flowfilter.setAttribute("max-rows", mr)
   flowfilter.setAttribute("domain-id", did)
   flowfilter.setAttribute("include-interface-data", iid)
   if orderby != "None": 
      flowfilter.setAttribute("order-by", orderby)
      flowfilter.setAttribute("order-by-desc", "false")
   getflow.appendChild(flowfilter)
   return doc, flowfilter

# only support time-range-selection, time-window-selection and day-selectioni, day-range-selection
def setDate(doc, ff, ty, td):
   dateselection=doc.createElement("date-selection")
   ff.appendChild(dateselection)
   ts = doc.createElement(ty)
   tdlist = td.split(',')
   if ty == "time-range-selection":
      if tdlist[1].strip() != "None": ts.setAttribute("end", tdlist[1].strip())
      if tdlist[0].strip() != "None": ts.setAttribute("start", tdlist[0].strip())
   elif ty == "time-window-selection":
      ts.setAttribute("duration", tdlist[0].strip())
   elif ty == "day-selection":
      if tdlist[0].strip() != "None": ts.setAttribute("start", tdlist[0].strip())
   elif ty == "day-range-selection":
      if tdlist[0].strip() != "None": ts.setAttribute("start", tdlist[0].strip())
      ts.setAttribute("day-count", tdlist[1].strip())
   else:
      print "Date selection error!"
      sys.exit()
   dateselection.appendChild(ts)


# hp: host-pair-selection supports BETWEEN_SELECTION_1_SELECTION_2 and SELECTION_1_A_SELECTION_2_Z or SELECTION_1_Z_SELECTION_2_A
# ty: supports host-group-selection, ip-address-range-selection, ip-address-list-selection (multiple ip addresses are seperated by comma), ip-address-selection
# key of hdic is in format of, "s1-selction_name", "x1-selection_name", "s2-selection_name"
def setHost(doc, ff, hp, hdic):
   hostselection = doc.createElement("host-selection")
   ff.appendChild(hostselection)
   hpselection = doc.createElement("host-pair-selection")
   hpselection.setAttribute("direction", hp)
   hostselection.appendChild(hpselection)

   for hk in hdic.keys():
      rs = re.search(r'([s,x])(\d)-(.+)', hk)
      if rs != None:
         sty = rs.group(1) # "s" or "x"
         sno = rs.group(2) # "1" or "2"
         sna = rs.group(3).strip() # selection name
         val = hdic[hk]

         vk="value"
         if sna == "host-group-selection": vk = "host-group-id"

         if sty == "s": # selection 1 or 2
            selection = doc.createElement("selection-"+sno)
            hpselection.appendChild(selection)
            ipselection = doc.createElement(sna)
            if sna == "ip-address-list-selection":
               vlist = val.split(',')
               for ip in vlist:
                  ipaddress = doc.createElement("ip-address")
                  ipaddress.setAttribute(vk, ip.strip())
                  ipselection.appendChild(ipaddress)
            else:
               ipselection.setAttribute(vk, val.strip())
               if sna == "host-group-selection": ipselection.setAttribute("include-sub-zones", "true")
         else: # selection-exclude 1 or 2
            selection = doc.createElement("selection-" + sno + "-exclude")
            hpselection.appendChild(selection)
            ipselection = doc.createElement(sna)
            if sna == "ip-address-list-selection":
               vlist = val.split(',')
               for ip in vlist:
                  ipaddress = doc.createElement("ip-address")
                  ipaddress.setAttribute(vk, ip.strip())
                  ipselection.appendChild(ipaddress)
            else:
               ipselection.setAttribute(vk, val.strip())
               if sna == "host-group-selection": ipselection.setAttribute("include-sub-zones", "true")
         selection.appendChild(ipselection)

# tdic is the mapping of traffic type to value, like
#    "client-bytes-range":"100, 10000"
#    "server-packets-range":"None, 10000"
#    "total-bytes-range":"100, None"
def setTraffic(doc, ff, tdic):
   traffic = doc.createElement("traffic")
   ff.appendChild(traffic)
   client = doc.createElement("client")
   server = doc.createElement("server")
   total = doc.createElement("total")
   hasClient, hasServer, hasTotal = 0, 0, 0

   for tk in tdic.keys():
      tvlist = tdic[tk].split(',')
      rs = re.search(r'(.+?)-(.+)', tk)
      if rs != None:
         hty = rs.group(1) # client, server or total
         tty = rs.group(2) # bytes-range, packets-range
         tt = doc.createElement(tty)
         if tvlist[0].strip() != "None": tt.setAttribute("low-value", tvlist[0].strip())
         if tvlist[1].strip() != "None": tt.setAttribute("high-value", tvlist[1].strip())
         if hty == "client":
            hasClient = 1
            client.appendChild(tt)
         elif hty == "server":
            hasServer = 1
            server.appendChild(tt)
         elif hty == "total":
            hasTotal = 1
            total.appendChild(tt)

   if hasClient != 0: traffic.appendChild(client)
   if hasServer != 0: traffic.appendChild(server)
   if hasTotal != 0: traffic.appendChild(total)


# server-ports and client-ports is a map of include/exclude ports list sepearted by comma
# "include":"53/udp, 80/tcp"
# "exclude":"443, 22"
# Note: only one key is allowed, either "include" or "exclude", this function only takes the first entry in server-ports or client-ports
def setPort(doc, ff, serverPorts, clientPorts):
   if len(serverPorts) != 0:
      skey = serverPorts.keys()[0]
      sp_text = doc.createTextNode(serverPorts[skey])
      sports = doc.createElement("ports")
      if skey == "exclude":
         sports.setAttribute("exclude", "true")
      sports.appendChild(sp_text)
      ff.appendChild(sports)
   elif len(clientPorts) != 0:
      ckey = clientPorts.keys()[0]
      cp_text = doc.createTextNode(clientPorts[ckey])
      cports = doc.createElement("client-ports")
      if ckey == "exclude":
         cports.setAttribute("exclude", "true")      
      cports.appendChild(cp_text)
      ff.appendChild(cports)

def getFlowInfo(doc):
   flow_output=[]
   for node in doc.getElementsByTagName("flow"):
      flowid=node.getAttribute("id")
      stime=node.getAttribute("start-time")
      etime=node.getAttribute("last-time")
      tbytes=node.getAttribute("total-bytes")

      cNode=node.getElementsByTagName("client")
      cip=cNode[0].getAttribute("ip-address")
      cport=cNode[0].getAttribute("port")
      cbytes=cNode[0].getAttribute("bytes")
      cpackets=cNode[0].getAttribute("packets")
      cgid=cNode[0].getAttribute("host-group-ids")
      ccountry=cNode[0].getAttribute("country")
      chostname=cNode[0].getAttribute("host-name")
      cflagNode=cNode[0].getElementsByTagName("flags")
      csyn=cflagNode[0].getAttribute("syn")
      csynack=cflagNode[0].getAttribute("syn-ack")
      crst=cflagNode[0].getAttribute("rst")
      cfin=cflagNode[0].getAttribute("fin")
      cintNode=cNode[0].getElementsByTagName("interface")
      ctranslatedip=cNode[0].getAttribute("xlate-ip-address")
      ctranslatedport=cNode[0].getAttribute("xlate-port")
      cint=''
      if cintNode != None:
         for cintNodeItem in cintNode:
            cintExporter=cintNodeItem.getAttribute("exporter-ip")
            cintIfIndex=cintNodeItem.getAttribute("if-index")
            cintDirection=cintNodeItem.getAttribute("direction")
            if cint == '': cint=cintExporter+"("+cintDirection+":"+cintIfIndex+")"
            else: cint=cint + ", " + cintExporter+"("+cintDirection+":"+cintIfIndex+")"

      sNode=node.getElementsByTagName("server")
      sip=sNode[0].getAttribute("ip-address")
      sport=sNode[0].getAttribute("port")
      stranslatedip=sNode[0].getAttribute("xlate-ip-address")
      stranslatedport=sNode[0].getAttribute("xlate-port")
      sbytes=sNode[0].getAttribute("bytes")
      spackets=sNode[0].getAttribute("packets")
      sgid=sNode[0].getAttribute("host-group-ids")
      scountry=sNode[0].getAttribute("country")
      shostname=sNode[0].getAttribute("host-name")
      sflagNode=sNode[0].getElementsByTagName("flags")
      ssyn=sflagNode[0].getAttribute("syn")
      ssynack=sflagNode[0].getAttribute("syn-ack")
      srst=sflagNode[0].getAttribute("rst")
      sfin=sflagNode[0].getAttribute("fin")
      sintNode=cNode[0].getElementsByTagName("interface")
      sint=''
      if sintNode != None:
         for sintNodeItem in sintNode:
            sintExporter=sintNodeItem.getAttribute("exporter-ip")
            sintIfIndex=sintNodeItem.getAttribute("if-index")
            sintDirection=sintNodeItem.getAttribute("direction")
            if sint == '': sint=sintExporter+"("+sintDirection+":"+sintIfIndex+")"
            else: sint=sint + ", " + sintExporter+"("+sintDirection+":"+sintIfIndex+")"

      cgid='"'+cgid+'"'
      sgid='"'+sgid+'"'
      cint='"'+cint+'"'
      sint='"'+sint+'"'

      flow_output.append({"flowid":flowid, "stime":stime, "etime":etime, "tbytes":tbytes, "chostname":chostname, "shostname":shostname, \
         "cip":cip, "cport":cport, "cbytes":cbytes, "cpackets":cpackets, "cgid":cgid, "ccountry": ccountry, "csyn":csyn, "csynack":csynack, "crst":crst, "cfin":cfin, \
         "sip":sip, "sport":sport, "sbytes":sbytes, "spackets":spackets, "sgid":sgid, "scountry": scountry, "ssyn":ssyn, "ssynack":ssynack, "srst":srst, "sfin":sfin, \
         "cint":cint, "sint":sint, "stranslatedip":stranslatedip, "ctranslatedip":ctranslatedip, "stranslatedport":stranslatedport, "ctranslatedport":ctranslatedport})

   return flow_output

def genxmlHostGroups(did):
   doc = xml.dom.minidom.Document()
   envelope = doc.createElementNS("http://schemas.xmlsoap.org/soap/envelope/", "soapenc:Envelope")
   envelope.setAttribute("xmlns:soapenc", "http://schemas.xmlsoap.org/soap/envelope/")
   doc.appendChild(envelope)
   body = doc.createElement("soapenc:Body")
   envelope.appendChild(body)
   gethostgrps = doc.createElement("getHostGroups")
   body.appendChild(gethostgrps)
   domain = doc.createElement("domain")
   domain.setAttribute("id", did)
   gethostgrps.appendChild(domain)
   return doc

def getHostGroupsInfo(doc):
   hostGroups_output=[]
   insideNode=doc.getElementsByTagName("inside-hosts")
   outsideNode=doc.getElementsByTagName("outside-hosts")

   for node in insideNode[0].getElementsByTagName("host-group"):
      hgid=node.getAttribute("id")
      hgname=node.getAttribute("name")
      hostGroups_output.append({"IN":"1", "hgid":hgid, "hgname":hgname})

   for node in outsideNode[0].getElementsByTagName("host-group"):
      hgid=node.getAttribute("id")
      hgname=node.getAttribute("name")
      hostGroups_output.append({"IN":"0", "hgid":hgid, "hgname":hgname})

   return hostGroups_output

def getHgName(hgid, hginfo):
   rslt = ''
   for id in hgid.split(','):
      for hgitem in hginfo:
         if id.strip() == hgitem["hgid"].strip():
            if rslt == '': rslt = hgitem["IN"] + ':' + hgitem["hgname"].replace('"','""')
            else: rslt = rslt + "," + hgitem["IN"] + ':' + hgitem["hgname"].replace('"','""')
            break
   
   return '"' + rslt + '"'

def printUsage():
   print 'Usage: ' + sys.argv[0] + ' [-h] [-v] [-o] [-l loginname] {-u userid | -n hostname | -i hostip [-j hostip] | {-w | --port} port | -r hostip range | -g hostgroup id} {-d days | {-s | --start} start_date {-e | --end} end_date} [{-m | --mail}  mailto]'
   print '      -h                         print this help message'
   print '      -l loginname               user id of smc server'
   print '      -u userid                  id of user you want to get his/her flow data'
   print '      -n hostname                name of host you want to get its flow data'
   print '      -i hostip                  ip address of host you want to get its flow data. Note: this option will be ignored if userid or hostname is defined'
   print '      -j another hostip          ip address of the Other host. Note: this must be paired with option -i'
   print '      -r hostip range            ip address range in format like 10.10.10.10.0/24. Note: this option will be ignored if userid or hostname is defined'
   print '      -g hostgroup id            hostgroup id, like 59995, which is "CRDC". Note: this option will be ignored if userid or hostname is defined'
   print '      -o                         search by hostname only, will not try to get username from hostname and search for VPN logs, which is default'
   print '      -c mac address             host mac address in format like XX-XX-XX-XX-XX-XX (this option has to used with -n)'
   print '      -w | --port                tcp/udp port in the format of 22/tcp, 53/udp'
   print '      -m | --mail mailto         send the flow report to mail address mailto'
   print '      -d days                    days ago till now to search'
   print '      -s | --start start_date    start time to search'
   print '      -e | --end end_date        end time to search'
   print '      -p number                  NAT port number - useful for flows behind ASAs or other hosts performing Network Address Translation (filters output)'
   print '      -q number                  Server/Destination port for a translation (filters output)'
   print '      -t NATed IP                NATed ip address - filters output to get the specific NATed ip address'
   print '      --csv                      Outputs Classical coma separated values (CSV) output instead of a table. Useful for processing externally'
   print '      -v                         get more flow details like tcp flags and interface info'
   print '      Note: start_date and end_date are in format of {YYYY-MM-DD | MM/DD/YYYY | MM-DD-YYYY}[Thh:mm:ss], like 2012-10-21T10:12:56 or 2012-10-21'
   print '            if time is omitted, start_date takes 00:00:00, end_date takes 23:59:59.'
   print ''
   print 'Note: This tool uses dce-cli to get the ip address and time frame assigned to target user or host. DCE is able to retrieve the VPN and DHCP data of last 6 months.'
   print '      So this script can only find flow within last 6 months, although the flow data is there.'
   sys.exit()

#################### main function ######################

uid=os.getlogin()

userid=''
hostname=''
hostip=''
hostjp=''
iprange=''
hostgrp=''
isHostOnly=False
isVerbose=False
isClassic=False
mac=''
days=''
start_date=''
end_date=''
mailto=''
natport=''
dstport=''
natip=''
csport=''

try:
   opts, args = getopt.getopt(sys.argv[1:], "hovu:n:d:s:e:m:l:c:i:j:r:g:p:q:t:w:", ["start=", "end=", "mail=", "port=", "csv" ])
except getopt.GetoptError:
   printUsage()
for opt, arg in opts:
   if opt == "-h":
      printUsage()
   elif opt == "-u":
      userid = arg
   elif opt == "-n":
      hostname = arg
   elif opt == "-i":
      hostip = arg
   elif opt == "-j":
      hostjp = arg
   elif opt == "-r":
      iprange = arg
   elif opt == '-o':
      isHostOnly = True
   elif opt in ("-w", "--port"):
      csport = arg
   elif opt == '-v':
      isVerbose = True
   elif opt == "-c":
      mac = arg
   elif opt == "--csv":
      isClassic = True
   elif opt == "-d":
      days = arg
   elif opt == '-g':
      hostgrp = arg
   elif opt == '-p':
      natport = arg
   elif opt == '-q':
      dstport = arg
   elif opt == '-t':
      natip = arg
   elif opt in ("-s", "--start"):
      datetime = arg.split('T')
      if len(datetime) == 1: start_date = datetime[0] + ' 00:00:00'
      else: start_date = datetime[0] + ' ' + datetime[1]
   elif opt in ("-e", "--end"):
      datetime = arg.split('T')
      if len(datetime) == 1: end_date = datetime[0] + ' 23:59:59'
      else: end_date = datetime[0] + ' ' + datetime[1]
   elif opt in ("-m", "--mail"):
      mailto = arg
   elif opt == "-l":
      uid = arg
   else:
      assert False, "Unhandled option"

if (userid == '' and hostname == '' and hostip == '' and iprange =='' and hostgrp == '') or (days == '' and (start_date == '' or end_date == '')):
   printUsage()

ipmap=[]
password=getpass.getpass('Please enter password of ' + uid + ' on SMC server rtp7-smc-1-p:')
passman = urllib2.HTTPPasswordMgrWithDefaultRealm()

start_time=time.strftime("%m/%d/%Y %H:%M:%S",time.localtime())

os.environ['TZ']='UTC'
time.tzset()

start_sec=0
end_sec=0
if days != '':
   end_sec = int(time.time())
   start_sec = end_sec - 24*3600*int(days)   
   end_date = time.strftime("%Y-%m-%d %H:%M:%S",time.gmtime(end_sec))
   start_date = time.strftime("%Y-%m-%d %H:%M:%S",time.gmtime(start_sec))
else:
   end_sec = getsec(end_date, 'UTC')
   start_sec = getsec(start_date, 'UTC') 

if days == '':
   days = str((int(time.time()) - getsec(start_date, 'UTC'))/(3600*24) + 1)

# get dhcp ip
hl=[]
subid = ''
isIPrange = 0
isHostGrp = 0
if userid != '':
   subid = "userid " + userid
   (out, err)=gethostname(userid)
   nl=[]
   for ln in out.split('\n'):
      rs=re.search(r'(.+?-\S+?)\s+?(\d\d-\d\d-\d\d\d\d \d\d:\d\d:\d\d)', ln)
      if rs != None:
         nl.append((rs.group(1), rs.group(2)))

   cur_sec=int(time.mktime(time.localtime()))
   for (host, lastseen) in nl:
      if int(time.mktime(time.strptime(lastseen, "%m-%d-%Y %H:%M:%S"))) - (cur_sec - 3600*24*int(days)) > 0: hl.append(host)
elif hostname != '': # userid is missed, use hostname
   subid = "hostname " + hostname
   hl.append(hostname)
   if not isHostOnly:
      if len(hostname.split('-')) > 1: userid = hostname.split('-')[0].strip()
elif hostip != '': # none of userid or hostname is found, use hostip
   subid = "hostip " + hostip
   st = getLancopeTime(start_date, 'UTC')
   et = getLancopeTime(end_date, 'UTC')
   if hostjp != '': ipmap.append({"stime":st, "etime":et, "ip":hostip+","+hostjp})
   else: ipmap.append({"stime":st, "etime":et, "ip":hostip})
elif iprange != '': # none of userid, hostname or hostip is found, use iprange
   subid = "iprange " + iprange
   isIPrange = 1
   st = getLancopeTime(start_date, 'UTC')
   et = getLancopeTime(end_date, 'UTC')
   ipmap.append({"stime":st, "etime":et, "ip":iprange})  
else: # none of userid, hostname, hostip or iprange is found, use hostgrp
   subid = "Host Group ID " + hostgrp
   isHostGrp = 1
   st = getLancopeTime(start_date, 'UTC')
   et = getLancopeTime(end_date, 'UTC')
   ipmap.append({"stime":st, "etime":et, "ip":hostgrp})  
      
#print "DHCP ip address assigned to " + userid + " in last " + days + " days:"
for host in hl:
   cmd='/usr/local/bin/dce-cli'
   proc=subprocess.Popen([cmd, '-tc', 'lease_history_hostname', '-l', days, host], stdout=subprocess.PIPE)
   (out, err)=proc.communicate()

   #print host
   #print out
# extract data from out, like start time, end time, ip, mac and host name
   lines = out.split("\n")
   for ln in lines:
      rd=re.search(r'(\d+?\.\d+?\.\d+?\.\d+?)\s+?(\S+?)\s+?(\d{1,2}-\d{1,2}-\d{4} \d{1,2}:\d{1,2}:\d{1,2}) UTC(.+)', ln)
      if rd != None:
         dip=rd.group(1).strip()
         dmc=rd.group(2).strip()

         if mac == '' or (mac != '' and dmc.upper() == mac.upper()):

            st=getLancopeTime(rd.group(3).strip(), 'UTC')
            et=rd.group(4).strip()
            if et.find('CURRENT') >= 0: et=time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())
            else: et=getLancopeTime(et.strip(' UTC'), 'UTC')
  
            if getLancopeSec(et) <= start_sec or getLancopeSec(st) >= end_sec: continue
            if start_sec > getLancopeSec(st): st = getLancopeTime(start_date, 'UTC')
            if end_sec < getLancopeSec(et): et = getLancopeTime(end_date, 'UTC')
  
            ipmap.append({"stime":st, "etime":et, "ip":dip, "hostname":host})  

# get vpn ip
if userid != '':
   cmd='/usr/local/bin/dce-cli'
   proc=subprocess.Popen([cmd, '-tc', 'vpn_history_owner', '-l', days, userid], stdout=subprocess.PIPE)
   (out, err)=proc.communicate()

#print "\n\nVPN ip address assigned to " + userid + " in last " + days + " days:"
#print out

   lines = out.split("\n")
   for ln in lines:
      rd=re.search(r'(\d+?\.\d+?\.\d+?\.\d+?)\s+?(\S+?)\s.+?(\d{1,2}-\d{1,2}-\d{4} \d{1,2}:\d{1,2}:\d{1,2}) UTC(.+)', ln)
      if rd != None:
         vip=rd.group(1).strip()
         #pip=rd.group(2).strip()
         st=getLancopeTime(rd.group(3).strip(), 'UTC')
         et=rd.group(4).strip()
         if et.find('NO DISCONNECT LOG') >= 0: continue # ignore VPN log without session end time
         elif et.find('CURRENT') >= 0:  et=time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()) 
         else: et=getLancopeTime(et.strip(' UTC'), 'UTC')

         if getLancopeSec(et) <= start_sec or getLancopeSec(st) >= end_sec: continue
         if start_sec > getLancopeSec(st): st = getLancopeTime(start_date, 'UTC')
         if end_sec < getLancopeSec(et): et = getLancopeTime(end_date, 'UTC')
  
         ipmap.append({"stime":st, "etime":et, "ip":vip})  

######################### get host to ip map done ################################################
#for i in /pmap:
#   print i["stime"] + " --- " + i["etime"] + " : " + i["ip"]

######################### get lancope log ###################

hginfo = []
mailtext='start_time,end_time,client_ip,client_name,client_port,server_ip,server_name,server_port,client_bytes,server_bytes,total_bytes,client_translated_IP,client_translated_port\n'
if isVerbose:
   theurl="https://rtp7-smc-1-p.cisco.com/smc/swsService/configuration"

   thedoc = genxmlHostGroups("111")
   input_xml=thedoc.toprettyxml(encoding="UTF-8")

   hequest = urllib2.Request(theurl, input_xml)
   basic_auth=base64.b64encode(uid + ":" + password)
   hequest.add_header("Authorization",  "Basic %s" % basic_auth)
   hequest.add_header("Content-Type", "application/x-www-form-urlencoded")

   pagehandle = urllib2.urlopen(hequest)
   rslt=pagehandle.read()

   xmldoc=xml.dom.minidom.parseString(rslt)
   hginfo = getHostGroupsInfo(xmldoc)

   mailtext='start_time,end_time,client_ip,client_name,client_hostgrp,client_port,client_syn,client_synack,client_rst,client_fin,client_interface,server_ip,server_name,server_hostgrp,server_port,server_syn,server_synack,server_rst,server_fin,server_interface,client_packets,server_packets,client_bytes,server_bytes,total_bytes,client_translated_IP,client_translated_port\n'

theurl="https://rtp7-smc-1-p.cisco.com/smc/swsService/flows"

if isClassic == True:
   print mailtext,
else:
   #template="{0:20} | {1:20} | {2:15} | {3:5} | {4:15} | {5:5} | {6:15} | {7:5} | {8:8} | {9:8} | {10:8} | {11:26} | {12:26}"
   #print template.format("Start Time","End Time","Source IP","sport","NAT IP", "Nport","destintion IP","dport","src data","dst data","tot.data","Source name", "Destination name")
   print "%-20s|%-20s|%-15s|%-6s|%-15s|%-6s|%-15s|%-6s|%-9s|%-9s|%-9s|%-26s|%-26s" % ("Start Time"," End Time"," Source IP"," sport"," NAT IP", " Nport"," destintion IP"," dport"," src data"," dst data"," tot.data"," Source name", " Destination name")
#print time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())
for ipadd in ipmap:
   incInterface = "false"
   if isVerbose: incInterface = "true"
   thedoc, ff = genxmlGetFlow("None", "111", incInterface, "None")
   stime=ipadd["stime"]
   etime=ipadd["etime"]
   chkip=ipadd["ip"]

   setDate(thedoc, ff, "time-range-selection", stime + ", " + etime)
   if isIPrange: setHost(thedoc, ff, "BETWEEN_SELECTION_1_SELECTION_2", {"s1-ip-address-range-selection":chkip})
   elif isHostGrp: setHost(thedoc, ff, "BETWEEN_SELECTION_1_SELECTION_2", {"s1-host-group-selection":chkip})
   else:
      ip_list = chkip.split(',')
      if len(ip_list) == 1: setHost(thedoc, ff, "BETWEEN_SELECTION_1_SELECTION_2", {"s1-ip-address-list-selection":ip_list[0]})
      else: setHost(thedoc, ff, "BETWEEN_SELECTION_1_SELECTION_2", {"s1-ip-address-list-selection":ip_list[0], "s2-ip-address-list-selection":ip_list[1]})
#   setHost(thedoc, ff, "BETWEEN_SELECTION_1_SELECTION_2", {"s1-ip-address-list-selection":chkip, "s2-host-group-selection":"1"})
#   setTraffic(thedoc, ff, {"total-bytes-range":"10485760, None"})
#   setPort(thedoc, ff, {"exclude":"5900/tcp, 5901/tcp"}, {})
   if csport != '': setPort(thedoc, ff, {"include": csport}, {})
       
   input_xml=thedoc.toprettyxml(encoding="UTF-8")
   print input_xml

   lequest = urllib2.Request(theurl, input_xml)
   basic_auth=base64.b64encode(uid + ":" + password)
   lequest.add_header("Authorization",  "Basic %s" % basic_auth)
   lequest.add_header("Content-Type", "application/x-www-form-urlencoded")

   pagehandle = urllib2.urlopen(lequest)
   rslt=pagehandle.read()

   xmldoc=xml.dom.minidom.parseString(rslt)

   flowinfo=getFlowInfo(xmldoc)
#   print time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())
   for flow in flowinfo:
      # lancope returns a flow whenever its start or end date/time is in the searching scope, so we need to drop the flow whose start time is out of scopt.
      if getLancopeSec(flow["stime"]) < getLancopeSec(stime): continue
      if natip!='' and flow["ctranslatedip"] != natip: continue
      rsltStr = flow["stime"] + "," + flow["etime"] + "," + flow["cip"]  + "," + flow["chostname"] + ","  + \
            flow["cport"] + ","  + flow["sip"] + "," + flow["shostname"] + "," + flow["sport"] + ","  + \
            flow["cbytes"] + "," + flow["sbytes"] + "," + flow["tbytes"] + "," + flow["ctranslatedip"] + "," + flow["ctranslatedport"] + "\n"
      if isVerbose: 
         rsltStr = flow["stime"] + "," + flow["etime"] + "," + flow["cip"]  + "," + flow["chostname"] + "," + getHgName(flow["cgid"].strip('"'), hginfo) + "," + \
               flow["cport"] + "," + flow["csyn"] + "," + flow["csynack"] + "," + flow["crst"] + "," + flow["cfin"] + "," + flow["cint"] + "," + \
               flow["sip"] + "," + flow["shostname"] + "," + getHgName(flow["sgid"].strip('"'), hginfo) + "," + flow["sport"] + "," + flow["ssyn"] + "," + \
               flow["ssynack"] + "," + flow["srst"] + "," + flow["sfin"] + "," + flow["sint"] + "," + flow["cpackets"] + ',' + flow["spackets"] + "," + \
               flow["cbytes"] + "," + flow["sbytes"] + "," + flow["tbytes"] + "," + flow["ctranslatedip"] + "," + flow["ctranslatedport"] + "\n"
      if isClassic == True:
         print rsltStr,
      else:
         if natip!='' and flow["ctranslatedip"] != natip: continue
         if (natport != '' and dstport != ''):
            if flow['sport'] == dstport and flow["ctranslatedport"] == natport:
               print "%-20s|%-20s|%-15s|%-6s|%-15s|%-6s|%-15s|%-6s|%-9s|%-9s|%-9s|%-26s|%-26s" % (flow["stime"], flow["etime"], flow["cip"], flow["cport"], flow["ctranslatedip"], flow["ctranslatedport"], flow["sip"], flow["sport"], flow["cbytes"], flow["sbytes"], flow["tbytes"], flow["chostname"],flow["shostname"])
         elif natport != '':
            #print "Have a NATPORT OF" + natport + "\n"
            if flow["ctranslatedport"] == natport:
               print "%-20s|%-20s|%-15s|%-6s|%-15s|%-6s|%-15s|%-6s|%-9s|%-9s|%-9s|%-26s|%-26s" % (flow["stime"], flow["etime"], flow["cip"], flow["cport"], flow["ctranslatedip"], flow["ctranslatedport"], flow["sip"], flow["sport"], flow["cbytes"], flow["sbytes"], flow["tbytes"], flow["chostname"],flow["shostname"])
         elif dstport != '':
            if flow['sport'] == dstport:
               print "%-20s|%-20s|%-15s|%-6s|%-15s|%-6s|%-15s|%-6s|%-9s|%-9s|%-9s|%-26s|%-26s" % (flow["stime"], flow["etime"], flow["cip"], flow["cport"], flow["ctranslatedip"], flow["ctranslatedport"], flow["sip"], flow["sport"], flow["cbytes"], flow["sbytes"], flow["tbytes"], flow["chostname"],flow["shostname"])
         else:
            print "%-20s|%-20s|%-15s|%-6s|%-15s|%-6s|%-15s|%-6s|%-9s|%-9s|%-9s|%-26s|%-26s" % (flow["stime"], flow["etime"], flow["cip"], flow["cport"], flow["ctranslatedip"], flow["ctranslatedport"], flow["sip"], flow["sport"], flow["cbytes"], flow["sbytes"], flow["tbytes"], flow["chostname"],flow["shostname"])
      #print rsltStr,      
      mailtext = mailtext + rsltStr 
if mailto != '':
   mailsub='netflow report of ' + subid 
   sendMail(mailto, mailsub, mailtext)
