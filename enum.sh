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
assetfinder --subs-only $domain | tee -a op.txt


amass enum -passive -d $domain | tee -a op.txt
amass enum -active -d $domain | tee -a amass_ips.txt

cat amass_ips.txt | awk '{print $1}' | tee -a op.txt

cat op.txt | sort -u | tee -a all.txt 
cat all.txt | httprobe | tee -a alive2.txt
cat alive2.txt | sort -u | tee -a alive.txt

echo "checing for sub-domain TakeOver"
subzy -targets all.txt -hide_fails | tee -a SubdomainTakeover.txt

echo "finding parameter and Next scan for xss"
for i in $(cat all.txt);do ./tools/ParamSpider/paramspider.py -d $i ;done 
cat output/*.txt | sort -u | tee -a paramspideroutput.txt

echo "starting Cms Detection"
whatweb -i alive.txt | tee -a whatweb_op.txt 

echo "AWS s3 checking" 
for i in $(cat op.txt);do aws s3 ls s3://$1 --no-sign-request --region us-west-2 ;done| tee Awsmischeck.txt

cd /root/tools/dirsearch
./dirsearch.py -u $domain | tee -a ../../dirseaechfuzz.txt

cd

echo "GF patterns scan" 
mkdir gfpatternsscan

cat alive.txt | waybackurls | sort -u >> waybackdata
cat waybackdata | gf redirect | tee -a gfpatternsscan/redirectGF.txt 
cat waybackdata | gf xss | tee -a gfpatternsscan/xssGF.txt
cat waybackdata | gf ssti | tee -a gfpatternsscan/sstiGF.txt
cat waybackdata | gf sqli | tee -a gfpatternsscan/sqliGF.txt
cat waybackdata | gf rce |  tee -a gfpatternsscan/rceGF.txt
cat waybackdata | gf lif | tee -a gfpatternsscan/lfiGF.txt
cat waybackdata | gf ssrf | tee -a gfpatternsscan/ssrfparamsGF.txt 




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











































