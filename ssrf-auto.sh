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

echo "please provide burp client link in burpserverCall.txt please then ssrf ffuf work NOTE"

blc $domain | tee brokenlinkscan.txt

# echo "finding parameter and Next scan for xss"
# for i in $(cat all.txt);do ./tools/ParamSpider/paramspider.py -d ;done
# cat output/*.txt | sort -u | tee -a paranspiderOutput2.txt
./tools/ParamSpider/paramspider.py -d $domain | tee para 

echo "ffuf Starting"
for i in $(cat para.txt);do ffuf -u $i -w /root/burpServerCall.txt -t 60 ;done| tee ssrfWithFfuf.txt








