#!/bin/bash

while getopts ":d:" input;do
        case "$input" in
                d) domain=${OPTARG}
                        ;;
                esac
        done
if [ -z "$domain" ]     
        then
                echo "Please give a domain like \"-d domain.com\""
                exit 1
fi


# echo "Internet boy thats my new name"

# echo "please configure the burpcollaborator client url In log4jscan"


# cat alive.txt | waybackurls | sort -u >> way.txt 
# cat way.txt  | sort -u | grep "=" | tee way2.txt

# cat way2.txt | uro | tee paramspiderOutput.txt


echo "Starting CMS detection"
whatweb -i alive.txt | tee whatweb_op.txt


echo "AWS S3 CHECK WITH USING ls command"
for i in $(cat op.txt);do aws s3 ls s3://$i --no-sign-request --region us-west-2 ;done | tee AWSmisCheckLS.txt


cd 


echo "GF patterns scan"
mkdir gfPatternsScan

 
cat way.txt | gf redirect | tee -a gfPatternsScan/redirectGf.txt
cat way.txt | gf xss | tee -a gfPatternsScan/xssGf.txt
cat way.txt | gf ssti | tee -a gfPatternsScan/sstiGf.txt
cat way.txt | gf sqli | tee -a gfPatternsScan/sqliGf.txt
cat way.txt | gf rce | tee -a gfPatternsScan/rceGf.txt
cat way.txt | gf lfi | tee -a gfPatternsScan/lfiGf.txt
cat way.txt | gf ssrf | tee -a gfPatternsScan/ssfrparamsGf.txt





echo "log4jscan Automation but you net to put your burp collaborator client url "
echo "log4jscan Automation but you net to put your burp collaborator client url "

/root/tools/Log4j-RCE-Scanner/./log4j-rce-scanner.sh -l alive.txt -b 8bk99byj0g7y68ymv5afj7w55wbnzc.burpcollaborator.net | tee -a log4jscan.txt

cp way.txt wayback_data/
mkdir wayback_data
cd wayback_data
# for i in $(cat ../all.txt);do echo $i | waybackurls ;done | tee -a way.txt
cat way.txt  | sort -u | grep "=" | tee -a paramlist.txt

cat way.txt u | grep -P "\w+\.js(\?|$)" | sort -u | tee -a jsurls.txt

cat way.txt  | grep -P "\w+\.php(\?|$)" | sort -u  | tee -a phpurls.txt

cat way.txt  | grep -P "\w+\.aspx(\?|$)" | sort -u  | tee -a aspxurls.txt

cat way.txt  | grep -P "\w+\.jsp(\?|$)" | sort -u | tee -a jspurls.txt

cat way.txt  | grep -P "\w+\.txt(\?|$)" | sort -u  | tee -a robots.txt

cd ..

cd 




