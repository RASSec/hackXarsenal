import json
import argparse
import subprocess
from pathlib import Path
import re
import yaml
import os
import requests



# function to  extract subdomains
def initial_recon(target):
    # if output directory does not exists , create it
    if not os.path.exists('output'):
        os.makedirs('output')
    if not os.path.exists('output/' + target + "/"):
        os.makedirs('output/' + target + "/")

    
    if args.domain:
        try:
            subprocess.run([path_list['paths']['subfinder'] , '-silent' ,'-d' , target , '-o' , 'output/' + target  + '/subfinder-' + target + '.txt'])
            subprocess.run([path_list['paths']['amass'] , 'enum','-o' ,'output/' + target + '/amass-' + target + '.txt' , '--passive' , '-d' , target])
            os.system(path_list['paths']['assetfinder'] +' -subs-only ' +  target +' > output/' + target + '/assetfinder-' + target + '.txt')
            if len(path_list['tokens']['github']) > 10:
                os.system("python3 " + path_list['paths']['github-subdomains'] + " -d " + target + " -t " + path_list['tokens']['github'] + " > output/" + target + "/github-" + target + ".txt" )
            os.system('cat output/' + target + '/subfinder-' + target + '.txt > output/' + target + '/' + target + '.txt')
            os.system('cat output/' + target + '/amass-' + target + '.txt >> output/' + target + '/' + target + '.txt')
            
            os.system('cat output/' + target + '/assetfinder-' + target + '.txt >> output/' + target + '/' + target + '.txt')
            
            if len(path_list['tokens']['github']) > 10:
                os.system('cat output/' + target + '/github-' + target + '.txt >> output/' + target + '/' + target + '.txt')
            if len('' + path_list['tokens']['github']) > 10:
                os.remove('output/' + target +'/github-' + target +'.txt')
            

            os.system('sort -u output/' + target + '/' + target + '.txt -o output/' + target + '/' + target + '.txt')
            if not args.active:
                os.system('cat output/' + target + '/' + target + '.txt | ' + path_list['paths']['massdns'] + ' -r ' + path_list['paths']['resolver_path'] + ' -t A -o S --flush 2>/dev/null | tee output/' + target + '/resolved-' + target + '.txt')
                os.system('cat output/' + target + '/resolved-' + target + '.txt | grep -Eo \'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\' > output/' + target + '/ips-' + target+ '.txt')

            url = "https://tls.bufferover.run/dns?q=." + target
            resp = requests.get(url)
            temp = []
            domains = []
            regexp = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            l = re.findall(regexp , resp.text)
            new_list = list(set(l))
            with open('ips-tls-' + target +'.txt' , 'w') as f:
                for i in new_list:
                    f.write(i + "\n")
            os.system('cat ips-tls-' + target +'.txt >> output/' + target + '/ips-' + target + '.txt')
            os.system('sort -u output/' + target + '/ips-' + target + '.txt -o output/' + target + '/ips-'+ target +'.txt')
            os.system('rm ips-tls-' + target +'.txt')
            if not args.active:
                os.system('cat output/' + target + '/resolved-' + target +'.txt | awk \'{print $1}\' > output/' + target + '/valid-'+ target +'.txt')
                os.system('sort -u  output/' + target + '/valid-' + target + '.txt -o output/' + target + '/valid-' + target + '.txt')
            if not args.active:
                os.system('rm output/' + target + '/resolved-'+ target +'.txt')
            os.system('rm output/' + target + '/amass-' + target + '.txt')
            os.system('rm output/' + target + '/subfinder-' + target + '.txt')
            os.system('rm output/' + target + '/assetfinder-' + target + '.txt')
            if not args.active:
                os.system('mv output/' + target + '/valid-' + target + '.txt output/' + target + '/resolved-' + target + '.txt')
            
            if args.active:
                os.system('cat output/' + target + "/" + target +'.txt | ' + path_list['paths']['dnsgen'] + ' - --fast | ' + path_list['paths']['massdns'] + ' -r ' + path_list['paths']['resolver_path'] + ' -t A -o S --flush 2>/dev/null | tee output/' + target + '/dns-brute-' + target + '.txt')
                os.system('cat output/' + target + '/dns-brute-' + target + '.txt | grep -Eo \'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\' >> output/' + target + '/ips-' + target+ '.txt')
                os.system('sort -u output/' + target + '/ips-' + target + '.txt -o output/' + target + '/ips-'+ target +'.txt')
                os.system('cat output/' + target + '/dns-brute-' + target + '.txt | awk \'{print $1}\' | tee output/' + target + '/dns-active-' + target + '.txt')
                os.system('sort -u output/' + target + '/dns-active-' + target + '.txt -o output/' + target + '/dns-active-'+ target +'.txt')
                os.system('rm output/' + target + '/dns-brute-' + target + '.txt')

            if not args.active:
                os.system('cat output/' + target + '/resolved-' + target + '.txt | ' + path_list['paths']['httpx'] + ' -silent' + ' -threads 100 | tee output/' + target + '/alive-' + target + '.txt')
            else:
                os.system('cat output/' + target + '/dns-active-' + target + '.txt | ' + path_list['paths']['httpx'] + ' -silent' + ' -threads 100 | tee output/' + target + '/alive-' + target + '.txt')


        
        except KeyboardInterrupt:
            print("QUITTED")
 
        

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(
        description="Hunter",
    )
    parser.add_argument(
        '-d',
        '--domain',
        help='Enter domain name',
        type=str,
        required=False
    )
    parser.add_argument(
        '-a',
        '--active',
        help='Active DNS Bruteforcing',
        action = "store_true"
    )
  
    
    args = parser.parse_args()

    # reading file containing paths

    with open('config.yaml', 'r') as f:
        try:
            path_list  = yaml.safe_load(f)
        except yaml.YAMLError as err:
            print(err)

    # assignment based on the supplied args
    if args.domain:
        target = args.domain
        initial_recon(target )
    
