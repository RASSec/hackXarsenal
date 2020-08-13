## hunter-recon 

### What it does ? 
 - fetches subdomains of a target using amass,subdfinder,assetfinder passively
 - resolves the found subdomains 
 - queries tls.bufferover.run API for IPs 
 - merges IP found by bufferove API and massdns 
 - uses httpx for finding alive domains
 - performs permutations and alterations using dnsgen and performs resolution(--active)

 
 ### Requirements
Edit config.yaml and provide respective paths after installing the programs specified 

Download github-subdomains.py from here : https://github.com/gwen001/github-search/blob/master/github-subdomains.py

Also add your github token in config.yaml file


 ### Output files
 
 ```
 command :  python3 hunter.py -d example.com
 
 file structure of output files
 
 output
     -- example.com
        |-- alive-example.com.txt     (alive subdomains)
        |-- ips-example.com.txt       (IPs of the target)
        |-- example.com.txt           (all the subdomains i.e alive+dead)
        |-- resolved-example.com.txt  (resolved subdomains)


Active Mode
command :  python3 hunter.py -d example.com --active

file structure of output files

output
    `-- lpu.in
        |-- alive-lpu.in.txt        (alive sundomains)
        |-- dns-active-lpu.in.txt   (resolved alterations of domains)
        |-- ips-lpu.in.txt          (IPs of the target)
        `-- lpu.in.txt              (all the subdomains i.e alive+dead)


### Passing a list of root domains
`{cat hosts.txt | xargs -I % python3 hunter.py -d % }`






 ```