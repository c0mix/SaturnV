# ![](https://upload.wikimedia.org/wikipedia/commons/1/18/Creative-Tail-rocket.svg) SaturnV
#### Boost your Network Discovery & Recon activity.

SaturnV provides a fast deployable distributed port scanner and information collector infrastructure. This software was developed to provide a lightweight tool to pentesters who need to perform sporadic Network PenTest activities on big ranges of public faced IP subnets. The idea behind this tool is simple: I need that my PC uses remote bots to perform port scans and discovery activities in a distributed way. Once bots have finished the scans I just need to grab the results on my local machine, parse them and output a "starting report" that could be useful for further manual analysis.

### Main Features
- Different scanning approach: since we have to optimize time, masscan is used to perform a SYN scan on all ports of every hosts. The results provided by masscan will be used as input for nmap and other tools that will provide more information about services (like banners or versions).
- Asynchronous operations: bots are autonomous and work without staying connected to any sort of master host. So I can use this software on my PC to start the scan on the bots and then I can turn it off, no data will be lost.
- Customizable: through the configuration file it is possible to tune your scan parameter and the tools command line. 

![](img/architecture.png)

## Dependencies and Installation
### Local (Attacker) Machine Setup
Setup is very simple using pip.
```bash
git clone https://github.com/c0mix/SaturnV.git 
cd SaturnV
pip install -r requirements.txt
```

### Bots Configuration
#### Host Requirements
- Minimum 1GB RAM
- OS: Ubuntu 18.04.4 LTS (This is not mandatory but I've tested the tool on it)

#### Firewall and Security
If you are using Amazon AWS ec2 instances as bots (or any other provider witch uses bult-in firewall configuration), please remember to setup accordingly your security policy, in particular masscan needs the port 44444 open. Below is provided an example of AWS security rule configuration.

![](img/aws_sec_rule.png)

#### User Permissions
In order to boost performance while avoiding permissions errors, bot's user must be in condition to execute sudo commands without asking for password. Add the following line at the end of `/etc/sudoers` file.
```bash
user-name ALL=(ALL) NOPASSWD: ALL
``` 

## Usage Instructions
1. Configuration: declare the IP and the username of all your bots inside the configuration file `config.conf` under the section `bots`.
   ```bash
   [bots]
   bots = {"ip":"213.171.185.113","username":"ecuser"};{"ip":"212.35.216.92","username":"ecuser"}
   ```
   
2. SSH key: create and deploy a ssh key launching the program only with the `--ssh_key` option (`-k`). You can also put an existing key in the `ssh_key` folder and this will be used instead a new one. **PLEASE NOTE that this key will be pushed on all your bots so be careful.** 
    ```bash
    python3 saturnV.py --ssh-key 
    ```
   NOTE: if you want to use Amazon's AWS EC2 instances as bots you can copy the private ssh key that you have deployed on your instances inside `ssh_key` folder of SaturnV.

3. Setup the bots: in order to equip all your bots with the necessary tools you have to launch the program with the `--setup` option only (`-s`). Please remember to check what is your bot network interface name (e.g. eth0) and change the following command inside `bot_dependencies.txt` file at line 21.
    ```bash
    sudo iptables -A INPUT -i eth0 -p tcp --dport 44444 -j DROP
    ```
    If you want you can also edit the dependency list contained in `bot_dependencies.txt` file. **Each line of this file is a bash command that will be executed on all your bots.** By default there are listed the minimum setup commands needed to perform the NPT analysis so you should not delete any command already present in the file. 
    ```bash
    python3 saturnV.py --setup 
    ```

4. Targets: SaturnV can help you in define a correct target list. It is possible to start the software with the `-t` or `--target` option and provide a heterogeneous list of target such as the following `all_targets.txt` file:
    ```text
    185.60.216.34
    www.facebook.com
    31.13.92.0/24
    ``` 
    SaturnV will parse your list, convert domain names into IP addresses and put all targets in CIDR notation inside the default files `original_subnets.txt` and `target_subnets.txt`. 
   ```bash
   python3 saturnV.py --target all_targets.txt
   cat target_subnets.txt 
   185.60.216.34/32
   31.13.86.36/32
   31.13.92.0/24
   ```
   You are now ready to start the analysis **BUT** if you want better performance, greater masscan reliability and an equal bots workload you should split your target nets into equal subnets. In order to to this operation you can use the [subnet_splitter](https://github.com/c0mix/subnet_splitter) script as shown below:
   ```bash
   wget https://raw.githubusercontent.com/c0mix/subnet_splitter/master/subnet_splitter.py 
   python3 subnet_splitter.py --input original_subnets.txt --output target_subnets.txt --size 26
   cat target_subnets.txt 
   185.60.216.34/32
   31.13.86.36/32
   31.13.92.0/26
   31.13.92.64/26
   31.13.92.128/26
   31.13.92.192/26
   ```
   You should notice that the application will specify the original subnets related to an host inside the final report.

5. Masscan: in order to create and the start a masscan port scan you have to:
    1. Review the masscan `masscan_cmd` and `masscan_cmd_udp` command lines in the `config.conf` file, adjusting with your preferred settings the rate and the wait time. Please do not touch the output format and the other {} options. 
    2. Launch the tool with the `--masscan-script` option or with `-mS`. This operation will produce, based on your targets, the file `scripts/masscan_scan_script.sh`.
    3. Launch the tool with the `--masscan-run` option or with `-mR`. This operation will split the aforementioned file on your bots and then start the attacks.
    ```bash
    python3 saturnV.py --masscan-script
    python3 saturnV.py --masscan-run
    ```

6. Check scan status: launching the program with the `--check-scan` option (`-c`) it is possible to verify if the tools activity is `started`, `finished` or not started at all. This step it is strongly suggested before grabbing the results from the bots.
    ```bash
    python3 saturnV.py --check-scan
    ```

7. Grab results: after masscan execution you have to grab the results from your bots (`-g` or `--get-results`). These results will be parsed and used as input for others analysis such as nmap and amass.
    ```bash
    python3 saturnV.py --get-results
    ```

8. Nmap and Amass: based on the results provided by Masscan it is possible to execute in-deep analysis on hosts and open ports. The Nmap tool is used to grab banners (`-nS` or `--nmap-script` option) while Amass (`-aS` or `--amass-script` option) provides useful information regarding hostnames. This analysis are not mandatory but are strongly recommended.
    ```bash
    python3 saturnV.py -nS
    python3 saturnV.py -aS
    python3 saturnV.py --amass-run --nmap-run
    ```    

9. gobuster: based on the results provided by Masscan it is possible to execute in-deep analysis on web services, in particular the gobuster tool is used to discover juicy directory or files (`-gS` or `--gobuster-script` option). This analysis are not mandatory but are strongly recommended. Please note that StaurnV, in order to detect if a web service is listening on a specific port will probe an http and https request against each open ports. Every web service that responds at this first probe will be added as target for gobuster. 
    ```bash
    python3 saturnV.py --gobuster-script
    python3 saturnV.py --gobuster-run
    ```  

10. Report & OSINT: when you are satisfied by all the information gathered you are ready to put everything together in a simple and readable CSV file providing the `--report` or `-r` switch to the application. **Just remember to grab all data from your bots before creating a report!**
    SaturnV can execute some OSINT passive research on discovered hosts. These analysis take advantage of the following resources:
    1. the Bing search engine with the `IP:` dork in order to find juicy file and information hosted on web servers. The results of this analysis will be placed in one single file `outputs/bing/url_resources.txt`.
    2. the Hackertarget API in order to discover as much host names as possible (Limited by request rate).
    3. the SSL certificate analysis in order to find out vhosts.
  If you want to perform these operations, you have to provide the `-o` or `--osint` option while requesting the final report.
    ```bash
    python3 saturnV -g --report --osint # Grab results and produce a report with OSINT info
    python3 saturnV -g --report         # Grab results and produce a report without OSINT info 
    ```

## Execution Example
TODO


## References
- Masscan: https://github.com/robertdavidgraham/masscan
- Nmap: https://nmap.org/
- Amass: https://github.com/OWASP/Amass
- Gobuster: https://github.com/OJ/gobuster
- HackerTarget: https://hackertarget.com/

## Why SaturnV
The name of this tool wants to honor the magnificent NASA rocket which carried men on the moon in 1969.

> As of 2020, the Saturn V remains the tallest, heaviest, and most powerful rocket ever brought to operational status.

![](https://ourplnt.com/wp-content/uploads/2018/07/Saturn-V-at-Johnson-Space-Center-NASA.jpg)

## Legals
The software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose and non infringement. In no event shall the authors or copyright holders be liable for any claim, damages or other liability, whether in an action of contract, tort or otherwise, arising from,out of or in connection with the software or the use or other dealings in the software.

Happy (Ethical) Hacking.
