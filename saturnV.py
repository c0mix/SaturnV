import socket
import ssh_utils
import argparse
import configparser
import json
import sys
import os
import datetime
import glob
import ipaddress
import csv
import re
from libnmap.parser import NmapParser
from loguru import logger
log_config = {"handlers":[{"sink": sys.stdout, "format": "{time:HH:mm:ss} | {level} | {message}"},{"sink": "logs/log_{}.log".format(datetime.datetime.now().strftime("%m%d%Y-%H%M%S")), "serialize": True}]}
logger.configure(**log_config)
import osint_utils
import urllib3
urllib3.disable_warnings()


class Host:

    def __init__(self, ip):
        self.ip = ip
        self.services = []
        self.name = ''
        self.subnet = ''

    # Getter
    def get_ip(self):
        return str(self.ip)

    def get_services(self):
        return self.services

    def get_name(self):
        return self.name

    def get_subnet(self):
        return self.subnet

    # Setter
    def add_service(self, service):
        self.services.append(service)

    def set_name(self, name):
        self.name += name

    def set_subnet(self, sub):
        self.subnet = sub


class Service:

    def __init__(self, port, protocol):
        self.port = port
        self.protocol = protocol
        self.version = ''
        self.name = ''
        self.info = ''

    # Getter
    def get_port(self):
        return self.port

    def get_name(self):
        return self.name

    def get_info(self):
        return self.info

    def get_protocol(self):
        return self.protocol

    def get_version(self):
        return self.version

    # Setter
    def set_version(self, version):
        self.version += version

    def set_name(self, name):
        self.name = name

    def set_info(self, info):
        self.info += info


def parse_masscan():
    '''
    Parse masscan greppable output and creates a list of hosts (host_list) where every single item of the list is a service found open on a specific ip.
    Example input file:
    # Masscan 1.0.6 scan initiated Mon Oct  7 08:39:57 2019
    # Ports scanned: TCP(65536;0-65535) UDP(0;) SCTP(0;) PROTOCOLS(0;)
    Timestamp: 1570437754   Host: 80.22.153.66 ()   Ports: 13888/open/tcp//unknown//
    Timestamp: 1570437817   Host: 94.93.62.71 ()    Ports: 25/open/tcp//smtp//
    '''
    logger.info(f'Parsing Masscan scan results')
    tot_service = 0
    if os.path.isfile(config['info']['targets_original_subs']):
        subnet = True
    else:
        subnet = False
    for file in glob.glob(config['info']['masscan_greppable_output']):
        if config['info']['npt_name'] in file:
            try:
                csv_in = open(str(file), 'r')
                csv_reader = csv.reader(csv_in, delimiter='\t')
                for row in csv_reader:
                    if 'Timestamp' in str(row):
                        already_found = False
                        ip = row[1].split(' ')[1]
                        port = row[2].split(' ')[1].split('/')[0]
                        protocol = row[2].split(' ')[1].split('/')[2]
                        service = row[2].split(' ')[1].split('/')[4]
                        ser = Service(port, protocol)
                        ser.set_name(service)
                        # Verify if host was already listed
                        for host in host_list:
                            if host.get_ip() == ip:
                                # Verify if service is not a duplicate
                                already_listed_service = False
                                for s in host.get_services():
                                    if s.get_port() == ser.get_port() and s.get_protocol() == ser.get_protocol():
                                        already_listed_service = True
                                # New service found on a previous known host
                                if not already_listed_service:
                                    host.add_service(ser)
                                    tot_service += 1
                                if subnet and get_subnet(ip):
                                    host.set_subnet(get_subnet(ip))
                                already_found = True
                        # New service fond on a new host
                        if not already_found:
                            tot_service += 1
                            host = Host(ip)
                            host.add_service(ser)
                            host_list.append(host)
                            if subnet and get_subnet(ip):
                                host.set_subnet(get_subnet(ip))
                csv_in.close()
            except:
                logger.error(f'Error in Masscan parsing')
                exit(1)
    return len(host_list), tot_service


def parse_amass():
    '''
    Given as input the amass output file, extract information about the fqdn
    '''
    logger.info(f'Parsing Amass scan results')
    for file in glob.glob(config['info']['amass_output']):
        if config['info']['npt_name'] in file:
            try:
                amass_res = open(file, 'r')
                for line in amass_res:
                    ip = line.split(' ')[1].strip()
                    fqdn = line.split(' ')[0].strip()
                    for host in host_list:
                        if ip == host.get_ip():
                            host.set_name(fqdn.replace('"', '')+'\n')
            except:
                pass


def parse_nmap():
    '''
    Given as input all the xml produced by the nmap_commands outputs, extract information about the software version etc...
    '''
    logger.info(f'Parsing Nmap scan results')
    found = 0
    for file in glob.glob(config['info']['nmap_xml_output']):
        if config['info']['npt_name'] in file:
            try:
                nmap_report = NmapParser.parse_fromfile(str(file))
                for ser in nmap_report.hosts[0].services:
                    found += 1
                    try:
                        version = re.match('product: (?P<product>.*) ostype:', ser.banner).group(1)
                        for host in host_list:
                            for serv in host.get_services():
                                if str(nmap_report.hosts[0].address) == host.get_ip() and str(ser.port) == str(serv.get_port()) and str(ser.protocol) == str(serv.get_protocol()):
                                    serv.set_version(version)
                                    if str(ser.service) != 'unknown' and str(ser.service) != '':
                                        serv.set_name(ser.service)

                    except:
                        for host in host_list:
                            for serv in host.get_services():
                                if str(nmap_report.hosts[0].address) == host.get_ip() and str(ser.port) == str(serv.get_port()) and str(ser.protocol) == str(serv.get_protocol()):
                                    if str(ser.service) != 'unknown' and str(ser.service) != '':
                                        serv.set_name(ser.service)
                                    #found += 1
            except:
                logger.error(f'Error in parsing nmap file: {file} Maybe no open ports were found or the file is corrupted!')
    return found


def create_report(osint):
    '''
    Produces the final csv with all the information gathered
    '''
    logger.info(f"Creating the final report: {config['info']['csv_output']}")
    csv_out = open(config['info']['csv_output'], 'w')
    if os.path.isfile(config['info']['targets_original_subs']):
        subnet = True
    else:
        subnet = False
    if subnet and osint:
        fieldnames = ['Host', 'Port', 'Protocol', 'Service', 'Version', 'Host Name', 'Host Name (SSLCert)', 'Subnet']
        csv_writer = csv.DictWriter(csv_out, fieldnames=fieldnames, delimiter='\t')
        csv_writer.writeheader()
        for host in host_list:
            for serv in host.get_services():
                csv_writer.writerow(
                    {'Host': host.get_ip(), 'Port': serv.get_port(), 'Protocol': serv.get_protocol(),
                     'Service': serv.get_name(), 'Version': serv.get_version(),
                     'Host Name': host.get_name().strip(), 'Host Name (SSLCert)': serv.get_info().strip(),
                     'Subnet': host.get_subnet()})
    elif subnet and not osint:
        fieldnames = ['Host', 'Port', 'Protocol', 'Service', 'Version', 'Host Name', 'Subnet']
        csv_writer = csv.DictWriter(csv_out, fieldnames=fieldnames, delimiter='\t')
        csv_writer.writeheader()
        for host in host_list:
            for serv in host.get_services():
                csv_writer.writerow(
                    {'Host': host.get_ip(), 'Port': serv.get_port(), 'Protocol': serv.get_protocol(),
                     'Service': serv.get_name(), 'Version': serv.get_version(),
                     'Host Name': host.get_name().strip(), 'Subnet': host.get_subnet()})
    elif osint and not subnet:
        fieldnames = ['Host', 'Port', 'Protocol', 'Service', 'Version', 'Host Name', 'Host Name (SSLCert)']
        csv_writer = csv.DictWriter(csv_out, fieldnames=fieldnames, delimiter='\t')
        csv_writer.writeheader()
        for host in host_list:
            for serv in host.get_services():
                csv_writer.writerow(
                    {'Host': host.get_ip(), 'Port': serv.get_port(), 'Protocol': serv.get_protocol(),
                     'Service': serv.get_name(), 'Version': serv.get_version(),
                     'Host Name': host.get_name().strip(),
                     'Host Name (SSLCert)': serv.get_info().strip()})
    else:
        fieldnames = ['Host', 'Port', 'Protocol', 'Service', 'Version', 'Host Name']
        csv_writer = csv.DictWriter(csv_out, fieldnames=fieldnames, delimiter='\t')
        csv_writer.writeheader()
        for host in host_list:
            for serv in host.get_services():
                csv_writer.writerow(
                    {'Host': host.get_ip(), 'Port': serv.get_port(), 'Protocol': serv.get_protocol(),
                     'Service': serv.get_name(), 'Version': serv.get_version(),
                     'Host Name': host.get_name().strip()})
    csv_out.close()


def masscan_commands():
    '''
    Given the target list as input, produces a bash file with the masscan cmds.
    '''
    subs_list = []
    input = open(config['info']['targets_file'], 'r')
    j = 0
    for line in input.readlines():
        subs_list.append(line.strip())
        j += 1
    input.close()
    output = open(config['info']['masscan_scan_script'], 'w')
    i = 0
    for target in list(set(subs_list)):
        i += 1
        output.write(config['commands']['masscan_cmd'].format('1-16383', config['info']['npt_name'], target.replace('.', '_').replace('/','_'), 1, target)+'\n')
        output.write(config['commands']['masscan_cmd'].format('16384-32767', config['info']['npt_name'], target.replace('.', '_').replace('/','_'), 2, target)+'\n')
        output.write(config['commands']['masscan_cmd'].format('32768-49151', config['info']['npt_name'], target.replace('.', '_').replace('/','_'), 3, target)+'\n')
        output.write(config['commands']['masscan_cmd'].format('49152-65535', config['info']['npt_name'], target.replace('.', '_').replace('/','_'), 4, target)+'\n')
        output.write(config['commands']['masscan_cmd_udp'].format(config['info']['npt_name'], target.replace('.', '_').replace('/','_'), target)+'\n')
    output.close()
    if i == j:
        logger.info(f'Successfully parsed and added {i} targets subnets')
    else:
        logger.warning(f'Subnets parsed from input {j} Subnets added to masscan script {i} if masscan subnets are lower maybe there were duplicates in input file! ')


def nmap_commands():
    '''
    Produces a bash file with the nmap cmd for each host and ports found by masscan.
    '''
    out = open(config['info']['nmap_scan_script'], 'w')
    for host in host_list:
        target = host.get_ip()
        port_tcp = ''
        port_udp = ''
        for ser in host.services:
            if ser.get_protocol() == 'udp':
                port_udp += ser.get_port() + ','
            elif ser.get_protocol() == 'tcp':
                port_tcp += ser.get_port()+','
        if port_tcp != '':
            out.write(config['commands']['nmap_cmd'].format(config['info']['npt_name']+'_'+target.replace('.', '_'), port_tcp[:-1], target+'\n'))
        if port_udp != '':
            out.write(config['commands']['nmap_cmd_udp'].format(config['info']['npt_name']+'_'+target.replace('.', '_'), port_udp[:-1], target+'\n'))
    out.close()


def amass_commands():
    '''
    Produces a bash file with the amass cmd for each host found by masscan.
    Example:
    amass intel -active -ip -addr 80.22.153.66 >> amass_out.txt
    amass intel -active -ip -addr 94.93.62.71 >> amass_out.txt
    '''
    out = open(config['info']['amass_scan_script'], 'w')
    for host in host_list:
        out.write(config['commands']['amass_cmd'].format(host.get_ip(), config['info']['amass_output'].split('*')[0]+config['info']['npt_name']+'_'+host.get_ip().replace('.', '_')) + '.txt\n')
    out.close()


def gobuster_commands():
    '''
    Produces a bash file with the gobuster cmd for each web host found by masscan.
    Example:
    ./tools/gobuster dir --useragent "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" --insecuressl --followredirect --expanded --wordlist tools/common_wordlist.txt --url https://185.198.116.138:4443/ --output outputs/gobuster/185_198_116_138.txt
    ./tools/gobuster dir --useragent "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" --insecuressl --followredirect --expanded --wordlist tools/common_wordlist.txt --url http://185.198.116.161:80/ --output outputs/gobuster/185_198_116_161.txt
    '''
    out = open(config['info']['gobuster_scan_script'], 'w')
    socket.setdefaulttimeout(3)
    http = urllib3.PoolManager()
    logger.info(f'Checking web service presence on each open service, this might take a while...')
    for host in host_list:
        for service in host.get_services():
            # Skip UDP services
            if str.lower(service.get_protocol()) == 'udp':
                continue
            headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:62.0) Gecko/20100101 Firefox/62.0", "Connection": "close"}
            # Try to connect with HTTPS
            try:
                url = "https://{}:{}/".format(host.get_ip(), service.get_port())
                http.request('GET', url, headers=headers, timeout=3)
                web_server_https = True
            except:
                web_server_https = False

            # Try to connect with HTTP
            try:
                url = "http://{}:{}/".format(host.get_ip(), service.get_port())
                http.request('GET', url, headers=headers, timeout=3)
                web_server_http = True
            except:
                web_server_http = False

            if web_server_http:
                out.write(config['commands']['gobuster_cmd'].format('http://'+host.get_ip()+':'+service.get_port()+'/', config['info']['npt_name']+'_'+host.get_ip().replace('.', '_')) + '.txt\n')
            if web_server_https:
                out.write(config['commands']['gobuster_cmd'].format('https://'+host.get_ip()+':'+service.get_port()+'/', config['info']['npt_name']+'_'+host.get_ip().replace('.', '_')) + '.txt\n')
    out.close()


def run_script(script, bot_list):
    '''
    Splits and Executes a given script on the different bots
    '''
    tot_line = sum(1 for l in open(script, 'r'))
    attack = open(script, 'r')
    delta = (int(tot_line/len(bot_list)))
    i = 0
    file_index = 1
    out = open(script.split('.')[0]+'_{}.sh'.format(file_index), 'w')
    out.write('echo "started" > /tmp/' + script.split('/')[-1].split('.')[0] + '\n')
    finish = False
    # create a sub-script for each bot
    for line in attack.readlines():
        # 25% of script execution
        if i == int(delta/4):
            out.write('echo "25% completed" > /tmp/' + script.split('/')[-1].split('.')[0] + '\n')
        # 50% of script execution
        if i == int(delta/2):
            out.write('echo "50% completed" > /tmp/' + script.split('/')[-1].split('.')[0] + '\n')
        # 75% of script execution
        if i == int((delta*3)/4):
            out.write('echo "75% completed" > /tmp/' + script.split('/')[-1].split('.')[0] + '\n')
        if i == delta and not finish:
            out.write('echo "100% completed" > /tmp/'+script.split('/')[-1].split('.')[0])
            out.close()
            i = 0
            file_index += 1
            out = open(script.split('.')[0] + '_{}.sh'.format(file_index), 'w')
            out.write('echo "started" > /tmp/' + script.split('/')[-1].split('.')[0]+'\n')
            if file_index == len(bot_list):
                finish = True
        out.write(line)
        i += 1
    out.write('echo "100% completed" > /tmp/' + script.split('/')[-1].split('.')[0])
    out.close()

    # Execute command on bots
    file_index = 0
    for bot in bot_list:
        file_index += 1
        bot.upload_single_file(script.split('.')[0] + '_{}.sh'.format(file_index), '~/saturnV/scripts/')
        cmd = 'chmod +x ~/saturnV/'+script.split('.')[0] + '_{}.sh'.format(file_index)
        bot.execute_blindcommand(cmd)
        cmd = 'cd ~/saturnV/ && '+config['commands']['tmux_generic_cmd'].format(script.split('/')[1].split('_')[0], script.split('.')[0] + '_{}.sh'.format(file_index))
        bot.execute_blindcommand(cmd)


def get_subnet(ip):
    '''
    Given an ip as input, looks inside all targets subnet and locate the correct one.
    '''
    target_subnets = []
    with open(config['info']['targets_original_subs'], 'r') as f:
        for sub in f.readlines():
            target_subnets.append(sub.strip())
    for subnet in target_subnets:
        if ipaddress.ip_address(ip) in ipaddress.ip_network(subnet, False):
            return subnet
    return ''


def elaborate_target(targets_file):
    output = open(config['info']['targets_original_subs'], 'w')
    with open(targets_file, 'r') as input:
        for line in input.readlines():
            try:
                output.write(str(ipaddress.ip_network(line.strip().replace(' ','')))+'\n')
            except:
                try:
                    output.write(str(ipaddress.ip_network(socket.gethostbyname(line.strip().replace(' ',''))))+'\n')
                except:
                    logger.error(f'Unable to parse the line: {line.strip()}')
    output.close()
    os.system('cp {} {}'.format(config['info']['targets_original_subs'], config['info']['targets_file']))
    logger.info(f"File {targets_file} was successfully elaborated, new targets file is {config['info']['targets_original_subs']}")


def check_scripts(script, bot_list):
    '''
    Checks if the script executed on a bot has started or completed its tasks
    '''
    for bot in bot_list:
        check = bot.execute_command('cat /tmp/{}_scan_script'.format(script))
        if 'No such file or directory' in check:
            logger.error(f'{script} NOT started on Bot: {bot.host}')
        elif 'started' in check:
            logger.warning(f'{script} execution STARTED on Bot: {bot.host}')
        elif 'completed' in check:
            logger.info(f'{script} execution {check} on Bot: {bot.host}')


def check_output_files(tool_output_dir):
    try:
        for file in glob.glob(config['info'][tool_output_dir]):
            if config['info']['npt_name'] in file:
                return True
        return False
    except:
        return False

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Boost your Network Discovery & Recon activity.')
    parser.add_argument('-t', '--target', help='Takes as input a multi format target list and produces the original_subnets.txt file', required=False)
    parser.add_argument('-k', '--ssh-key', help='Deploy an ssh key on bots', required=False, action="store_true", default=False)
    parser.add_argument('-s', '--setup', help='Install all the required tools and create folder structure on bots', required=False, action="store_true", default=False)
    parser.add_argument('-mS', '--masscan-script', help='Create the Masscan script', required=False, action="store_true", default=False)
    parser.add_argument('-nS', '--nmap-script', help='Create the Nmap script (Masscan results needed!)', required=False, action="store_true", default=False)
    parser.add_argument('-aS', '--amass-script', help='Create the Amass script (Masscan results needed!)', required=False, action="store_true", default=False)
    parser.add_argument('-gS', '--gobuster-script', help='Create the Gobuster script (Masscan results needed!)', required=False, action="store_true", default=False)
    parser.add_argument('-mR', '--masscan-run', help='Split and run Masscan script on bots', required=False, action="store_true", default=False)
    parser.add_argument('-nR', '--nmap-run', help='Split and run Nmap script on bots', required=False, action="store_true", default=False)
    parser.add_argument('-aR', '--amass-run', help='Split and run Amass script on bots', required=False, action="store_true", default=False)
    parser.add_argument('-gR', '--gobuster-run', help='Split and run Gobuster script on bots', required=False, action="store_true", default=False)
    parser.add_argument('-g', '--get-results', help='Collect outputs from all bots', required=False, action="store_true", default=False)
    parser.add_argument('-c', '--check-scan', help='Check scan progress on each bot', required=False, action="store_true", default=False)
    parser.add_argument('-o', '--osint', help='Perform OSINT activity (Grab info from SSL certs, HackerTarget and Bing Dork)', required=False, action="store_true", default=False)
    parser.add_argument('-r', '--report', help='Create the final report (at least Masscan results needed!)', required=False, action="store_true", default=False)
    parser.add_argument('-v', '--verbose', help='Increase output verbosity', required=False, action="store_true", default=False)
    args = parser.parse_args()

    # WELCOME BANNER
    print("\n***** Welcome to SaturnV *****\n")

    # INITIAL CHECKS
    if 'True' not in str(args) and not args.target:
        logger.error(f'No argument provided!\n')
        os.system('python3 '+sys.argv[0]+' -h')
        exit(1)

    try:
        config = configparser.ConfigParser()
        config.read('config.conf')
    except:
        logger.error(f'The configuration file "config.conf" was not found inside this directory')
        exit(1)

    # ELABORATE TARGET LIST
    if args.target:
        if os.path.isfile(args.target):
            elaborate_target(args.target)
            exit(0)
        else:
            logger.error(f'The supplied argument: "{args.target}" is not a valid file!')
            exit(1)

    # SUPPORT LIST
    bot_list = []
    host_list = []

    # BOT LIST
    ssh_key_path = ssh_utils.create_ssh_keys()
    for item in config['bots']['bots'].split(';'):
        bot = ssh_utils.RemoteClient(host=json.loads(item.strip())['ip'], user=json.loads(item.strip())['username'], ssh_key_filepath=ssh_key_path)
        bot_list.append(bot)

    # SSH
    if args.ssh_key:
        for bot in bot_list:
            ssh_utils.upload_ssh_key(bot)

    # SETUP
    if args.setup:
        for bot in bot_list:
            bot.execute_blindcommand('mkdir ~/saturnV')
            bot.execute_blindcommand('touch /tmp/saturnV_install_log.txt')
            bot.upload_single_file('bot_dependencies.txt', '~/saturnV/bot_dependencies.sh')
            bot.execute_blindcommand('chmod +x ~/saturnV/bot_dependencies.sh')
            logger.info(f'Starting dependencies installation on Bot {bot.host}, this might take a while...')
            bot.execute_command('./saturnV/bot_dependencies.sh')
            file_log_name = 'logs/saturnV_install_log_{}.txt'.format(bot.host.replace('.','_'))
            bot.scp.get('/tmp/saturnV_install_log.txt', file_log_name)
            logger.info(f'Dependencies installation on Bot {bot.host} is FINISHED, please review {file_log_name} log file to check if everything went well!')

    # SCRIPT BUILDER
    if args.masscan_script:
        masscan_commands()
    if args.nmap_script or args.amass_script or args.gobuster_script:
        tot_hosts, tot_services = parse_masscan()
        if tot_hosts == 0 and tot_services == 0:
            logger.error(f'No Masscan output presents in {config["info"]["masscan_greppable_output"]} or 0 hosts founded during the analysis. Exiting')
            exit(1)
        logger.info(f'Masscan discovery has found {tot_services} open services on {tot_hosts} different hosts')
        if args.nmap_script:
            nmap_commands()
            logger.info(f'Nmap script created: {config["info"]["nmap_scan_script"]}')
        if args.amass_script:
            amass_commands()
            logger.info(f'Amass script created: {config["info"]["amass_scan_script"]}')
        if args.gobuster_script:
            gobuster_commands()
            logger.info(f'Gobuster script created: {config["info"]["gobuster_scan_script"]}')

    # ATTACK LAUNCHER
    if args.masscan_run:
        run_script(config['info']['masscan_scan_script'], bot_list)
    if args.nmap_run:
        run_script(config['info']['nmap_scan_script'], bot_list)
    if args.amass_run:
        run_script(config['info']['amass_scan_script'], bot_list)
    if args.gobuster_run:
        run_script(config['info']['gobuster_scan_script'], bot_list)

    # SCAN RESULTS
    if args.check_scan:
        for script in ['masscan', 'nmap', 'amass', 'gobuster']:
            check_scripts(script, bot_list)

    if args.get_results:
        for bot in bot_list:
            for path, files in bot.sftp_walk('/home/{}/saturnV/outputs/'.format(bot.user)):
                last_folder = 'outputs/'+path.split('/')[-1]
                if not os.path.exists(last_folder):
                    os.mkdir(last_folder)
                logger.info(f'Transferring {last_folder} from bot {bot.host} to local outputs/ folder')
                for file in files:
                    bot.sftp.get(os.path.join(os.path.join(path, file)), last_folder+'/'+file)

    # REPORT
    if args.report:
        tot_hosts, tot_services = parse_masscan()
        if check_output_files('nmap_xml_output'):
            logger.info(f'Nmap outputs found! Adding them to final report')
            tot_nmap_services = parse_nmap()
            logger.info(f'Services found by Nmap: {tot_nmap_services} - Services found by Masscan: {tot_services}')
        if check_output_files('amass_output'):
            logger.info(f'Amass outputs found! Adding them to final report')
            parse_amass()
        if check_output_files('gobuster_result_output'):
            logger.info(f'Gobuster outputs found! you can manually review them in {config["info"]["gobuster_result_folder"]} folder')
        if args.osint:
            logger.info(f'Getting information through OSINT')
            for host in host_list:
                osint_utils.bing(host, output=config['info']['bing_result'])
                osint_utils.queryAPI(host)
                for s in host.get_services():
                    osint_utils.sslGrabber(host, s)
            logger.info(f'Web application URLs eventually discovered with Bing dork can be found here: {config["info"]["bing_result"]}')
        create_report(args.osint)
