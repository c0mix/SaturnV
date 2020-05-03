import argparse
import configparser
import json
import socket
import urllib3
urllib3.disable_warnings()
from ssh_utils import create_ssh_keys, RemoteClient


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
            out.write('echo "25% completed!" > /tmp/' + script.split('/')[-1].split('.')[0] + '\n')
        # 50% of script execution
        if i == int(delta/2):
            out.write('echo "50% completed!" > /tmp/' + script.split('/')[-1].split('.')[0] + '\n')
        # 75% of script execution
        if i == int((delta*3)/4):
            out.write('echo "75% completed!" > /tmp/' + script.split('/')[-1].split('.')[0] + '\n')
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
        bot.upload_single_file(script.split('.')[0] + '_{}.sh'.format(file_index), '~/npt_automator/scripts/')
        cmd = 'chmod +x ~/npt_automator/'+script.split('.')[0] + '_{}.sh'.format(file_index)
        bot.execute_blindcommand(cmd)
        cmd = 'cd ~/npt_automator/ && '+config['commands']['tmux_generic_cmd'].format(script.split('/')[1].split('_')[0], script.split('.')[0] + '_{}.sh'.format(file_index))
        bot.execute_blindcommand(cmd)


def gobuster_commands(hostnames):
    '''
    Produces a bash file with the gobuster cmd for each web host found by masscan.
    Example:

    '''
    out = open(config['info']['gobuster_hostname_scan_script'], 'w')
    input = open(hostnames, 'r')
    socket.setdefaulttimeout(3)
    http = urllib3.PoolManager()
    print('[+] Checking web service presence on each hostname... This operation may some minutes')
    for host in input.readlines():
        headers = {"User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:62.0) Gecko/20100101 Firefox/62.0", "Connection": "close", "Host":host.strip()}
        # Try to connect with HTTPS

        try:
            url = "https://{}/".format(host.strip())
            http.request('GET', url, headers=headers, timeout=3)
            web_server_https = True
        except:
            web_server_https = False

        # Try to connect with HTTP
        try:
            url = "http://{}/".format(host.strip())
            http.request('GET', url, headers=headers, timeout=3)
            web_server_http = True
        except:
            web_server_http = False

        if web_server_http:
            out.write(config['commands']['gobuster_cmd'].format('http://' + host.strip() + '/', host.strip().replace('.', '_')) + '.txt\n')
        if web_server_https:
            out.write(config['commands']['gobuster_cmd'].format('https://' + host.strip() + '/', host.strip().replace('.', '_')) + '.txt\n')
        '''
        out.write(config['commands']['gobuster_cmd'].format('http://' + host.strip() + '/', host.strip().replace('.', '_')) + '.txt\n')
        out.write(config['commands']['gobuster_cmd'].format('https://' + host.strip() + '/', host.strip().replace('.', '_')) + '.txt\n')
        '''

    out.close()
    input.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('-i', '--input', help='Input file', required=True)
    args = parser.parse_args()

    try:
        config = configparser.ConfigParser()
        config.read('config.conf')
    except:
        print('[-] The configuration file "config.conf" was not found inside this directory')
        exit(1)

    # SUPPORT LIST
    bot_list = []

    # BOT LIST
    ssh_key_path = create_ssh_keys()
    for item in config['bots']['bots'].split(';'):
        bot = RemoteClient(host=json.loads(item.strip())['ip'], user=json.loads(item.strip())['username'], ssh_key_filepath=ssh_key_path)
        bot_list.append(bot)

    gobuster_commands(args.input)
    run_script(config['info']['gobuster_hostname_scan_script'], bot_list)