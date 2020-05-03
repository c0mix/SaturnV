import os
from datetime import datetime
import fnmatch
from stat import S_ISDIR
from saturnV import logger
from paramiko import SSHClient, AutoAddPolicy, RSAKey
from paramiko.auth_handler import AuthenticationException, SSHException
from scp import SCPClient, SCPException
import warnings
warnings.filterwarnings(action='ignore', module='.*paramiko.*')


class RemoteClient:
    """
    Client to interact with a remote host via SSH & SCP.
    """

    def __init__(self, host, user, ssh_key_filepath):
        self.host = host
        self.user = user
        self.ssh_key_filepath = ssh_key_filepath
        self.client = None
        self.scp = None
        self.conn = None
        self.sftp = None


    def __get_ssh_key(self):
        """
        Fetch locally stored SSH key.
        """
        try:
            self.ssh_key = RSAKey.from_private_key_file(self.ssh_key_filepath)
            logger.info(f'Found SSH key at self {self.ssh_key_filepath}')
        except SSHException as error:
            logger.error(error)
        return self.ssh_key


    def __connect(self):
        """
        Open connection to remote host.
        """
        try:
            self.client = SSHClient()
            self.client.load_system_host_keys()
            self.client.set_missing_host_key_policy(AutoAddPolicy())
            self.client.connect(self.host,
                                username=self.user,
                                key_filename=self.ssh_key_filepath,
                                look_for_keys=True,
                                timeout=5000)
            self.scp = SCPClient(self.client.get_transport())
        except AuthenticationException as error:
            logger.info('Authentication failed: did you remember to create an SSH key?')
            logger.error(error)
            raise error
        finally:
            return self.client


    def disconnect(self):
        """
        Close ssh connection.
        """
        self.client.close()
        self.scp.close()


    def bulk_upload(self, files, remote_path):
        """
        Upload multiple files to a remote directory.
        :param files: List of strings representing file paths to local files.
        """
        if self.client is None:
            self.client = self.__connect()
        uploads = [self.upload_single_file(file) for file in files]
        logger.info(f'Finished uploading {len(uploads)} files to {remote_path} on {self.host}')


    def upload_single_file(self, file, remote_path):
        """Upload a single file to a remote directory."""
        if self.client is None:
            self.client = self.__connect()
        try:
            self.scp.put(file,
                         recursive=True,
                         remote_path=remote_path)
        except SCPException as error:
            logger.error(error)
            raise error
        finally:
            logger.info(f'Uploaded {file} to {remote_path}')


    def download_file(self, file):
        """
        Download file from remote host.
        """
        if self.conn is None:
            self.conn = self.__connect()
        self.scp.get(file)


    def sftp_walk(self, remotepath):
        if self.conn is None:
            self.conn = self.__connect()
        self.sftp = self.conn.open_sftp()
        path = remotepath
        files = []
        folders = []
        for f in self.sftp.listdir_attr(remotepath):
            if S_ISDIR(f.st_mode):
                folders.append(f.filename)
            else:
                files.append(f.filename)
        if files:
            yield path, files
        for folder in folders:
            new_path = os.path.join(remotepath, folder)
            for x in self.sftp_walk(new_path):
                yield x


    def execute_commands(self, commands):
        """
        Execute multiple commands in succession.
        :param commands: List of unix commands as strings.
        """
        if self.client is None:
            self.client = self.__connect()
        for cmd in commands:
            stdin, stdout, stderr = self.client.exec_command(cmd)
            stdout.channel.recv_exit_status()
            response = stdout.readlines()
            errors = stderr.readlines()
            for line in response:
                logger.info(f'INPUT: {cmd} | OUTPUT: {line.strip()}')
            for line in errors:
                logger.error(f'INPUT: {cmd} | OUTPUT: {line.strip()}')


    def execute_blindcommand(self, cmd):
        """
        Execute single command without waiting for output.
        :param cmd: unix command as strings.
        """
        if self.client is None:
            self.client = self.__connect()
        self.client.exec_command(cmd)
        logger.info(f'Command: {cmd} Executed on Bot: {self.host}')


    def execute_command(self, cmd):
        """
        Execute single command.
        :param cmd: unix command as strings.
        """
        if self.client is None:
            self.client = self.__connect()
        stdin, stdout, stderr = self.client.exec_command(cmd)
        stdout.channel.recv_exit_status()
        response = stdout.readlines()
        errors = stderr.readlines()
        r_line = ''
        e_line = ''
        for line in response:
            r_line += line
            #logger.info(f'INPUT: {cmd} | OUTPUT: {line.strip()}')
        for line in errors:
            e_line += line
            #logger.error(f'INPUT: {cmd} | OUTPUT: {line.strip()}')
        if r_line == '':
            return e_line.strip()
        else:
            return r_line.strip()


def create_ssh_keys():
    pub_key = None
    priv_key = None
    for file in os.listdir('ssh_key'):
        if 'BEGIN RSA PRIVATE KEY' in open('ssh_key/'+file, 'r').readline():
            priv_key = file
        if 'ssh-rsa' in open('ssh_key/'+file, 'r').readline():
            pub_key = file

    if priv_key and pub_key:
        logger.info(f'SSH key pair found in ssh_key folder, the following key will be used: {priv_key}')

    elif priv_key and not pub_key:
        logger.info(f'SSH private key found in ssh_key folder, the following key will be used: {priv_key}')

    else:
        priv_key = '/nptKey-' + datetime.now().strftime('%Y%m%d%H%M%S')
        keyname = os.getcwd() + '/ssh_key'
        logger.info(f'No SSH key found in ssh_key folder, creating a new one at: {keyname+priv_key}')
        os.system("ssh-keygen -t rsa -b 4096 -N '' -f {}".format(keyname+priv_key))
        os.system("cp {0}.pub ~/.ssh/{1}.pub".format(keyname+priv_key, priv_key))
        os.system("cp {0} ~/.ssh/{1}".format(keyname+priv_key, priv_key))
    return 'ssh_key/' + priv_key

def upload_ssh_key(bot):
    try:
        os.system(f'ssh-copy-id -i {bot.ssh_key_filepath} {bot.user}@{bot.host}>/dev/null 2>&1')
        os.system(f'ssh-copy-id -i {bot.ssh_key_filepath}.pub {bot.user}@{bot.host}>/dev/null 2>&1')
        logger.info(f'{bot.ssh_key_filepath} uploaded to {bot.host}')
    except FileNotFoundError as error:
        logger.error(error)