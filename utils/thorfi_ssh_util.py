import paramiko
from scp import SCPClient

def ssh_command_with_out(ssh, command):

    transport = ssh.get_transport()
    transport.set_keepalive(20)

    channel = transport.open_session()
    channel.settimeout(30)
    channel.exec_command(command)

    exit_status = channel.recv_exit_status()  # Blocks until command succeeds
    stdout = channel.makefile('rb').read()  # Be sure to read before the channel closes
    stderr = channel.makefile_stderr('rb').read()

    channel.close()

    return exit_status, stdout, stderr


def ssh_command(ssh, command):

    transport = ssh.get_transport()
    transport.set_keepalive(20)

    channel = transport.open_session()
    channel.settimeout(30)
    channel.exec_command(command)

    exit_status = channel.recv_exit_status()  # Blocks until command succeeds
    #stdout = channel.makefile('rb').read()  # Be sure to read before the channel closes
    #stderr = channel.makefile_stderr('rb').read()

    channel.close()

    #return exit_status, stdout, stderr
    return exit_status

def ssh_connect_scp(hostname, username, port, key=None):
    
    print 'Establishing SSH connection to:', hostname, port, '...'
    t = paramiko.Transport((hostname, port))
    t.start_client()

    agent_auth(t, username)

    if not t.is_authenticated():
        print 'RSA key auth failed! Trying password login...'
        t.connect(username=username, password=password, hostkey=hostkey)
    else:
        sftp = t.open_session()
    sftp = paramiko.SFTPClient.from_transport(t)

def ssh_connect(host, user, key=None):
    try:
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=host, username=user, key_filename=key)
        return ssh

    except Exception as e:
        print('Connection Failed')
        print(e)
