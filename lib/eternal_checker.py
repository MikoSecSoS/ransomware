from lib.mysmb import MYSMB
from impacket import smb, smbconnection, nt_errors
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.rpcrt import DCERPCException
from struct import pack
import sys
import argparse


'''
Script for
- check target if MS17-010 is patched or not.
- find accessible named pipe
'''


def check_ms17_010(conn):
    TRANS_PEEK_NMPIPE = 0x23
    recvPkt = conn.send_trans(pack('<H', TRANS_PEEK_NMPIPE), maxParameterCount=0xffff, maxDataCount=0x800)
    status = recvPkt.getNTStatus()
    if status == 0xC0000205:  # STATUS_INSUFF_SERVER_RESOURCES
        print('[!] The target is not patched')
        return 1
    else:
        print('[-] The target is patched')
        return 0

def check_accessible_pipes(conn):
    print('=== Testing named pipes ===')
    conn.find_named_pipe(firstOnly=False)

def checker(target, port=445):

    import re
    domain, username, password, remoteName = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(target).groups('')

    #In case the password contains '@'
    if '@' in remoteName:
        password = password + '@' + remoteName.rpartition('@')[0]
        remoteName = remoteName.rpartition('@')[2]

    if domain is None:
        domain = ''

    if password == '' and username != '':
        from getpass import getpass
        password = getpass("Password:")

    target_ip = remoteName

    conn = MYSMB(target_ip, int(port))
    try:
        conn.login(username, password)
    except smb.SessionError as e:
        print('[-] Login failed: ' + nt_errors.ERROR_MESSAGES[e.error_code][0])
        return 0
    finally:
        print('[*] Target OS: ' + conn.get_server_os())

    tid = conn.tree_connect_andx('\\\\'+target_ip+'\\'+'IPC$')
    conn.set_default_tid(tid)

    out = check_ms17_010(conn)
    check_accessible_pipes(conn)

    conn.disconnect_tree(tid)
    conn.logoff()
    conn.get_socket().close()

    print('[*] Done')

    if out:
        return 1