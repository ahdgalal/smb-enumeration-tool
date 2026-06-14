from impacket.smbconnection import SMBConnection
from impacket.smbconnection import SessionError
from impacket import nt_errors
from io import BytesIO
import os
import sys
import argparse

def smbconnect(conn, username='', password=''):
    conn.login(username, password)
    shares = conn.listShares()
    sh=[]
    for share in shares:
        sh.append(share['shi1_netname'].rstrip('\x00'))
    return sh

def smbaccess(conn, username='', password='', verbose=False):
    access = {}
    shares = smbconnect(conn, username, password)
    for share in shares:
        if share == "IPC$":
            continue

        tag = 'admin' if share in ("C$", "ADMIN$") else 'normal'

        ## Read
        read_result = "UNDETERMINED"
        try:
                conn.listPath(share, "*")
                read_result = 'READ'   
        except SessionError as e:
                if verbose:
                    print(f"DEBUG: {share} failed: {e}")
                if e.getErrorCode() == nt_errors.STATUS_NO_SUCH_FILE:  
                    read_result = 'READ'
                elif e.getErrorCode() in (nt_errors.STATUS_ACCESS_DENIED, nt_errors.STATUS_NETWORK_ACCESS_DENIED):
                    read_result  = 'ACCESS DENIED'
                else:
                    read_result = 'ERROR'
        except Exception as e:
                if verbose:
                    print(f"DEBUG: {share} failed: {e}")

        ## Write
        write_result = 'UNDETERMINED'
        if tag == 'admin':
            write_result = 'SKIPPED'
        else:
            try:
                unique_name = f"rwtest_{os.getpid()}.txt"
                data = BytesIO(b"test")
                conn.putFile(share, unique_name, data.read)
                write_result = 'WRITE'
            except SessionError as e:
                if verbose:
                        print(f"DEBUG: {share} failed: {e}")
                if e.getErrorCode() in (nt_errors.STATUS_ACCESS_DENIED, nt_errors.STATUS_NETWORK_ACCESS_DENIED):
                        write_result  = 'UNWRITABLE'
                elif e.getErrorCode() == nt_errors.STATUS_OBJECT_NAME_NOT_FOUND:
                    write_result = 'UNDETERMINED'        
                else:
                        write_result = 'ERROR'
            except Exception:
                write_result = 'ERROR'
            finally:
                if write_result == "WRITE":
                    try:
                        conn.deleteFile(share, unique_name)
                    except Exception as e:
                        print(f"CLEANUP FAILED on {share}: {unique_name} left behind  undeleted — {e}")
                        write_result = 'WRITE (CLEANUP FAILED)'
        access[share] = {'type': tag, 'read': read_result, 'write': write_result} 
                
    return access

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("-u", "--username", default="", help="SMB username")
    parser.add_argument("-p", "--password", default="", help="SMB password")
    parser.add_argument("-v", "--verbose", action="store_true", help="show debug detail")

    args = parser.parse_args()

    try:
        conn = SMBConnection(args.target, args.target, timeout=10 )
    except OSError as e:
        print(f"FAILED on {args.target}: {e}")
        sys.exit(1)
    try:
        print(smbaccess(conn, args.username, args.password, args.verbose) )
    except SessionError as e:
        print(f"SMB ERROR: {e}")
        sys.exit(1)
         
if __name__ == "__main__":
	main()
