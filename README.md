# SMB Enumeration Tool


This tool is an SMB enumeration tool that connects to a target host, lists available SMB shares, and tests actual access rather than relying on claimed permissions by the server. By default it uses a null session (anonymous authentication) and determines read/write access by attempting real operations against each discovered share.

## Usage


```bash
python3 smb_enum.py -h
python3 smb_enum.py [target_ip]   # null session (default)
python3 smb_enum.py [target_ip] -u [USERNAME] -p [PASSWORD]  # with credentials
```

## Example Output

Run against a Metasploitable target with credentials:
```
$ python3 smb_enum.py 192.168.15.130 -u msfadmin -p msfadmin
{'print$': {'type': 'admin', 'read': 'READ', 'write': 'UNWRITABLE'},
 'tmp': {'type': 'normal', 'read': 'READ', 'write': 'WRITE'},
 'opt': {'type': 'normal', 'read': 'READ', 'write': 'UNWRITABLE'},
 'ADMIN$': {'type': 'admin', 'read': 'ACCESS DENIED', 'write': 'UNWRITABLE'},
 'msfadmin': {'type': 'normal', 'read': 'READ', 'write': 'WRITE'}}
 ```
Running the same target without credentials returns ACCESS DENIED on print$ and opt, and the msfadmin share does not appear. This shows that the tool reflects the actual access of the current session, not the permissions the server advertises.

## How it works


The tool speaks SMB directly through impacket rather than running smbclient/nxc and parsing their printed output. Parsing another tool's text is fragile; if that tool changes its output format, the parser breaks. It also means only understanding how to read a tool's output, not the SMB protocol itself.

## How Access Is Tested

1) This tool determines access by testing, not by trusting what the server advertises. Because a server can claim a share is restricted but still let an anonymous session in through misconfiguration.
   
2) Write detection: The tool tests write access by creating a uniquely-named file on the share. If the file is created successfully, the share is writable.
   - A new file has no per-file permissions of its own, so whether it can be created depends only on the share's write permission giving a clean answer about the share itself.
   - On success, the tool deletes the test file as cleanup.
   - The tool does not attempt to remove the log, because removing logs is a post exploitation cleanup (out of scope of this tool).

3) IPC$ is skipped. Admin shares (C$, ADMIN$, print$) are tested and flagged as default admin shares.

4) When the target is unreachable, refuses the connection, or is given an invalid address, the tool prints a single clear error message and exits with code 1.

5) A connection timeout prevents the tool from hanging indefinitely on a host that does not respond.

## Limitations


- The tool can see files, but doesn't download them.
- No RPC, it only does SMB file share operations.
- Reports what the current session can access only.
- Failure to access a share doesn't prove the share doesn't exist.
- Read access is tested at the share's root level only. A share could deny access at root but permit it in a subfolder.
