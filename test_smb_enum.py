from unittest.mock import MagicMock
from impacket.smbconnection import SessionError
from smb_enum import smbaccess

def make_conn():
    conn = MagicMock()
    conn.login.return_value = None
    conn.listShares.return_value = [{'shi1_netname': 'SHARE\x00'}]
    return conn

def test_open_share():
    conn = make_conn()
    conn.listPath.return_value = []         # read succeeds = READ
    conn.putFile.return_value = None        # write succeeds = WRITE
    conn.deleteFile.return_value = None     # cleanup succeeds

    result = smbaccess(conn)
    print(result)

    assert result['SHARE']['read'] == 'READ'
    assert result['SHARE']['write'] == 'WRITE'
    print("PASS: open share -> READ + WRITE")

def test_denied_read():
    conn = make_conn()
    conn.listPath.side_effect = SessionError(error=0xc0000022) #read fails
    conn.putFile.return_value = None           
    conn.deleteFile.return_value = None     

    result = smbaccess(conn)
    print(result)

    assert result['SHARE']['read'] == 'ACCESS DENIED'
    assert result['SHARE']['write'] == 'WRITE'
    print("PASS: denied share -> ACCESS DENIED")

def test_denied_write():
    conn = make_conn()
    conn.listPath.return_value = []
    conn.putFile.side_effect = SessionError(error=0xc0000022)   # write fails
    conn.deleteFile.return_value = None  # cleanup succeeds

    result = smbaccess(conn)
    print(result)

    assert result['SHARE']['read'] == 'READ'
    assert result['SHARE']['write'] == 'UNWRITABLE'
    print("PASS: unwritable share -> WRITE DENIED")

def test_cleanup_fail():
    conn = make_conn()
    conn.listPath.return_value = []
    conn.putFile.return_value = None    # write succeed
    conn.deleteFile.side_effect = SessionError(error=0xc0000022)   # cleanup fails

    result = smbaccess(conn)
    print(result)

    assert result['SHARE']['read'] == 'READ'
    assert result['SHARE']['write'] == 'WRITE (CLEANUP FAILED)'
    print("PASS: writable share -> CLEANUP FAILED")

def test_ipc_skipped():
    conn = make_conn()
    conn.listShares.return_value = [{'shi1_netname': 'IPC$\x00'}]
    result = smbaccess(conn)
    assert 'IPC$' not in result
    print("PASS: IPC$ SKIPPED")

def main():
    test_open_share()
    test_denied_read()
    test_denied_write()
    test_cleanup_fail()
    test_ipc_skipped()

if __name__ == "__main__":
    main()