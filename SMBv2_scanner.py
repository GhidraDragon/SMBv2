import sys
import socket
import ipaddress

def check_smb2(ip, port=445, timeout=2):
    pkt = (
        b"\x00\x00\x00\x62"      
        b"\xfeSMB"
        b"\x40\x00"
        b"\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x01\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00"*16
        b"\x24\x00"
        b"\x03\x00"
        b"\x01\x00"
        b"\x00\x00"
        b"\x7f\x00\x00\x00"
        b"\x11\x22\x33\x44\x55\x66\x77\x88"
        b"\x00\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x02\x02"
        b"\x10\x02"
        b"\x00\x03"
    )
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((str(ip), port))
        s.sendall(pkt)
        resp = s.recv(1024)
        s.close()
        if len(resp) >= 4 and resp[0:4] == b"\xfeSMB":
            return True
    except:
        pass
    return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 smb2_scanner.py <CIDR or single-IP>")
        sys.exit(1)

    net = ipaddress.ip_network(sys.argv[1], strict=False)
    print("Scanning for hosts with SMBv2 open. This may take a while...")
    for host in net.hosts():
        if check_smb2(host):
            print(f"{host} has SMBv2 open. Run: ./smb2_pipe_exec_client {host} 445")
    print("Scan complete.")