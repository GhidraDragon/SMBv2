#!/usr/bin/env python3

import sys
import socket
import subprocess

def smb2_scanner(target_ip, target_port=445):
    """
    Minimal SMBv2 scanner using a simple TCP connection test and
    a basic SMB2 negotiate request. 
    """
    # SMB2 negotiate protocol request (hard-coded for demonstration).
    # This packet checks if the server responds with SMB2 capabilities.
    # The packet below is a bare-bones example; real-world usage may require
    # more robust handling, retries, or library-based parsing (e.g. impacket).
    
    # Prebuilt SMB negotiate packet to test SMB2
    # (includes NetBIOS session service header + SMB2 header + negotiation data).
    # Dialects set to SMB2.0 (0x0202).
    smb2_negotiate_packet = (
        b"\x00"              # Session message type
        b"\x00\x00\x54"      # Length (0x54 = 84 bytes)
        b"\xfeSMB"           # SMB2 protocol identifier
        b"\x40\x00"          # Header length and 'credit charge'
        b"\x00\x00"          # Channel sequence/Reserved
        b"\x00\x00\x00\x00"  # Status
        b"\x01\x00"          # Command (negotiate)
        b"\x00\x00"          # Credits requested
        b"\x00\x00\x00\x00"  # Flags
        b"\x00\x00\x00\x00"  # Chain offset
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Session ID
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Signature
        b"\x24\x00"          # Structure size (36)
        b"\x01\x00"          # Dialect count (1)
        b"\x00\x00"          # Security mode
        b"\x00\x00"          # Reserved
        b"\x7f\x00\x00\x00"  # Capabilities
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # GUID
        b"\x02\x00"          # Negotiate context offset
        b"\x00\x00"          # Negotiate context count
        b"\x02\x02"          # Dialect: SMB 2.0 (0x0202)
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
    """
    Calls the external 'smb2_pipe_exec_client' program with the given IP and port.
    """
    try:
        print("[*] Running smb2_pipe_exec_client...")
        result = subprocess.run(["./smb2_pipe_exec_client", target_ip, str(target_port)])
        print(f"[*] smb2_pipe_exec_client returned with code: {result.returncode}")
    except FileNotFoundError:
        print("[-] Error: smb2_pipe_exec_client not found or not executable.")
    except Exception as e:
        print(f"[-] Error running smb2_pipe_exec_client -> {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_ip> [port]")
        sys.exit(1)

    ip = sys.argv[1]
    if len(sys.argv) == 3:
        port = int(sys.argv[2])
    else:
        port = 445

    print(f"[*] Scanning {ip}:{port} for SMBv2...")
    smb2_supported = smb2_scanner(ip, port)

    if smb2_supported:
        run_smb2_pipe_exec_client(ip, port)