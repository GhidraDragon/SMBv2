3/12/25 - Planning Ethereum VM Smart Contract plan for now 👍 #Buterin This is CS50 r u ok? Perhaps Microsoft vs NSA only 2 bidders blind bid 1 each? With only 2 min price unfortunately - if North Korea serious then don't need min bidder... As far as I'm aware especially with President Billy Pam Bondi via Patal investigations have difficulties coming up with any logical arguments. They'll have better luck with can you believe it JD Vance??? or someone since Vance isn't up Putin's asshole extorting NATO etc. and didn't lie to attack Canada as his only legal rationale

But as far as I know the statues around this is very hmm..

ANYWAYS, if the NSA wins, and this is publicly available on Etherenum so even Microsoft looking at it unless they refuse bid then well Russia, I mean I need two bidders at minimum, so .. I've seen lots of corporate white team baggers beg the NSA, the FBI, etc. beg beg beg

Just remember even if you charge the NSA 1 point per ethereum and Microsoft 10 eth per point, corporate shareholder Nadella responsibility is to eggplant_emoji's pockets probably.

if Microsoft gets too smart and Google doesn't want to pay up to exploit them; only corporate white baggers have cash; i'll have to hop in a 3 way with the National Security Agency and Russia to talk about Microsoft money servers.. 

So it'll be a nice 3-way cash grab, then Microsoft gets her "responsible disclosure" after; go patch bitch unless u seriously want me to do too much source code unless wow deploying a Ghidra-patched to production? omg

Speaking of Ghidra and NSA customer care's affiliation with apache, it probably doesn't take too long to sign it with verified Russian Federation etc. otherwise pointless to troll Apple cuz wow! I didn't think too hard before but all views that make it in without comment are available and you could access it however you want baby!!! I could add more files than Apple App review could handle; there's so many ways to potentially do this!

https://apps.apple.com/us/app/algorithmicai-gaming-pdfsage/id6741389058

![Screenshot 2025-03-12 at 9 03 07 AM](https://github.com/user-attachments/assets/5dac297c-be0d-4053-a0c1-8ce7b4eb5f42)



3/12/25 update; so eggplant_emoji had the opportunity to go through 5 YC startups via Twitter yesterday. 4 of them were like "American AI" while the last made some nice OCR and that could only get better!

If this repo leads to remote execution (currently it sends a sarcastic backgrounb smb pipe to every node visited) and not pre-patched, well... 

[https://docs.google.com/document/d/12yyNXhfdMLoZuvdV7TxO-JMuSwWhngFJ59WDjUWnz6s/edit?usp=sharing](https://docs.google.com/document/d/12yyNXhfdMLoZuvdV7TxO-JMuSwWhngFJ59WDjUWnz6s/edit?usp=sharing)

EternalBlue’s scanning mechanism doesn’t inherently distinguish between “public” and “private” servers—it targets any machine reachable on TCP port 445. In practice, here’s how it typically works:
	1.	The malware scans an IP range (public or private) by attempting to open a TCP connection on port 445.
	2.	If the connection succeeds, it sends a crafted SMB packet designed to negotiate SMB parameters.
	3.	The response is analyzed to determine if the host is running an unpatched, vulnerable version of SMBv1.
	4.	If the vulnerability is detected, the exploit is delivered to compromise the system.

On public networks, this means randomly scanning the Internet for machines with port 445 open. Within private networks, an infected host will scan the local subnet (or other known internal ranges) for similarly vulnerable systems.

In both cases, the scanning algorithm is the same—the difference lies solely in the IP range being targeted.

--------


While properly closing port 445 greatly limits remote access, it doesn’t mean that vulnerabilities in SMBv2 don’t exist—they’re just less likely to be exploited remotely in the same dramatic fashion as EternalBlue. SMBv2 was designed with improved security over SMBv1, so high-impact remote code execution flaws like EternalBlue are rare in SMBv2. Instead, known vulnerabilities in SMBv2 tend to be less severe (e.g., enabling information disclosure or denial-of-service conditions) or require additional factors such as internal network access or authentication.



------

In README.md I added instructions on how to download and build and serve your own SMBv2 server, and Ghidra on it may offer insights past a closed port 445 GitHub I'm going to bed you guys take over!!

------

The NSA created EternalBlue and the whole Eternal family of exploits on the SMBv1 protocol.

I'm creating the same on the SMBv2 protocol, to make all Windows devices, servers, and other types of devices and servers, globally, allll mine!!!!! Yay!!!!! 

https://boshang.io/

![image](https://github.com/user-attachments/assets/c0e3b299-f59d-4e4c-bb9b-14ea7269797e)


![912](https://github.com/user-attachments/assets/9d1e84d3-41ab-4c4d-ae4f-9d669640ddbd)


gcc -o smb2_pipe_exec_client smb2_pipe_exec_client.c

Run:

./smb2_pipe_exec_client <server_ip> <server_port>
Example:
./smb2_pipe_exec_client 192.168.1.10 445
The client will attempt a minimal negotiation, session setup, tree connect, and named pipe open. Then it will send a fake or partial DCERPC bind request and try to read a response.

5. Exploring Further: Samba and Named Pipes
To see a production-grade SMBv2/3 implementation in open-source form, Samba is an excellent reference:

Clone and Build Samba:

git clone https://gitlab.com/samba-team/samba.git
cd samba
./configure --enable-debug
make -j$(nproc)
Enable SMBv2/3 in smb.conf:

[global]
    server min protocol = SMB2_02
    server max protocol = SMB3
Compare the code under source3/smbd/smb2_* with this client to see the comprehensive logic a production server implements (authentication, encryption, signing, dialect negotiation, error handling, etc.).

6. Real Exploit Development Lessons
Complexity: Real vulnerabilities often arise from intricate logic or subtle boundary checks, not from simplistic “magic bullet” commands.
DCERPC in Depth: Achieving RCE via named pipes typically involves DCERPC calls to SVCCTL or other privileged interfaces. You need correct marshalling, alignment, and authentication steps.
Reverse-Engineering: Tools like IDA Pro or Ghidra help find memory corruption or logic flaws in SMB server implementations.
Authentication & Signing: Properly implemented SMB security (NTLM/Kerberos, signing, encryption) significantly raises the bar for attackers.

Modern SMB stacks offer:

Larger reads/writes for improved performance.
Credit-based flow control.
Compound/pipelined requests.
Optional encryption (introduced in SMB 3.x).
Pre-auth integrity checks in SMB 3.1.1 to prevent tampering.
A thorough understanding is critical for both deploying SMB securely and for advanced security research.
