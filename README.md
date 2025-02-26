Below is the **complete** README with the final section’s heading changed to "**Still Not a Production/Exploit-Ready Tool**." Everything else is kept exactly as in the original text (including all code and explanatory sections) so you have a precise, updated document.

---

# SMBv2 Named Pipe Client & Lessons in Protocol-Level Development

Welcome! This repository now contains an improved demonstration client (`smb2_pipe_exec_client.c`) that showcases how one might connect to an SMBv2/SMB3 server (over TCP 445), perform essential SMB2 handshake steps (negotiate, session setup, tree connect), open a named pipe (e.g., `\\PIPE\\svcctl`), send rudimentary DCERPC bind stubs, and close the pipe. Although improved, it still does not implement real authentication or full DCERPC-based remote service creation/management logic. This remains primarily an educational code sample, intended to illustrate how raw SMBv2 named pipe communication and partial RPC stubbing might work.

> **Disclaimer**: This repository is not a complete exploit-development kit. It is not a production-ready tool. It does not fully parse or marshal real DCERPC data, sign sessions, or authenticate securely. If you are exploring how advanced Windows or Samba-based RCE might be achieved, consider this only a starting point for learning the wire protocol—not a final or polished solution.

## Table of Contents

1. [Purpose & Context](#purpose--context)  
2. [Big Picture: SMBv2/3 and Real-World Exploits](#big-picture-smbv23-and-real-world-exploits)  
3. [About smb2_pipe_exec_client.c](#about-smb2_pipe_exec_clientc)  
   1. [Workflow Overview](#workflow-overview)  
   2. [Capabilities & Limitations](#capabilities--limitations)  
   3. [Security Warnings](#security-warnings)  
4. [Building & Running the Client](#building--running-the-client)  
5. [Exploring Further: Samba and Named Pipes](#exploring-further-samba-and-named-pipes)  
6. [Real Exploit Development Lessons](#real-exploit-development-lessons)  
7. [Overview of SMBv2/3 Capabilities](#overview-of-smbv23-capabilities)  
8. [Full Source Code](#full-source-code)  
9. [Still Not a Production/Exploit-Ready Tool](#still-not-a-productionexploit-ready-tool)

---

<a name="purpose--context"></a>
## 1. Purpose & Context

### Why this code?

This example demonstrates how to initiate and maintain a client-side SMB2 session with a server (Windows or Samba) and how to open a named pipe (like the Windows Service Control Manager pipe `\\PIPE\\svcctl`). In more advanced usage, sending specially crafted DCERPC packets to the Service Control Manager can lead to remote service creation and execution. However, the code here does not fully implement the necessary DCERPC logic—this is left as an exercise for security researchers who want to explore deeper protocol-level details.

### Who should read this?

- Security researchers learning the fundamentals of Windows networking and SMBv2/SMB3 at the packet level.  
- Developers who need an introduction to raw SMB pipe-based communication and (partial) DCERPC stubs.  
- Anyone curious about how real exploits (like EternalBlue) might build upon low-level SMB communication.

> **Note**: No zero-day or unpatched vulnerability is presented here. This is purely educational.

---

<a name="big-picture-smbv23-and-real-world-exploits"></a>
## 2. Big Picture: SMBv2/3 and Real-World Exploits
- **SMBv2/3** drastically improves performance and security over older SMBv1. It adds message signing, encryption, and robust flow-control.  
- **Named Pipes** over SMB are a common Microsoft RPC transport, used for administrative tasks (service management, registry edits, etc.).  
- **Real exploit development** often involves more complex vulnerabilities, like memory corruption (e.g., EternalBlue) or logical flaws in how servers handle requests. Modern SMB stacks (including Samba’s) are significantly more hardened than they once were.

---

<a name="about-smb2_pipe_exec_clientc"></a>
## 3. About smb2_pipe_exec_client.c

<a name="workflow-overview"></a>
### 3.1 Workflow Overview

1. **Socket Connection** to the target server on TCP port 445.  
2. **SMB2 Negotiate**: Dialect negotiation (e.g., 0x0202, 0x0210, 0x0300).  
3. **SMB2 Session Setup**: Minimal handshake (in real life, this involves NTLM or Kerberos).  
4. **SMB2 Tree Connect** to `\\<server>\IPC$`.  
5. **SMB2 Create**: Open a named pipe (e.g., `\\PIPE\\svcctl`).  
6. **(Optional) DCERPC Bind**: A partial demonstration of sending a DCERPC bind request to the SVCCTL interface (though incomplete).  
7. **SMB2 Write/Read**: Exchange data with the pipe.  
8. **SMB2 Close**: Properly close the pipe/file handle.

<a name="capabilities--limitations"></a>
### 3.2 Capabilities & Limitations

**Capabilities**:
- Demonstrates minimal usage of SMB2 headers to do open/read/write on a named pipe.  
- Includes additional sample code stubbing out a DCERPC bind call.  
- Properly closes the pipe with an SMB2 Close, cleaning up the handle.

**Limitations**:
- **No real authentication**: The code doesn’t do a legitimate NTLM/Kerberos handshake.  
- **No signing or encryption**: Production SMB sessions often require signing or encryption for security.  
- **No full DCERPC**: This only includes a placeholder bind stub for demonstration. Real SVCCTL calls require additional IDL-based marshalling, which is non-trivial.  
- **Minimal error handling** for complex corner cases.

<a name="security-warnings"></a>
### 3.3 Security Warnings

1. **Incomplete Auth**: Do not assume this code can safely authenticate to real environments—it’s purely a “stub.”  
2. **RPC Stubs**: Real DCERPC requires IDL definitions, alignment rules, etc. The demonstration is incomplete and should not be used for production.  
3. **Ethical Use**: Only run code like this in lab/test networks where you have full permission. Unauthorized usage, especially if combined with real DCERPC exploit logic, can be illegal and unethical.

---

<a name="building--running-the-client"></a>
## 4. Building & Running the Client

The following steps apply to Linux-like environments with a C toolchain:

1. **Install Dependencies** (e.g., on Ubuntu/Debian):
   ```bash
   sudo apt-get update
   sudo apt-get install -y build-essential
   ```

2. **Compile**:
   ```bash
   gcc -o smb2_pipe_exec_client smb2_pipe_exec_client.c
   ```

3. **Run**:
   ```bash
   ./smb2_pipe_exec_client <server_ip> <server_port>
   ```
   - Example:
     ```bash
     ./smb2_pipe_exec_client 192.168.1.10 445
     ```
   - The client will attempt a minimal negotiation, session setup, tree connect, and named pipe open. Then it will send a fake or partial DCERPC bind request and try to read a response.

---

<a name="exploring-further-samba-and-named-pipes"></a>
## 5. Exploring Further: Samba and Named Pipes

To see a production-grade SMBv2/3 implementation in open-source form, **Samba** is an excellent reference:

1. **Clone and Build Samba**:
   ```bash
   git clone https://gitlab.com/samba-team/samba.git
   cd samba
   ./configure --enable-debug
   make -j$(nproc)
   ```

2. **Enable SMBv2/3 in smb.conf**:
   ```ini
   [global]
       server min protocol = SMB2_02
       server max protocol = SMB3
   ```

3. **Compare** the code under `source3/smbd/smb2_*` with this client to see the comprehensive logic a production server implements (authentication, encryption, signing, dialect negotiation, error handling, etc.).

---

<a name="real-exploit-development-lessons"></a>
## 6. Real Exploit Development Lessons

1. **Complexity**: Real vulnerabilities often arise from intricate logic or subtle boundary checks, not from simplistic “magic bullet” commands.  
2. **DCERPC in Depth**: Achieving RCE via named pipes typically involves DCERPC calls to SVCCTL or other privileged interfaces. You need correct marshalling, alignment, and authentication steps.  
3. **Reverse-Engineering**: Tools like IDA Pro or Ghidra help find memory corruption or logic flaws in SMB server implementations.  
4. **Authentication & Signing**: Properly implemented SMB security (NTLM/Kerberos, signing, encryption) significantly raises the bar for attackers.

---

<a name="overview-of-smbv23-capabilities"></a>
## 7. Overview of SMBv2/3 Capabilities

Modern SMB stacks offer:  
- Larger reads/writes for improved performance.  
- Credit-based flow control.  
- Compound/pipelined requests.  
- Optional encryption (introduced in SMB 3.x).  
- Pre-auth integrity checks in SMB 3.1.1 to prevent tampering.

A thorough understanding is critical for both deploying SMB securely and for advanced security research.

---

<a name="full-source-code"></a>
## 8. Full Source Code

Below is the complete `smb2_pipe_exec_client.c` including unchanged parts, plus improvements such as a partial DCERPC bind request demonstration and a SMB2 Close command. This is still not production-ready or a full exploit kit.

<details>
<summary>Click to expand the entire code</summary>

```c
/***************************************************
* File: smb2_pipe_exec_client.c
*
* Demonstrates:
*   1. Connecting to an SMB2/3 server (TCP 445).
*   2. Negotiate, Session Setup, Tree Connect to IPC$.
*   3. Create/open the named pipe "\\PIPE\\svcctl".
*   4. Partially demonstrate sending a DCERPC bind
*      request to the SVCCTL interface (stub only).
*   5. Read back any server response.
*   6. Close the pipe with an SMB2 Close.
*
* Security & Production Warnings:
*   - This remains incomplete demonstration code:
*     - No real auth or signing.
*     - No real DCERPC parse/marshalling logic.
*     - Minimal error handling and no encryption.
*   - Use only in a controlled environment with
*     permission!
***************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <errno.h>

#pragma pack(push, 1)

//--------------------------------------------------
//                  SMB2 Header
//--------------------------------------------------
typedef struct _SMB2Header {
    unsigned char  ProtocolId[4];  // 0xFE 'S' 'M' 'B'
    uint16_t       StructureSize;  // Always 64 for SMB2
    uint16_t       CreditCharge;   // Credits requested/charged
    uint32_t       Status;         // For responses, server sets status
    uint16_t       Command;        // SMB2 command code
    uint16_t       Credits;        // Credits granted/requested
    uint32_t       Flags;          // SMB2 header flags
    uint32_t       NextCommand;    // Offset to next command in compound
    uint64_t       MessageId;      // Unique message ID
    uint32_t       Reserved;       // Usually 0
    uint32_t       TreeId;         // Tree ID
    uint64_t       SessionId;      // Session ID
    unsigned char  Signature[16];  // For signing (unused here)
} SMB2Header;

// SMB2 Commands
#define SMB2_NEGOTIATE       0x0000
#define SMB2_SESSION_SETUP   0x0001
#define SMB2_TREE_CONNECT    0x0003
#define SMB2_CREATE          0x0005
#define SMB2_CLOSE           0x0006
#define SMB2_READ            0x0008
#define SMB2_WRITE           0x0009

// SMB2 Status Codes (common)
#define STATUS_SUCCESS                0x00000000
#define STATUS_INVALID_PARAMETER      0xC000000D
#define STATUS_ACCESS_DENIED          0xC0000022
#define STATUS_NOT_SUPPORTED          0xC00000BB

// SMB2 Dialects
#define SMB2_DIALECT_0202    0x0202
#define SMB2_DIALECT_0210    0x0210
#define SMB2_DIALECT_0300    0x0300

//--------------------------------------------------
//     Minimal Structures for Basic SMB2 Ops
//--------------------------------------------------

/* SMB2 NEGOTIATE */
typedef struct _SMB2NegotiateRequest {
    uint16_t StructureSize;  // Must be 36
    uint16_t DialectCount;
    uint16_t SecurityMode;
    uint16_t Reserved;
    uint32_t Capabilities;
    uint64_t ClientGuid;     // Simplified to 8 bytes for demonstration
    uint32_t NegotiateContextOffset;
    uint16_t NegotiateContextCount;
    uint16_t Reserved2;
    // Then dialect array
} SMB2NegotiateRequest;

typedef struct _SMB2NegotiateResponse {
    uint16_t StructureSize;   // Must be 65 in real SMB2
    uint16_t SecurityMode;
    uint16_t DialectRevision;
    uint16_t NegotiateContextCount;
    uint32_t ServerGuid;      // Simplified
    uint32_t Capabilities;
    uint32_t MaxTransSize;
    uint32_t MaxReadSize;
    uint32_t MaxWriteSize;
    uint64_t SystemTime;
    uint64_t ServerStartTime;
    // etc...
} SMB2NegotiateResponse;

/* SMB2 SESSION_SETUP */
typedef struct _SMB2SessionSetupRequest {
    uint16_t StructureSize;  // Must be 25
    uint8_t  Flags;
    uint8_t  SecurityMode;
    uint32_t Capabilities;
    uint32_t Channel;
    uint16_t SecurityBufferOffset;
    uint16_t SecurityBufferLength;
    // Security buffer follows...
} SMB2SessionSetupRequest;

typedef struct _SMB2SessionSetupResponse {
    uint16_t StructureSize;  // Must be 9
    uint16_t SessionFlags;
    uint16_t SecurityBufferOffset;
    uint16_t SecurityBufferLength;
    // ...
} SMB2SessionSetupResponse;

/* SMB2 TREE_CONNECT */
typedef struct _SMB2TreeConnectRequest {
    uint16_t StructureSize;  // Must be 9
    uint16_t Reserved;
    uint32_t PathOffset;
    uint32_t PathLength;
    // Path follows
} SMB2TreeConnectRequest;

typedef struct _SMB2TreeConnectResponse {
    uint16_t StructureSize;  // Must be 16
    uint8_t  ShareType;
    uint8_t  Reserved;
    uint32_t ShareFlags;
    uint32_t Capabilities;
    uint32_t MaximalAccess;
} SMB2TreeConnectResponse;

/* SMB2 CREATE */
typedef struct _SMB2CreateRequest {
    uint16_t StructureSize;     // Must be 57
    uint8_t  SecurityFlags;
    uint8_t  RequestedOplockLevel;
    uint32_t ImpersonationLevel;
    uint64_t SmbCreateFlags;
    uint64_t Reserved;
    uint32_t DesiredAccess;
    uint32_t FileAttributes;
    uint32_t ShareAccess;
    uint32_t CreateDisposition;
    uint32_t CreateOptions;
    uint16_t NameOffset;
    uint16_t NameLength;
    uint32_t CreateContextsOffset;
    uint32_t CreateContextsLength;
    // Filename follows...
} SMB2CreateRequest;

typedef struct _SMB2CreateResponse {
    uint16_t StructureSize; // Must be 89
    uint8_t  OplockLevel;
    uint8_t  Flags;
    uint32_t CreateAction;
    uint64_t CreationTime;
    uint64_t LastAccessTime;
    uint64_t LastWriteTime;
    uint64_t ChangeTime;
    uint64_t AllocationSize;
    uint64_t EndofFile;
    uint32_t FileAttributes;
    // 16-byte FileId
    uint64_t FileIdPersistent;
    uint64_t FileIdVolatile;
    // optional create contexts
} SMB2CreateResponse;

/* SMB2 WRITE/READ (for the RPC data) */
typedef struct _SMB2WriteRequest {
    uint16_t StructureSize; // Must be 49
    uint16_t DataOffset;
    uint32_t Length;
    uint64_t Offset;
    uint64_t FileIdPersistent;
    uint64_t FileIdVolatile;
    uint32_t Channel;
    uint32_t RemainingBytes;
    uint16_t WriteChannelInfoOffset;
    uint16_t WriteChannelInfoLength;
    uint32_t Flags;
    // Then the data
} SMB2WriteRequest;

typedef struct _SMB2WriteResponse {
    uint16_t StructureSize; // Must be 17
    uint16_t Reserved;
    uint32_t Count;
    uint32_t Remaining;
    uint16_t WriteChannelInfoOffset;
    uint16_t WriteChannelInfoLength;
} SMB2WriteResponse;

typedef struct _SMB2ReadRequest {
    uint16_t StructureSize; // Must be 49
    uint8_t  Padding;
    uint8_t  Reserved;
    uint32_t Length;
    uint64_t Offset;
    uint64_t FileIdPersistent;
    uint64_t FileIdVolatile;
    uint32_t MinimumCount;
    uint32_t Channel;
    uint32_t RemainingBytes;
    uint16_t ReadChannelInfoOffset;
    uint16_t ReadChannelInfoLength;
} SMB2ReadRequest;

typedef struct _SMB2ReadResponse {
    uint16_t StructureSize; // Must be 17
    uint8_t  DataOffset;
    uint8_t  Reserved;
    uint32_t DataLength;
    uint32_t DataRemaining;
    uint32_t Reserved2;
    // data follows
} SMB2ReadResponse;

/* SMB2 CLOSE */
typedef struct _SMB2CloseRequest {
    uint16_t StructureSize; // Must be 24
    uint16_t Flags;
    uint32_t Reserved;
    uint64_t FileIdPersistent;
    uint64_t FileIdVolatile;
} SMB2CloseRequest;

typedef struct _SMB2CloseResponse {
    uint16_t StructureSize; // Must be 60
    uint16_t Flags;
    uint32_t Reserved;
    uint64_t CreationTime;
    uint64_t LastAccessTime;
    uint64_t LastWriteTime;
    uint64_t ChangeTime;
    uint64_t AllocationSize;
    uint64_t EndOfFile;
    uint32_t FileAttributes;
} SMB2CloseResponse;

#pragma pack(pop)

//--------------------------------------------------
//       Global State & Helper Functions
//--------------------------------------------------
static uint64_t gMessageId = 1;
static uint64_t gSessionId = 0;
static uint32_t gTreeId    = 0;
static int      gSock      = -1;

static uint64_t gPipeFidPersistent = 0;
static uint64_t gPipeFidVolatile   = 0;

/*
 * sendSMB2Request: send an SMB2 header + payload
 */
int sendSMB2Request(SMB2Header *hdr, const void *payload, size_t payloadLen) {
    ssize_t sent = send(gSock, hdr, sizeof(SMB2Header), 0);
    if (sent < 0) {
        perror("send header");
        return -1;
    }
    if (payload && payloadLen > 0) {
        sent = send(gSock, payload, payloadLen, 0);
        if (sent < 0) {
            perror("send payload");
            return -1;
        }
    }
    return 0;
}

/*
 * recvSMB2Response: recv an SMB2 header + payload
 */
int recvSMB2Response(SMB2Header *outHdr, void *outBuf, size_t bufSize, ssize_t *outPayloadLen) {
    ssize_t recvd = recv(gSock, outHdr, sizeof(SMB2Header), 0);
    if (recvd <= 0) {
        perror("recv SMB2 header");
        return -1;
    }
    if (recvd < (ssize_t)sizeof(SMB2Header)) {
        fprintf(stderr, "Incomplete SMB2 header.\n");
        return -1;
    }

    // Validate signature
    if (!(outHdr->ProtocolId[0] == 0xFE &&
          outHdr->ProtocolId[1] == 'S'  &&
          outHdr->ProtocolId[2] == 'M'  &&
          outHdr->ProtocolId[3] == 'B')) {
        fprintf(stderr, "Invalid SMB2 signature.\n");
        return -1;
    }

    // Non-blocking peek to see if there's more data
    int peekLen = recv(gSock, outBuf, bufSize, MSG_DONTWAIT);
    if (peekLen > 0) {
        int realLen = recv(gSock, outBuf, peekLen, 0);
        if (realLen < 0) {
            perror("recv payload");
            return -1;
        }
        *outPayloadLen = realLen;
    } else {
        *outPayloadLen = 0;
    }

    return 0;
}

/*
 * buildSMB2Header: fill out common fields
 */
void buildSMB2Header(uint16_t command, uint32_t treeId, uint64_t sessionId, SMB2Header *hdrOut) {
    memset(hdrOut, 0, sizeof(SMB2Header));
    hdrOut->ProtocolId[0] = 0xFE;
    hdrOut->ProtocolId[1] = 'S';
    hdrOut->ProtocolId[2] = 'M';
    hdrOut->ProtocolId[3] = 'B';
    hdrOut->StructureSize = 64;
    hdrOut->Command       = command;
    hdrOut->Credits       = 1;  // minimal
    hdrOut->MessageId     = gMessageId++;
    hdrOut->TreeId        = treeId;
    hdrOut->SessionId     = sessionId;
}

//--------------------------------------------------
// SMB2 NEGOTIATE
//--------------------------------------------------
int doNegotiate() {
    SMB2Header hdr;
    buildSMB2Header(SMB2_NEGOTIATE, 0, 0, &hdr);

    SMB2NegotiateRequest req;
    memset(&req, 0, sizeof(req));
    req.StructureSize = 36;
    req.DialectCount  = 3;
    uint16_t dialects[3] = {
        SMB2_DIALECT_0202,
        SMB2_DIALECT_0210,
        SMB2_DIALECT_0300
    };

    // Send header + negotiate request
    if (sendSMB2Request(&hdr, &req, sizeof(req)) < 0) return -1;
    // Followed by the dialect array
    if (send(gSock, dialects, sizeof(dialects), 0) < 0) {
        perror("send dialects");
        return -1;
    }

    // Receive
    SMB2Header respHdr;
    unsigned char buf[1024];
    ssize_t payloadLen;
    if (recvSMB2Response(&respHdr, buf, sizeof(buf), &payloadLen) < 0) return -1;

    if (respHdr.Status != STATUS_SUCCESS) {
        fprintf(stderr, "Negotiate failed, status=0x%08X\n", respHdr.Status);
        return -1;
    }
    printf("[Client] SMB2 NEGOTIATE OK. payloadLen=%zd\n", payloadLen);
    return 0;
}

//--------------------------------------------------
// SMB2 SESSION_SETUP (stub - no real authentication)
//--------------------------------------------------
int doSessionSetup() {
    SMB2Header hdr;
    buildSMB2Header(SMB2_SESSION_SETUP, 0, 0, &hdr);

    SMB2SessionSetupRequest ssreq;
    memset(&ssreq, 0, sizeof(ssreq));
    ssreq.StructureSize = 25;

    // In real usage, you'd set SecurityBufferOffset/Length and
    // provide an NTLM/Kerberos token. This is omitted here.

    if (sendSMB2Request(&hdr, &ssreq, sizeof(ssreq)) < 0) return -1;

    SMB2Header respHdr;
    unsigned char buf[1024];
    ssize_t payloadLen;
    if (recvSMB2Response(&respHdr, buf, sizeof(buf), &payloadLen) < 0) return -1;

    if (respHdr.Status != STATUS_SUCCESS) {
        fprintf(stderr, "SessionSetup failed, status=0x%08X\n", respHdr.Status);
        return -1;
    }

    gSessionId = respHdr.SessionId;
    printf("[Client] SMB2 SESSION_SETUP OK. SessionId=0x%llx\n",
           (unsigned long long)gSessionId);
    return 0;
}

//--------------------------------------------------
// SMB2 TREE_CONNECT to \\server\IPC$
//--------------------------------------------------
int doTreeConnect(const char *ipcPath) {
    SMB2Header hdr;
    buildSMB2Header(SMB2_TREE_CONNECT, 0, gSessionId, &hdr);

    SMB2TreeConnectRequest tcreq;
    memset(&tcreq, 0, sizeof(tcreq));
    tcreq.StructureSize = 9;
    tcreq.PathOffset    = sizeof(tcreq);

    uint32_t pathLen = (uint32_t)strlen(ipcPath);
    tcreq.PathLength  = pathLen;

    size_t reqSize = sizeof(tcreq) + pathLen;
    char *reqBuf = (char *)malloc(reqSize);
    if (!reqBuf) {
        fprintf(stderr, "malloc failed\n");
        return -1;
    }
    memcpy(reqBuf, &tcreq, sizeof(tcreq));
    memcpy(reqBuf + sizeof(tcreq), ipcPath, pathLen);

    if (sendSMB2Request(&hdr, reqBuf, reqSize) < 0) {
        free(reqBuf);
        return -1;
    }
    free(reqBuf);

    SMB2Header respHdr;
    unsigned char buf[1024];
    ssize_t payloadLen;
    if (recvSMB2Response(&respHdr, buf, sizeof(buf), &payloadLen) < 0) {
        return -1;
    }

    if (respHdr.Status != STATUS_SUCCESS) {
        fprintf(stderr, "TreeConnect to %s failed, status=0x%08X\n",
                ipcPath, respHdr.Status);
        return -1;
    }
    if (payloadLen < (ssize_t)sizeof(SMB2TreeConnectResponse)) {
        fprintf(stderr, "TreeConnect response too small\n");
        return -1;
    }

    gTreeId = respHdr.TreeId;
    printf("[Client] TREE_CONNECT to %s OK. TreeId=0x%08X\n", ipcPath, gTreeId);
    return 0;
}

//--------------------------------------------------
// SMB2 CREATE (Open named pipe, e.g. "\\PIPE\\svcctl")
//--------------------------------------------------
int doOpenPipe(const char *pipeName) {
    SMB2Header hdr;
    buildSMB2Header(SMB2_CREATE, gTreeId, gSessionId, &hdr);

    SMB2CreateRequest creq;
    memset(&creq, 0, sizeof(creq));
    creq.StructureSize        = 57;
    creq.RequestedOplockLevel = 0; // none
    creq.ImpersonationLevel   = 2; // SecurityImpersonation
    creq.DesiredAccess        = 0x001F01FF; // GENERIC_ALL (over-simplified)
    creq.ShareAccess          = 3; // read/write share
    creq.CreateDisposition    = 1; // FILE_OPEN
    creq.CreateOptions        = 0; 
    creq.NameOffset           = sizeof(SMB2CreateRequest);

    // Convert ASCII to a simple UTF-16LE
    uint32_t pipeNameLenBytes = (uint32_t)(strlen(pipeName) * 2);
    creq.NameLength = (uint16_t)pipeNameLenBytes;

    size_t totalSize = sizeof(creq) + pipeNameLenBytes;
    unsigned char *reqBuf = (unsigned char *)malloc(totalSize);
    if (!reqBuf) {
        fprintf(stderr, "malloc doOpenPipe failed\n");
        return -1;
    }
    memcpy(reqBuf, &creq, sizeof(creq));

    // ASCII -> UTF-16LE
    unsigned char *pName = reqBuf + sizeof(creq);
    for (size_t i = 0; i < strlen(pipeName); i++) {
        pName[i*2]   = (unsigned char)pipeName[i];
        pName[i*2+1] = 0x00;
    }

    if (sendSMB2Request(&hdr, reqBuf, totalSize) < 0) {
        free(reqBuf);
        return -1;
    }
    free(reqBuf);

    SMB2Header respHdr;
    unsigned char buf[1024];
    ssize_t payloadLen;
    if (recvSMB2Response(&respHdr, buf, sizeof(buf), &payloadLen) < 0) return -1;

    if (respHdr.Status != STATUS_SUCCESS) {
        fprintf(stderr, "OpenPipe '%s' failed, status=0x%08X\n",
                pipeName, respHdr.Status);
        return -1;
    }

    if (payloadLen < (ssize_t)sizeof(SMB2CreateResponse)) {
        fprintf(stderr, "CreateResponse too small.\n");
        return -1;
    }
    SMB2CreateResponse *cres = (SMB2CreateResponse *)buf;
    gPipeFidPersistent = cres->FileIdPersistent;
    gPipeFidVolatile   = cres->FileIdVolatile;

    printf("[Client] Named pipe '%s' opened OK. FID=(%llx:%llx)\n",
           pipeName,
           (unsigned long long)gPipeFidPersistent,
           (unsigned long long)gPipeFidVolatile);
    return 0;
}

//--------------------------------------------------
// doWritePipe: Send raw bytes into the named pipe
//--------------------------------------------------
int doWritePipe(const unsigned char *data, size_t dataLen) {
    SMB2Header hdr;
    buildSMB2Header(SMB2_WRITE, gTreeId, gSessionId, &hdr);

    SMB2WriteRequest wreq;
    memset(&wreq, 0, sizeof(wreq));
    wreq.StructureSize      = 49;
    wreq.DataOffset         = sizeof(SMB2WriteRequest);
    wreq.Length             = (uint32_t)dataLen;
    wreq.FileIdPersistent   = gPipeFidPersistent;
    wreq.FileIdVolatile     = gPipeFidVolatile;

    size_t totalSize = sizeof(wreq) + dataLen;
    unsigned char *reqBuf = (unsigned char*)malloc(totalSize);
    if (!reqBuf) {
        fprintf(stderr, "malloc doWritePipe failed\n");
        return -1;
    }
    memcpy(reqBuf, &wreq, sizeof(wreq));
    memcpy(reqBuf + sizeof(wreq), data, dataLen);

    if (sendSMB2Request(&hdr, reqBuf, totalSize) < 0) {
        free(reqBuf);
        return -1;
    }
    free(reqBuf);

    // read response
    SMB2Header respHdr;
    unsigned char buf[512];
    ssize_t payloadLen;
    if (recvSMB2Response(&respHdr, buf, sizeof(buf), &payloadLen) < 0) return -1;

    if (respHdr.Status != STATUS_SUCCESS) {
        fprintf(stderr, "WritePipe failed, status=0x%08X\n", respHdr.Status);
        return -1;
    }
    if (payloadLen < (ssize_t)sizeof(SMB2WriteResponse)) {
        fprintf(stderr, "WriteResponse too small\n");
        return -1;
    }
    SMB2WriteResponse *wres = (SMB2WriteResponse *)buf;
    printf("[Client] Wrote %u bytes to pipe.\n", wres->Count);
    return 0;
}

//--------------------------------------------------
// doReadPipe: read back from the pipe
//--------------------------------------------------
int doReadPipe(unsigned char *outBuf, size_t outBufSize, uint32_t *outBytesRead) {
    SMB2Header hdr;
    buildSMB2Header(SMB2_READ, gTreeId, gSessionId, &hdr);

    SMB2ReadRequest rreq;
    memset(&rreq, 0, sizeof(rreq));
    rreq.StructureSize     = 49;
    rreq.Length            = (uint32_t)outBufSize;
    rreq.FileIdPersistent  = gPipeFidPersistent;
    rreq.FileIdVolatile    = gPipeFidVolatile;

    if (sendSMB2Request(&hdr, &rreq, sizeof(rreq)) < 0) return -1;

    SMB2Header respHdr;
    unsigned char buf[2048];
    ssize_t payloadLen;
    if (recvSMB2Response(&respHdr, buf, sizeof(buf), &payloadLen) < 0) return -1;

    if (respHdr.Status != STATUS_SUCCESS) {
        fprintf(stderr, "ReadPipe failed, status=0x%08X\n", respHdr.Status);
        return -1;
    }
    if (payloadLen < (ssize_t)sizeof(SMB2ReadResponse)) {
        fprintf(stderr, "ReadResponse too small\n");
        return -1;
    }
    SMB2ReadResponse *rres = (SMB2ReadResponse *)buf;

    uint32_t dataLen = rres->DataLength;
    if (dataLen > 0) {
        uint8_t *dataStart = buf + rres->DataOffset;
        // Check for bounds
        if (rres->DataOffset + dataLen <= (uint32_t)payloadLen) {
            if (dataLen > outBufSize) {
                dataLen = (uint32_t)outBufSize; // Truncate
            }
            memcpy(outBuf, dataStart, dataLen);
        } else {
            fprintf(stderr, "Data offset/length out of payload bounds!\n");
            return -1;
        }
    }
    *outBytesRead = dataLen;
    printf("[Client] Read %u bytes from pipe.\n", dataLen);

    return 0;
}

//--------------------------------------------------
// doDCERPCBind: a partial DCERPC bind request to SVCCTL
//--------------------------------------------------
int doDCERPCBind() {
    // A typical DCERPC bind to SVCCTL might include:
    //   - Version/PacketType
    //   - Interface UUID
    //   - Transfer syntax, etc.
    // This is an oversimplified placeholder.
    unsigned char dcerpcBindStub[] = {
        0x05, 0x00, // RPC version
        0x0B,       // bind PDU type
        0x10,       // flags (little-endian)
        0x00, 0x00, 0x00, 0x00, // DCE call ID (placeholder)
        // [Interface UUID + version], [transfer syntax], etc...
        // This is incomplete for a real DCERPC bind!
    };

    printf("[Client] Sending partial DCERPC bind stub...\n");
    return doWritePipe(dcerpcBindStub, sizeof(dcerpcBindStub));
}

//--------------------------------------------------
// doClosePipe: SMB2 Close for the named pipe handle
//--------------------------------------------------
int doClosePipe() {
    SMB2Header hdr;
    buildSMB2Header(SMB2_CLOSE, gTreeId, gSessionId, &hdr);

    SMB2CloseRequest creq;
    memset(&creq, 0, sizeof(creq));
    creq.StructureSize     = 24;
    creq.Flags             = 0; // 0 or 1 for POSTQUERY_ATTR
    creq.FileIdPersistent  = gPipeFidPersistent;
    creq.FileIdVolatile    = gPipeFidVolatile;

    if (sendSMB2Request(&hdr, &creq, sizeof(creq)) < 0) return -1;

    SMB2Header respHdr;
    unsigned char buf[512];
    ssize_t payloadLen;
    if (recvSMB2Response(&respHdr, buf, sizeof(buf), &payloadLen) < 0) {
        return -1;
    }

    if (respHdr.Status != STATUS_SUCCESS) {
        fprintf(stderr, "ClosePipe failed, status=0x%08X\n", respHdr.Status);
        return -1;
    }
    printf("[Client] SMB2 Close on pipe handle OK.\n");
    return 0;
}

//--------------------------------------------------
// main()
//--------------------------------------------------
int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <server_ip> <server_port>\n", argv[0]);
        fprintf(stderr, "Example: %s 192.168.1.10 445\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *serverIp = argv[1];
    int port = atoi(argv[2]);

    // 1. Create socket
    gSock = socket(AF_INET, SOCK_STREAM, 0);
    if (gSock < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    // 2. Connect
    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port   = htons(port);
    if (inet_pton(AF_INET, serverIp, &serverAddr.sin_addr) <= 0) {
        perror("inet_pton");
        close(gSock);
        return EXIT_FAILURE;
    }

    if (connect(gSock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("connect");
        close(gSock);
        return EXIT_FAILURE;
    }
    printf("[Client] Connected to %s:%d\n", serverIp, port);

    // 3. SMB2 NEGOTIATE
    if (doNegotiate() < 0) {
        close(gSock);
        return EXIT_FAILURE;
    }

    // 4. SMB2 SESSION_SETUP (stub)
    if (doSessionSetup() < 0) {
        close(gSock);
        return EXIT_FAILURE;
    }

    // 5. SMB2 TREE_CONNECT to IPC$
    // Construct a UNC path like "\\\\192.168.1.10\\IPC$"
    char ipcPath[256];
    snprintf(ipcPath, sizeof(ipcPath), "\\\\%s\\IPC$", serverIp);
    if (doTreeConnect(ipcPath) < 0) {
        close(gSock);
        return EXIT_FAILURE;
    }

    // 6. SMB2 CREATE for named pipe "\\PIPE\\svcctl"
    if (doOpenPipe("\\PIPE\\svcctl") < 0) {
        close(gSock);
        return EXIT_FAILURE;
    }

    // 7. (Optional) Send a partial DCERPC Bind
    if (doDCERPCBind() < 0) {
        // Not strictly fatal; you might decide to continue or bail out
        fprintf(stderr, "DCERPC bind stub failed.\n");
    }

    // 8. Attempt a read from the pipe (whatever the server might send back)
    unsigned char readBuf[512];
    memset(readBuf, 0, sizeof(readBuf));
    uint32_t bytesRead = 0;
    if (doReadPipe(readBuf, sizeof(readBuf), &bytesRead) < 0) {
        fprintf(stderr, "Read from pipe failed.\n");
    } else {
        if (bytesRead > 0) {
            printf("[Client] Pipe response (hex):\n");
            for (uint32_t i = 0; i < bytesRead; i++) {
                printf("%02X ", readBuf[i]);
            }
            printf("\n");
        } else {
            printf("[Client] No data returned from pipe.\n");
        }
    }

    // 9. Close the pipe handle
    if (doClosePipe() < 0) {
        fprintf(stderr, "Failed to close pipe properly.\n");
    }

    // 10. Done
    close(gSock);
    printf("[Client] Done.\n");
    return EXIT_SUCCESS;
}
```
</details>

---

<a name="still-not-a-productionexploit-ready-tool"></a>
## 9. Still Not a Production/Exploit-Ready Tool

1. **SMBv2/3** is a key protocol in modern Windows and Samba ecosystems—understanding its handshake, tree connect, and named-pipe semantics is essential for both legitimate development and advanced security research.  
2. The `smb2_pipe_exec_client.c` here illustrates minimal steps to negotiate, create a named pipe, (partially) bind DCERPC, and then close the handle.  
3. **Still Not a Production/Exploit-Ready Tool**: The advanced topics (NTLM/Kerberos, DCERPC marshalling, signing, encryption, error handling) are purposely not fully implemented.  
4. **Security Best Practices**: If you extend or adapt this code, do so in a lab environment with explicit authorization. Implement secure authentication, signing, and proper validation.  
5. **Ethical Use Only**: Always comply with relevant laws and get permission before running code that interacts with others’ networks or hosts.

Thank you for exploring SMBv2 named pipe fundamentals! For more in-depth references, consult:

- Microsoft’s official protocol documentation (MS-SMB2, MS-RPC, MS-SVCCTL, etc.).  
- The Samba source for a robust open-source implementation.

Stay safe, and happy researching!


![cat-asvab](https://github.com/user-attachments/assets/5944caf1-7292-48ee-8540-d0904f258f18)

