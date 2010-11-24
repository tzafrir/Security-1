#include <stdio.h>
#include "md5class.h"
#include <Winsock2.h>

// Need to link with Ws2_32.lib
// Instructions for Microsoft Visual Studio:
// 1. Go to "Project" menu, choose "SIMPLE_SERVER Properties"
// 2. Choose "Linker" category on left, then "Input" subcategory
// 3. Set "Additional Dependencies" field to "Ws2_32.lib"

#define DEFAULT_SERVER_PORT		13131
#define MAX_SHELLCOMMAND_LEN	1024
#define RECVBUF_LEN				4096
#define LOGIN_PROMPT			"password: "
#define STORED_HASHSTRING		"c34112aaabca311084b412f44aca5bee"


SOCKET g_newclient_socket;
void grant_access(void);
bool check_password_login(char *recvbuf);

int main(int argc, char **argv)
{
	// initialize Winsock
	WSADATA WSAData;
	SOCKADDR_IN sin;
	SOCKET sock;
	WSAStartup(MAKEWORD(2,0), &WSAData);
	sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons((u_short)DEFAULT_SERVER_PORT);
	printf("addr: %d\nport: %d\n", sin.sin_addr.s_addr, sin.sin_port);
	bind(sock, (SOCKADDR *)&sin, sizeof(SOCKADDR_IN));
	listen(sock, SOMAXCONN);

	// server loop
	while (true) {
		// wait for a new client
		SOCKET newclient_socket = accept(sock, 0, 0);
		printf("Accepted a connection!\n");
		// update global variable when client connects
		g_newclient_socket = newclient_socket;

		for (int i=0; i<100; i++) {
			printf("");
			//No references from previous semester!
		}
				
		// send a login prompt to the client
		send(newclient_socket, LOGIN_PROMPT, sizeof(LOGIN_PROMPT)/sizeof(char)-1, 0);
		printf("LOG: sent login prompt\n");

		// obtain the password from the client
		char recvbuf[RECVBUF_LEN];
		int bytes_received = recv(newclient_socket, recvbuf, RECVBUF_LEN, 0);
//		recvbuf[bytes_received] = '\0';
		printf("LOG: received password\n");

		// check client's password
		bool authenticated = check_password_login(recvbuf);

		if (authenticated) {			
			// authenticated --> log event & grant shell
			printf("LOG: valid password, access granted\n");
			send(g_newclient_socket, "succ", 5, 0);
			grant_access();			
		} else {
			// unauthenticated --> log event & close connection
			printf("LOG: invalid password, access denied\n");
			send(g_newclient_socket, "fail", 5, 0);
			closesocket(newclient_socket);
		}
	}
	
	return 0;
}

// returns true iff 'recvbuf' contains a valid password
// uses CMD5 class that implements the MD5 hash algorithm
bool check_password_login(char *recvbuf) {
	char password[16+1];// at most 16 characters + terminating '\0'
	recvbuf[16] = '\0'; // limit recvbuf to 16 chars
	strcpy(password, recvbuf);				// create working copy from network buffer	

	// hash text up to and excluding 1st newline
	CMD5 myhash(strtok(password, "\n"));
	// compare hash to stored hash and return result
	return !strcmp(myhash.toString(), STORED_HASHSTRING);
}

void grant_access(void) {
	// create new process for new shell
	// and redirect its I/O to the network
	STARTUPINFO si = {0};
	PROCESS_INFORMATION pi = {0};
	char shell_command[MAX_SHELLCOMMAND_LEN];
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	si.lpTitle = "REMOTE ACCESS CONSOLE";
	si.hStdOutput = (HANDLE) g_newclient_socket;
	si.hStdError = (HANDLE) g_newclient_socket;
	si.hStdInput = (HANDLE) g_newclient_socket;
	GetEnvironmentVariable("COMSPEC", shell_command, MAX_SHELLCOMMAND_LEN);
	CreateProcess(shell_command, "/k cmd.exe", 0, 0, true, CREATE_NEW_CONSOLE, 0, 0, &si, &pi);
	
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}