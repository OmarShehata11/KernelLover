#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <fltUser.h>
#include <winternl.h>
#include "yaraHead.h"

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "fltlib.lib")
#pragma comment(lib, "fltmgr.lib")
#pragma comment(lib, "ntdll.lib")

BOOLEAN OpenConnectionAndSendToFilterDriver();

int wmain(int argc, const wchar_t** argv)
{
	SC_HANDLE hScm;
	SC_HANDLE hService;
	LPSERVICE_STATUS lpServiceStatus = static_cast<LPSERVICE_STATUS>(malloc(sizeof(SERVICE_STATUS)));

	hScm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);

	if (hScm == NULL)
	{
		printf("error while openning the scm. error code %d\n", GetLastError());
		return -1;
	}

	hService = OpenServiceA(hScm, "YaraEngine", SERVICE_ALL_ACCESS);

	if (hService == NULL)
	{
		printf("error while openning the scm. error code %d\n", GetLastError());
		return -1;
	}

	//TCHAR* Messages[] = { (TCHAR*)"First message brooo", (TCHAR*)"Second Message Broooo" };


	/*if (!(StartServiceA(hService, 2, (LPCSTR*)Messages)))
	{
		printf("error while sending the arguments. error code %d\n", GetLastError());
		return -1;
	}*/

	if (!(ControlService(hService, SERVICE_CONTROL_PAUSE, _Out_ lpServiceStatus)))
	{
		printf("error while sending control code to the service . error code %d\n", GetLastError());
		return -1;
	}

	BOOLEAN isOk = OpenConnectionAndSendToFilterDriver();

	if (isOk)
		printf("The connection has established correctly ..\n");
	else
		printf("error in the connection function ..\n");


	// TEST THE STRING CONVERTION THING..
	UNICODE_STRING unstr;
	
	RtlInitUnicodeString(&unstr, L"this is a wide string");

	wchar_t wideString[1024] = { 0 };

	RtlCopyMemory(wideString, unstr.Buffer, unstr.Length);
	wideString[unstr.Length] = '\0';

	std::wcout << L"the wide string is : " << unstr.Buffer << std::endl;

	printf("Service is now paused for 2 seconds...\n");
	Sleep(2000); // 10 seconds

	if (!(ControlService(hService, SERVICE_CONTROL_CONTINUE, _Out_ lpServiceStatus)))
	{
		printf("error while sending control code to the service . error code %d\n", GetLastError());
		return -1;
	}
	printf("Service has continued again.\n");

	HANDLE hPipe = CreateFile(L"\\\\.\\pipe\\YaraEngine", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hPipe == INVALID_HANDLE_VALUE)
	{
		printf("error while getting a handle to the pipe, error code %d\n", GetLastError());
		return -1;
	}

	printf("we got a handle.\n");

	// TCHAR Data[] = L"Hello from the other siiiidddeeeeee.";

	BUFFER_DATA data;
	data.type = 1; // 0 => file scanning, 1=> process scanning.
	strncpy_s(data.buffer, MAX_LENGTH, "12176", MAX_LENGTH - 1);
	//strncpy_s(data.buffer, MAX_LENGTH, "C:\\Users\\Omar Shehata\\Desktop\\a.exe", MAX_LENGTH - 1);

	bool succ = WriteFile(hPipe, &data, sizeof(data), nullptr, nullptr);
	if (!succ)
	{
		printf("error while writing to the pipe line, error code %d", GetLastError());
		return -1;
	}

	printf("all is done.\n");

	CloseHandle(hPipe);
	return 0;
}

BOOLEAN OpenConnectionAndSendToFilterDriver()
{
	CHAR bufferToFilter[] = "HELLO FROM USER MODE. THIS IS YARA ENGINE.";
	CHAR bufferFromFilter[MAX_LENGTH];
	LPDWORD lpByteRet = NULL;
	DWORD test = 0;
	HRESULT rslt;

	if (gCommPort == NULL)
	{
		rslt = FilterConnectCommunicationPort(L"\\KLobjName", 0, NULL, 0, NULL, &gCommPort);
		if (IS_ERROR(rslt))
		{
			printf("[yara engine]: ERROR can't open a connection to the filter.\n"); // pop-up for error message.
			return FALSE;
		}
	}

	printf("[yara engine] SUCCESS: we were enable to open a connection to the filter driver.\n");

	return TRUE;

	// if success
	/*rslt = FilterSendMessage(gCommPort, bufferToFilter, sizeof(bufferToFilter), NULL, test, lpByteRet);

	if (rslt != S_OK)
	{
		printf("[yara engine] ERROR: couldn't send a message to the filter.\n");
		return FALSE;
	}

	else
	{
		printf("[yara engine] SUCCESS: the message has sent and also recieved. good job omar.\n");
		printf("and the message from kernel is : %s\n", bufferFromFilter);
	}*/

}