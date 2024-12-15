#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <fltUser.h>
#include <winternl.h>
#include <stdlib.h>
#include "Header.h"
#include "../../TheCYaraAgent/TheCYaraAgent/yaraHead.h"

#define DEFAULT_THREAD_COUNT 8

/* global */

HANDLE gCommPortControl;

typedef struct _KL_SCAN_RECIEVE_FROM_KERNEL
{
	FILTER_MESSAGE_HEADER messageHeader;

	KL_SCAN_REQUEST_DATA  ReqData;

	OVERLAPPED Overlapped;

}KL_SCAN_RECIEVE_FROM_KERNEL, * PKL_SCAN_RECIEVE_FROM_KERNEL;

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "fltlib.lib")
#pragma comment(lib, "fltmgr.lib")
#pragma comment(lib, "ntdll.lib")

BOOLEAN OpenConnectionAndSendToFilterDriver();
DWORD WINAPI ThreadStartRoutine(PSCANNER_THREAD_CONTEXT Context);

int wmain(int argc, const wchar_t** argv)
{

	HRESULT rslt;
	UNICODE_STRING unstr;
	BOOLEAN isOk = FALSE;
	wchar_t wideString[1024] = { 0 };
	PKL_SCAN_RECIEVE_FROM_KERNEL dataFromKernel = NULL;
	HANDLE hCompletionRoutine;
	SCANNER_THREAD_CONTEXT context[DEFAULT_THREAD_COUNT];
	OVERLAPPED overlappedStructure;
	HANDLE hThread[DEFAULT_THREAD_COUNT];
	DWORD threadId, i;

	SC_HANDLE hScm;
	SC_HANDLE hService;
	LPSERVICE_STATUS lpServiceStatus = static_cast<LPSERVICE_STATUS>(malloc(sizeof(SERVICE_STATUS)));

	printf("[+] Now trying to connect to the yara engine...\n");


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

	printf("[+] THE CONNECTION TO THE YARA ENGINE ACCOMPLISHED.\n");

	printf("now trying to connect to the pipeline..\n");

	HANDLE hPipe = CreateFile(L"\\\\.\\pipe\\YaraEngine", GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hPipe == INVALID_HANDLE_VALUE)
	{
		printf("error while getting a handle to the pipe, error code %d\n", GetLastError());
		return -1;
	}

	printf("[+] CONNECTION TO THE PIPELINE ACCOMPLISHED.\n");

	
	printf("connecting to the filter ...\n");
	while(!isOk)
	{ 
		isOk = OpenConnectionAndSendToFilterDriver();
		Sleep(2000);
	}

	if (isOk)
		printf("The connection has established correctly ..\n");
	else
		printf("error in the connection function ..\n");


	// create completion routine
	hCompletionRoutine = CreateIoCompletionPort(gCommPortControl, NULL, 0, DEFAULT_THREAD_COUNT);

	if (hCompletionRoutine == NULL) {

		printf("ERROR: Creating completion port: %d\n", GetLastError());
		CloseHandle(gCommPortControl);
		return 3;
	}

	printf("Scanner: Port = 0x%p Completion = 0x%p\n", gCommPortControl, hCompletionRoutine);
	

	printf("waiting for any message from filter driver.\n");

	for ( i = 0; i < DEFAULT_THREAD_COUNT; i++)
	{ 
		context[i].Port = gCommPortControl;
		context[i].Completion = hCompletionRoutine;
		context[i].ThreadId = i;
		context[i].hPipe = hPipe;

		hThread[i] = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)ThreadStartRoutine, &context[i], 0, &threadId);

		if (hThread[i] == NULL)
		{
			printf("couldn't create the thread number : %d\n", i);
		}

		dataFromKernel = (PKL_SCAN_RECIEVE_FROM_KERNEL)malloc(sizeof(KL_SCAN_RECIEVE_FROM_KERNEL));

		// SET TO NULL
		memset(&dataFromKernel->Overlapped, 0, sizeof(OVERLAPPED));

		rslt = FilterGetMessage(gCommPortControl, &dataFromKernel->messageHeader, sizeof(KL_SCAN_RECIEVE_FROM_KERNEL), &dataFromKernel->Overlapped);
		
		if (rslt != HRESULT_FROM_WIN32(ERROR_IO_PENDING))
		{
			printf("ERROR couldn't get a message from the kernel driver. error code : 0x%x\n", rslt);
		
			free(dataFromKernel);

			FilterClose(gCommPortControl);
			
			return 0;
		}
		printf("thread number %d is in the pending state waiting for reply ...\n", i);

	}
	printf("now waiting for threads to be finished...\n");

	WaitForMultipleObjectsEx(i, hThread, TRUE, INFINITE, FALSE);

	printf("DONE all threads have finished.\n");

	printf("Now closing the handle to the pipeline ..\n");
	CloseHandle(hPipe);
	printf("Service is now paused for 2 seconds...\n");
	Sleep(2000); // 10 seconds

	free(dataFromKernel);

	FilterClose(gCommPortControl);

	return 0;
}

BOOLEAN OpenConnectionAndSendToFilterDriver()
{
	HRESULT rslt;

	if (gCommPortControl == NULL)
	{
		rslt = FilterConnectCommunicationPort(L"\\KLobjName", 0, NULL, 0, NULL, &gCommPortControl);
		if (rslt != S_OK)
		{
			printf("[yara engine]: ERROR can't open a connection to the filter.\n"); // pop-up for error message.
			gCommPortControl = NULL;
			return FALSE;
		}
	}

	printf("[yara engine] SUCCESS: we were enable to open a connection to the filter driver.\n");

	return TRUE;
}

DWORD WINAPI ThreadStartRoutine(PSCANNER_THREAD_CONTEXT Context)
{
	BOOL result;
	DWORD outSize;
	DWORD dataSizeToKernel;
	ULONG_PTR key;
	HRESULT rslt;
	BUFFER_DATA dataToEngine;
	size_t varIgnore;
	LPOVERLAPPED lpOverlapped;
	PKL_SCAN_RECIEVE_FROM_KERNEL dataFromKernel;
	KL_SCAN_SEND_TO_KERNEL dataToKernel;
	KL_SCAN_REQUEST_DATA targetData;

	while (true)
	{
		result = GetQueuedCompletionStatus(Context->Completion, &outSize, &key, &lpOverlapped, INFINITE);

		dataFromKernel = CONTAINING_RECORD(lpOverlapped, KL_SCAN_RECIEVE_FROM_KERNEL, Overlapped);

		if (!result)
		{
			printf("[THID : %d]: error: while queuing the message from the IOCP.\n", Context->ThreadId);
		}

		printf("[THID : %d]: message recieved size ; %Id\n", Context->ThreadId, lpOverlapped->InternalHigh);

		targetData = dataFromKernel->ReqData;

		//
		// HERE WE SHOULD SCAN THE FILE AND GET A RET VALUE...
		// 
		
		std::wcout << L"the file path recieved is : " << targetData.FilePath << std::endl;

		// CONVERT FROM WIDE CHAR TO CHAR 
		wcstombs_s(&varIgnore, dataToEngine.buffer, (size_t)MAX_LENGTH, targetData.FilePath, (size_t)MAX_LENGTH - 1);

		// try to get a handle to that file ..
		printf("Now trying to get a handle to that file.\n");

		HANDLE hFile = CreateFileA(dataToEngine.buffer, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

		if (hFile == INVALID_HANDLE_VALUE)
		{
			printf("[-]ERROR: couldn't open a handle to that file. error code is : %d\n", GetLastError());
		}
		else
		{
			printf("[+]SUCCESS: the file is open normally.\n");
			CloseHandle(hFile);
		}

		printf("Now print the file name path as a just multibyte char : %s\n", dataToEngine.buffer);
		dataToEngine.type = 0;

		// send data to engine ..
		printf(("[+] NOW trying to send the file path to the engine ...\n"));

		bool succ = WriteFile(Context->hPipe, &dataToEngine, sizeof(dataToEngine), nullptr, nullptr);
		if (!succ)
		{
			printf("error while writing to the pipe line, error code %d\n", GetLastError());
			return -1;
		}

		printf("[+] all is done.\n");

		printf("{*****} Now waiting for the engine to get us our message....\n");
		BOOLEAN isInfected;
		succ = ReadFile(Context->hPipe, &isInfected, 1, nullptr, nullptr);

		if (!succ)
		{
			printf("[-]ERROR: while waiting for the engine to send a message. error code : %d.\n", GetLastError());

		}
		else
		{
			printf("[+] the message recieved. is infected ? : %d\n", isInfected);
		}

		printf("[THID : %d]: now trying to send a reply ..\n", Context->ThreadId);

		dataToKernel.replyHeader.MessageId = dataFromKernel->messageHeader.MessageId;
		dataToKernel.replyHeader.Status = 0;
		dataToKernel.scanResult.isInfected = isInfected;

		dataSizeToKernel = sizeof(FILTER_REPLY_HEADER) + sizeof(KL_SCAN_RESULT);
		//dataSizeToKernel = sizeof(dataToKernel);

		rslt = FilterReplyMessage(Context->Port, (PFILTER_REPLY_HEADER)&dataToKernel, dataSizeToKernel);

		if (rslt != S_OK)
		{
			printf("[THID : %d]: the reply to the kernel has an error. the error code is : 0x%X\n", Context->ThreadId, rslt);
			return 0;
		}
		printf("[THID : %d]: [+] the message has replied correctly. \n", Context->ThreadId);

		// again we should call FilterGetMessage()

		rslt = FilterGetMessage(Context->Port, &dataFromKernel->messageHeader,
			FIELD_OFFSET(KL_SCAN_RECIEVE_FROM_KERNEL, Overlapped), &dataFromKernel->Overlapped);

		if (rslt != HRESULT_FROM_WIN32(ERROR_IO_PENDING))
		{
			break;
		}

	}

	if (!SUCCEEDED(rslt)) {

		if (rslt == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE)) {

			//
			//  Scanner port disconncted.
			//

			printf("Scanner: Port is disconnected, probably due to scanner filter unloading.\n");

		}
		else {

			printf("Scanner: Unknown error occured. Error = 0x%X\n", rslt);
		}
	}

	free(dataFromKernel);

	return rslt;
}
