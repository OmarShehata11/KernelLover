#pragma once
#include <iostream>

#define MAX_LENGTH 2048

typedef struct _BUFFER_DATA
{
	short type; /* 0 = scan file,, 1 = scan process */
	char buffer[MAX_LENGTH];

}BUFFER_DATA, *PBUFFER_DATA;

typedef struct _DATA_FROM_KERNEL
{
	BUFFER_DATA BufferData;
	OVERLAPPED Overlapped;

}DATA_FROM_KERNEL, *PDATA_FROM_KERNEL;

typedef struct _THREAD_PARAMETERS
{
	HANDLE hCompletionRoutine;
	HANDLE hPipe;
}THREAD_PARAMETERS, *PTHREAD_PARAMETERS;
