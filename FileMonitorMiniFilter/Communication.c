#include <fltKernel.h>
#include "Communication.h"
#include "mainHeader.h"
#include "../ControlFilterApp/Header.h"


NTSTATUS KlInitCommunication()
{
	KdPrint(("[KL] ENTERING FUNCTION : %s", __FUNCTION__));

	NTSTATUS status;
	OBJECT_ATTRIBUTES objectAttr = { 0 };
	PSECURITY_DESCRIPTOR securityDesc = NULL;
	
	UNICODE_STRING objectName = RTL_CONSTANT_STRING(L"\\KLobjName");

	status = FltBuildDefaultSecurityDescriptor(&securityDesc, FLT_PORT_ALL_ACCESS);

	InitializeObjectAttributes(&objectAttr, &objectName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, securityDesc);

	status = FltCreateCommunicationPort(pRetFilter , &gCommPort, &objectAttr, NULL, KlUserConnectCallBack, KlUserDisconnectCallBack,
		KlUserMessageSendCallBack, 1);

	// not needed after call to FltCreateCommunicationPort
	FltFreeSecurityDescriptor(securityDesc);

	return STATUS_SUCCESS;
}

NTSTATUS KlUserConnectCallBack(
	_In_ PFLT_PORT ClientPort,
	_In_ PVOID ServerPortCookie,
	_In_ PVOID ConnectionContext,
	_In_ ULONG ContextSize,
	_Out_ PVOID* ConnectionPortCookie
)
{
	KdPrint(("[KL] ENTERING FUNCTION : %s", __FUNCTION__));

	// first init the global variable of client port to be used later if we want to send messages to user.
	gClientPort = ClientPort;

	KdPrint(("[KL] SUCCESS: the user has connected.\n"));
	
	ConnectionPortCookie = NULL;
	return STATUS_SUCCESS;
}

VOID KlUserDisconnectCallBack(
	_In_ PVOID ConnectionCookie
)
{
	KdPrint(("[KL] ENTERING FUNCTION : %s", __FUNCTION__));

	KdPrint(("[KL] DISCONNETING request from the user.\n"));
	FltCloseClientPort(pRetFilter, &gClientPort);
}

NTSTATUS KlUserMessageSendCallBack(
	_In_ PVOID PortCookie,
	_In_ PVOID InputBuffer OPTIONAL,
	_In_ ULONG InputBufferLength,
	_Out_ PVOID OutputBuffer OPTIONAL,
	_In_ ULONG OutputBufferLength,
	_Out_ PULONG ReturnOutputBufferLength
)
{
	KdPrint(("[KL] ENTERING FUNCTION : %s", __FUNCTION__));

	//CHAR kernelMessageTest[] = "kernel Message, Hello Omar";

	/*
	if (OutputBufferLength < sizeof(kernelMessageTest))
	{
		KdPrint(("[KL] ERROR: the size of output buffer is less than our message buffer. our size : %d, buffer size : %d.\n",
			sizeof(kernelMessageTest), OutputBufferLength));
	}
	*/

	//strcpy((PCHAR)OutputBuffer, kernelMessageTest);

	OutputBuffer = NULL;

	KdPrint(("[KL] MESSAGE RECIEVED : %s\n", InputBuffer));

	*ReturnOutputBufferLength = 0;

	return STATUS_SUCCESS;
}

VOID KlFilterCommunicationUnload()
{
	KdPrint(("[KL] ENTERING FUNCTION : %s", __FUNCTION__));

	KdPrint(("[KL] CLOSING the communication port.\n"));
	FltCloseCommunicationPort(gCommPort);
}

NTSTATUS KlSendMessageToEngine(PUNICODE_STRING filePath, PBOOLEAN isInfected)
{
	NTSTATUS status;
	BOOLEAN isInfectedResponse = FALSE;
	ULONG bufferInSize = sizeof(BOOLEAN);

	status = FltSendMessage(pRetFilter, &gClientPort, (PVOID)filePath, sizeof(KL_SCAN_REQUEST_DATA),
		&isInfectedResponse, &bufferInSize, NULL);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("[KL] ERROR: while sending the file path to the engine, error code : 0x%x\n", status));
		return status;
	}
	else
	{
		if (status == STATUS_TIMEOUT)
		{
			KdPrint(("[KL] ERROR: TIME OUT for the sending request.\n"));
		}
		else
		{
			KdPrint(("[KL] SUCCESS: the data has sent. is the file infected : %d\n", isInfectedResponse));
		}
	}

	*isInfected = isInfectedResponse;

	return status;
}

NTSTATUS KlSendFileToEngine(_In_ UNICODE_STRING filePath, _Out_ PBOOLEAN isInfected)
{
	KdPrint(("[KL] ENTERING FUNCTION %s\n", __FUNCTION__));

	NTSTATUS status;
	BOOLEAN isInfLocal;
	PKL_SCAN_REQUEST_DATA dataToUser = NULL;
	PKL_SCAN_RESULT dataFromUser = NULL;
	ULONG replySize = 0;
	// I will use this pool for both the send and recieve.

	try{
		dataToUser = (PKL_SCAN_REQUEST_DATA)ExAllocatePoolZero(NonPagedPool, sizeof(KL_SCAN_REQUEST_DATA), KL_SCAN_REQUEST_DATA_TAG);
		
		if (NULL == dataToUser)
		{
			KdPrint(("[KL] ERROR: couldn't allocate space for data to user.\n"));
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		
		RtlCopyMemory(&dataToUser->FilePath, filePath.Buffer, min(filePath.Length, KL_MAX_FILE_PATH_LENGTH));

		dataFromUser = (PKL_SCAN_RESULT)ExAllocatePoolZero(NonPagedPool, sizeof(KL_SCAN_RESULT), KL_SCAN_RESULT_TAG);

		if (NULL == dataFromUser)
		{
			KdPrint(("[KL] ERROR: couldn't allocate space for data from user.\n"));
			ExFreePoolWithTag(dataToUser, KL_SCAN_REQUEST_DATA_TAG);
			return STATUS_INSUFFICIENT_RESOURCES;
		}
	
		replySize = sizeof(KL_SCAN_RESULT);
	
		status = FltSendMessage(pRetFilter, &gClientPort, (PVOID)dataToUser, sizeof(KL_SCAN_REQUEST_DATA),
			dataFromUser, &replySize, NULL);
	
		if (NT_SUCCESS(status))
		{
			isInfLocal = dataFromUser->isInfected;
			KdPrint(("[KL] SUCCESS: the data was sent and recieved, Is Infectd : %d", isInfLocal));
			*isInfected = isInfLocal;
			return STATUS_SUCCESS;
		}
	
		KdPrint(("[KL] ERROR: the data has not sent or recieved. error code 0x%x\n", status));

	} finally {

		if(dataToUser != NULL)
			ExFreePoolWithTag(dataToUser, KL_SCAN_REQUEST_DATA_TAG);
		
		if (dataFromUser != NULL)
			ExFreePoolWithTag(dataFromUser, KL_SCAN_RESULT_TAG);
	}
	return status;
}