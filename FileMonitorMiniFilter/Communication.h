#pragma once

/* GLOBAL */
PFLT_PORT gClientPort;
PFLT_PORT gCommPort;

// MACRO
#define KL_CONNECTION_PORT_COOKIE_SIZE sizeof(KL_CONNECTION_PORT_COOKIE)

#define KL_CONNECTION_PORT_COOKIE_TAG 'Tcpc'
#define KL_SCAN_REQUEST_DATA_TAG	  'Tdcs'
#define KL_SCAN_RESULT_TAG			  'Trs'



typedef struct _KL_CONNECTION_PORT_COOKIE
{
	// that's all what I need now..
	PFLT_FILTER hFilter;

}KL_CONNECTION_PORT_COOKIE, *PKL_CONNECTION_PORT_COOKIE;



NTSTATUS KlUserConnectCallBack(
	_In_ PFLT_PORT ClientPort,
	_In_ PVOID ServerPortCookie,
	_In_ PVOID ConnectionContext,
	_In_ ULONG ContextSize,
	_Out_ PVOID* ConnectionPortCookie
);

VOID KlUserDisconnectCallBack(
	_In_ PVOID ConnectionCookie
);

NTSTATUS KlUserMessageSendCallBack(
	_In_ PVOID PortCookie,
	_In_ PVOID InputBuffer OPTIONAL,
	_In_ ULONG InputBufferLength,
	_Out_ PVOID OutputBuffer OPTIONAL,
	_In_ ULONG OutputBufferLength,
	_Out_ PULONG ReturnOutputBufferLength
);


NTSTATUS KlSendFileToEngine(
	_In_ UNICODE_STRING filePath,
	_Out_ PBOOLEAN isInfected
);

NTSTATUS KlInitCommunication();

VOID KlFilterCommunicationUnload();
