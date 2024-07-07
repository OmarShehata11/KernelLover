#pragma once


/* GLOBAL VARIABLES */
PFLT_FILTER pRetFilter;
ULONGLONG gNumofFileNeedScan;

// some GUID definitions:

DEFINE_GUID(GUID_ECP_CSV_DOWN_LEVEL_OPEN,
	0x4248be44,
	0x647f,
	0x488f,
	0x8b, 0xe5, 0xa0, 0x8a, 0xaf, 0x70, 0xf0, 0x28);

DEFINE_GUID(GUID_ECP_PREFETCH_OPEN,
	0xe1777b21,
	0x847e,
	0x4837,
	0xaa, 0x45, 0x64, 0x16, 0x1d, 0x28, 0x6, 0x55);

/* flags definitions */
#define DESKTOP

#define KL_PREFETCH_FOUND_FLAG	1

// some flag sizes 
#define KL_STREAMHANDLE_CONTEXT_SIZE sizeof(KL_STREAMHANDLE_CONTEXT)
#define KL_STREAM_CONTEXT_SIZE sizeof(KL_STREAM_CONTEXT)

/* pool tages */
#define KL_STREAMHANDLE_CONTEXT_TAG 'gaTh'
#define KL_STREAM_CONTEXT_TAG 'gaTc'
#define KL_KEVENT_TAG 'gaTk'
#define KL_MSDOS_FILE_NAME_TAG 'tDSM'

/* just list of states that the file object can be one of them */
typedef enum _KL_FILE_STATE
{
	KlFileModified,
	KlFileInfected,
	KlFileScanning,
	KlFileClear
}KL_FILE_STATE;

// we should support both file id 64 and 128
typedef union _KL_FILE_ID
{
	struct
	{
		ULONGLONG value64;
		ULONGLONG upperZeroes;
	}Fields;

	FILE_ID_128 FileId128;

}KL_FILE_ID, * PKL_FILE_ID;

typedef struct _KL_STREAM_CONTEXT
{
	ULONG flags;
	BOOLEAN isExeFile;
	BOOLEAN isFromDesktop;
	PKEVENT event;		// the event for synchronization things.
	KL_FILE_STATE fileState;
	KL_FILE_ID FileId;
}KL_STREAM_CONTEXT, * PKL_STREAM_CONTEXT;

typedef struct _OBJECT_CONTEXT
{
	ULONG flags;

}OBJECT_CONTEXT, * POBJECT_CONTEXT;


typedef struct _KL_STREAMHANDLE_CONTEXT
{
	ULONG flags;

}KL_STREAMHANDLE_CONTEXT, * PKL_STREAMHANDLE_CONTEXT;



// macros 
#define FlagOn(_x, _y) ((_x) & (_y))
#define SetFlag(_x, _y) ((_x) |= (_y))
#define ClearFlag(_x, _y) ((_x) &= ~(_y))

#define SetFileModified(_fileState) (_fileState = KlFileModified) // the enum is 4 bytes long
#define SetFileInfected(_fileState) (_fileState = KlFileInfected) 
#define SetFileScanning(_fileState) (_fileState = KlFileScanning) 
#define SetFileCleared(_fileState)  (_fileState = KlFileClear)

#define KlIsFileModified(_fileState) (BOOLEAN)((_fileState) == KlFileModified)
#define KlIsFileInfected(_fileState) (BOOLEAN)((_fileState) == KlFileInfected)


#define KlIsFileNeedScan(_pFileContext) (BOOLEAN)((_pFileContext)->isExeFile == TRUE && \
											      KlIsFileModified(_pFileContext->fileState) == TRUE && \
												  (_pFileContext)->isFromDesktop == TRUE)


/* FUNCTION DEFINITION */
PFLT_FILE_NAME_INFORMATION KlGetFileNameHelper(PFLT_CALLBACK_DATA Data);

VOID PrintCreateDisposition(ULONG options);

VOID PrintCreateOptions(ULONG options);

NTSTATUS KlCheckEncryptedFile(PCFLT_RELATED_OBJECTS FltObjects, PBOOLEAN isEncrypted);

NTSTATUS KlIsFileHasADS(PCFLT_RELATED_OBJECTS FltObjects, PBOOLEAN isContainAds, PFLT_CALLBACK_DATA Data);

NTSTATUS KlObtainFileId(_In_ PFILE_OBJECT FileObject, PFLT_INSTANCE Instance, _Out_ PKL_FILE_ID FileId);

NTSTATUS KlGetFileStateFromCache();

NTSTATUS KlIsFileExectuable(_In_ PFLT_CALLBACK_DATA Data, _In_ PFILE_OBJECT FileObject, _Out_ PKL_STREAM_CONTEXT StreamContext);

NTSTATUS KlCreateStreamHandleContext(PCFLT_RELATED_OBJECTS FltObjects, PKL_STREAMHANDLE_CONTEXT* retContext);

NTSTATUS KlCreateAndInitStreamContext(PCFLT_RELATED_OBJECTS FltObjects, PKL_STREAM_CONTEXT* retStreamContext);

BOOLEAN IsPrefetchEcpExist(PFLT_CALLBACK_DATA Data);

BOOLEAN IsCsvfsEcpExist(PFLT_CALLBACK_DATA Data);

NTSTATUS KlIsFromDesktop(PFLT_FILE_NAME_INFORMATION pFileNameInfo, PBOOLEAN IsFromDesktop);


// clean up context functions
void KlStreamContextCleanUp(
	_In_ PFLT_CONTEXT Context,
	_In_ FLT_CONTEXT_TYPE ContextType
);

BOOLEAN
KlOperationsModifyingFile(
	_In_ PFLT_CALLBACK_DATA Data
);
