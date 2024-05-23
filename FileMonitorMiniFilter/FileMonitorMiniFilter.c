#include <fltKernel.h>
#include "mainHeader.h"

// some GUID definitions:

DEFINE_GUID(GUID_ECP_CSV_DOWN_LEVEL_OPEN,
	0x4248be44,
	0x647f,
	0x488f,
	0x8b, 0xe5, 0xa0, 0x8a, 0xaf, 0x70, 0xf0, 0x28);

DEFINE_GUID(GUID_ECP_PREFETCH_OPEN, 0xe1777b21, 0x847e, 0x4837, 0xaa, 0x45, 0x64, 0x16, 0x1d, 0x28, 0x6, 0x55);

#ifdef __cpluplus
EXTERN_C_START
#endif

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath);

NTSTATUS FilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS PreCreateCallBack(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext);

FLT_POSTOP_CALLBACK_STATUS PostCreateCallBack(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID CompletionContext,
	FLT_POST_OPERATION_FLAGS Flags);

#ifdef __cplusplus
EXTERN_C_END
#endif

BOOLEAN IsEcpWithGuidExist(PFLT_CALLBACK_DATA Data, const GUID Guid);
PFLT_FILE_NAME_INFORMATION GetFileNameHelper(PFLT_CALLBACK_DATA Data);
VOID PrintCreateDisposition(ULONG options);
VOID PrintCreateOptions(ULONG options);


const FLT_OPERATION_REGISTRATION Callbacks[] =
{
	{IRP_MJ_CREATE, 0, PreCreateCallBack, PostCreateCallBack},
	{IRP_MJ_OPERATION_END}
};

const FLT_REGISTRATION Registration = {
	sizeof(FLT_REGISTRATION),
	FLT_REGISTRATION_VERSION,
	0,
	NULL,
	Callbacks,
	FilterUnload,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
};

/* GLOBAL VARIABLES */
PFLT_FILTER pRetFilter;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, FilterUnload)
#pragma alloc_text(PAGA, GetFileNameHelper)
#pragma alloc_text(PAGE, PreCreateCallBack)
#endif


#define FlagOn(_x, _y) ((_x) & (_y))
#define SetFlag(_x, _y) ((_x) |= (_y))
#define ClearFlag(_x, _y) ((_x) &= ~(_y))

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegPath)
{
	KdPrint(("ENTERING : %s\r\n", __FUNCTION__));

	NTSTATUS status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(RegPath);

	status = FltRegisterFilter(DriverObject, &Registration, &pRetFilter);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("Minifilter Driver: FAIL in registration for filtering. error 0x%x\r\n", status));
		return status;
	}
	
	status = FltStartFiltering(pRetFilter);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("Minifilter Driver: FAIL in start filtering. error 0x%x\r\n", status));
		FltUnregisterFilter(pRetFilter);
		return status;
	}

	return STATUS_SUCCESS;
}

NTSTATUS FilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
	KdPrint(("ENTERING : %s\r\n", __FUNCTION__));

	UNREFERENCED_PARAMETER(Flags);
	FltUnregisterFilter(pRetFilter);
	return STATUS_SUCCESS;
}

//
// callback for the IRP_MJ_CREATE
//

FLT_PREOP_CALLBACK_STATUS PreCreateCallBack(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{


/*++

Routine Description:

	This routine is the pre-create completion routine.


Arguments:

	Data - Pointer to the filter callbackData that is passed to us.

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance, its associated volume and
		file object.

	CompletionContext - If this callback routine returns FLT_PREOP_SUCCESS_WITH_CALLBACK or
		FLT_PREOP_SYNCHRONIZE, this parameter is an optional context pointer to be passed to
		the corresponding post-operation callback routine. Otherwise, it must be NULL.

		I'm going to pass the object context structure into this last argument to the post 
		callback routine.

Return Value:

	FLT_PREOP_SYNCHRONIZE - PostCreate needs to be called back synchronizedly.
	FLT_PREOP_SUCCESS_NO_CALLBACK - PostCreate does not need to be called.

--*/

	UNREFERENCED_PARAMETER(CompletionContext);
	
	//
	// no need to allocate it in a non-paged pool.
	//
	OBJECT_CONTEXT objectContext = { 0 };
	
	PFLT_FILE_NAME_INFORMATION pFltNameInfo = NULL;
	ULONG options = 0;
	//HANDLE hFile;
	//NTSTATUS status = STATUS_SUCCESS;
	PIO_STATUS_BLOCK pIoStatus = NULL;
	OBJECT_ATTRIBUTES objectAttr;
	ULONG_PTR stackHigh, stackLow;
	HANDLE hHeap;



	/* skip the directory open */

	if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}


	/* first skip the stack based file object */
	
	IoGetStackLimits(&stackLow, &stackHigh);
	if (((ULONG_PTR)FltObjects->FileObject < stackHigh) &&
		((ULONG_PTR)FltObjects->FileObject > stackLow)) // is it in the address range of my stack frame
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	/* also skip the pre-rename operation that open the parent directory : */
	if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	/* skip the paging files */
	if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	/* also skip the DASD (direct access storage device) open requests. */
	if (FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	/* also skip the prefetch file open (we should flag it on a global structure to skip any incoming I/O operation to it. */
	if (IsEcpWithGuidExist(Data, GUID_ECP_PREFETCH_OPEN))
	{
		SetFlag(objectContext.flags, KL_PREFETCH_FOUND_FLAG);
	}

	/* also skip the CSVFS request. (this is not mandatory because this AV won't run in a server). */
	if (IsEcpWithGuidExist(Data, GUID_ECP_CSV_DOWN_LEVEL_OPEN))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	/* let's skip also the request came from kernel mode at this moment. */
	if (Data->RequestorMode == KernelMode)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	/* ignore the NTFS repase point (RP) */
	if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_OPEN_REPARSE_POINT))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	/* let's try to print the name for the object file */

	pFltNameInfo = GetFileNameHelper(Data);

	if (pFltNameInfo != NULL)
	{
		KdPrint(("[AV_MINIFILTER]: got a creation of a file \r\n"));
		KdPrint(("[AV_MINIFILTER]: the name of the file is %wZ", &pFltNameInfo->Name));
		PrintCreateDisposition(Data->Iopb->Parameters.Create.Options);
		PrintCreateOptions(Data->Iopb->Parameters.Create.Options);
	}

	else
	{
		KdPrint(("[AV_MINIFILTER]: error: could not resolve the name of the file object. \r\n"));
	}

	/*
	if (FltObjects->FileObject != NULL && Data->RequestorMode == UserMode) // a file access from the user mode
	{
		options = Data->Iopb->Parameters.Create.Options;

		// CHECK IF IT'S A FILE CREATION:
	
		 if (FlagOn(options,FILE_NON_DIRECTORY_FILE) && (options >> 24) == FILE_CREATE) // file Creation: 
		{
				pFltNameInfo = GetFileNameHelper(Data);

				if (NULL != pFltNameInfo)
				{ 
				
					// I will assume that we got alwayes the normalized file name...
					// now initialize the object attribute : 
					
					InitializeObjectAttributes(&objectAttr, &pFltNameInfo->Name, OBJ_EXCLUSIVE, NULL, NULL);
					
					// now try to get the handle : 
					status = FltCreateFile(pRetFilter, NULL, &hFile, FILE_READ_DATA, &objectAttr, pIoStatus, NULL, FILE_ATTRIBUTE_NORMAL
						, 0, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0, 0);
				
					
					if (!NT_SUCCESS(status))	// FAIL == file not exist, it tries to create a new one
					{
						KdPrint(("A file WAS CREATED ...\r\n"));

						KdPrint(("FILTER DRIVER: dealing with NORMALIZED FILE NAME : %wZ \r\n", &pFltNameInfo->Name));
					}

					else
					{ 
						FltClose(hFile);
						
					}


				}
		}


	}
	*/

if (pFltNameInfo != NULL) 	// now clean everything up :
		FltReleaseFileNameInformation(pFltNameInfo);

*CompletionContext = (PVOID)objectContext.flags;

return FLT_PREOP_SYNCHRONIZE;
}


FLT_POSTOP_CALLBACK_STATUS PostCreateCallBack(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID CompletionContext,
	FLT_POST_OPERATION_FLAGS Flags)
{
/*++

	Routine Description:

		This routine is the post-create completion routine.


	Arguments:

	Data - Pointer to the filter callbackData that is passed to us.

	FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
		opaque handles to this filter, instance, its associated volume and
		file object.

	CompletionContext - The completion context set in the pre-create routine.

	Flags - Denotes whether the completion is successful or is being drained.
	
	Return Value:.
		NTSTATUS of the operation.

--*/



	/* MISSED TO DO: */


	KdPrint(("[KernelLover]: ENTERING : %s\n", __FUNCTION__));

	KdPrint(("Try to print the context ... \n"));

	KdPrint(("Data is : %d \n", (ULONG_PTR)CompletionContext ));

	return FLT_POSTOP_FINISHED_PROCESSING;
	
}

PFLT_FILE_NAME_INFORMATION GetFileNameHelper(PFLT_CALLBACK_DATA Data)
{

/* ROUTINE EXPLAINATION:
	- this routine retrive the info about the object file name represented in FLT_FILE_NAME_INFORMATION.
	
	PARAMETERS:
		-Data: to get the file object from it.
		
	RETURN:
		- pointer to FLT_FILE_NAME_INFORMATION: if it could find one (whether it's normalized or opened file name.
		- NULL: if it couldn't find one.
*/
	KdPrint(("--------------------------------------------\r\n"));
	KdPrint(("ENTERING : %s \r\n", __FUNCTION__));

	NTSTATUS status;
	PFLT_FILE_NAME_INFORMATION pFltNameInfo = NULL;

	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP | FLT_FILE_NAME_NORMALIZED, &pFltNameInfo);
	/*
	WE ARE GOING TO FIRST GET THE NORMALIZED FILE NAME, IF IT FAILED, THEN WE WILL GET THE OPENED FILE NAME
	(BY OF COURSE CHANGING THE FLAGS USED)
	*/

	//failed to get the normalized name, now try to get the open name : 
	if (NT_SUCCESS(status))
	{
		return pFltNameInfo;
	}

	return NULL;
}


BOOLEAN IsEcpWithGuidExist(PFLT_CALLBACK_DATA Data, const GUID Guid)
{
/* ROUTINE EXPLAINATION:
	- it finds if the specific GUID is existed in the ECP_LIST, if there's and ECP_LIST in the first place.
	
	PARAMETERS:
		- Data: a pointer to FLT_CALLBACK_DATA structure to get the file object
		- Guid: a pointer to a GUID to search for the ECP_CONTEXT.

	RETURN:
		-TRUE: found the ECP context.
		-FALSE: not found.
*/
	KdPrint(("Entering function : %s", __FUNCTION__));
	NTSTATUS status;
	PECP_LIST ecpList = NULL;
	status = FltGetEcpListFromCallbackData(pRetFilter, Data, &ecpList);

	if (NT_SUCCESS(status) && NULL != ecpList)
	{
		status = FltFindExtraCreateParameter(pRetFilter, ecpList, &Guid, NULL, NULL);
		if (NT_SUCCESS(status))
			return TRUE;
	}

	return FALSE; // there's no ECP_LIST in the first place or can't find the ecp context.
}


VOID PrintCreateDisposition(ULONG options)
{
	// HIGH 8 BITS 
	ULONG opt = options >> 24;

	KdPrint(("[AV_MINIFILTER]: THE CREATE DISPOSITION OPTIONS FOR THE CREATE REQUEST ARE: \r\n"));
	

	if (FlagOn(opt, FILE_SUPERSEDE))
		KdPrint(("  - FILE_SUPERSEDE \n"));

	 if (FlagOn(opt, FILE_OPEN))
		KdPrint(("  - FILE_OPEN \n"));

	 if (FlagOn(opt, FILE_OPEN_IF))
		KdPrint(("  - FILE_OPEN_IF \n"));

	 if (FlagOn(opt, FILE_OVERWRITE))
		KdPrint(("  - FILE_OVERWRITE \n"));

	 if (FlagOn(opt, FILE_CREATE))
		KdPrint(("  - FILE_CREATE \n"));

	 if (FlagOn(opt, FILE_OVERWRITE_IF))
		KdPrint(("  - FILE_OVERWRITE_IF \n"));

}

VOID PrintCreateOptions(ULONG options)
{
	// LOW 24 BITS
	ULONG opt = options;

	KdPrint(("[AV_MINIFILTER]: THE CREATE DISPOSITION OPTIONS FOR THE CREATE REQUEST ARE: \r\n"));

	if (FlagOn(opt, FILE_DIRECTORY_FILE)) {
		KdPrint(("  - FILE_DIRECTORY_FILE\n"));
	}
	if (FlagOn(opt, FILE_WRITE_THROUGH)) {
		KdPrint(("  - FILE_WRITE_THROUGH\n"));
	}
	if (FlagOn(opt, FILE_SEQUENTIAL_ONLY)) {
		KdPrint(("  - FILE_SEQUENTIAL_ONLY\n"));
	}
	if (FlagOn(opt, FILE_NO_INTERMEDIATE_BUFFERING)) {
		KdPrint(("  - FILE_NO_INTERMEDIATE_BUFFERING\n"));
	}

	if (FlagOn(opt, FILE_SYNCHRONOUS_IO_ALERT)) {
		KdPrint(("  - FILE_SYNCHRONOUS_IO_ALERT\n"));
	}
	if (FlagOn(opt, FILE_SYNCHRONOUS_IO_NONALERT)) {
		KdPrint(("  - FILE_SYNCHRONOUS_IO_NONALERT\n"));
	}
	if (FlagOn(opt, FILE_NON_DIRECTORY_FILE)) {
		KdPrint(("  - FILE_NON_DIRECTORY_FILE\n"));
	}
	if (FlagOn(opt, FILE_CREATE_TREE_CONNECTION)) {
		KdPrint(("  - FILE_CREATE_TREE_CONNECTION\n"));
	}

	if (FlagOn(opt, FILE_COMPLETE_IF_OPLOCKED)) {
		KdPrint(("  - FILE_COMPLETE_IF_OPLOCKED\n"));
	}
	if (FlagOn(opt, FILE_NO_EA_KNOWLEDGE)) {
		KdPrint(("  - FILE_NO_EA_KNOWLEDGE\n"));
	}
	if (FlagOn(opt, FILE_OPEN_REMOTE_INSTANCE)) {
		KdPrint(("  - FILE_OPEN_REMOTE_INSTANCE\n"));
	}
	if (FlagOn(opt, FILE_RANDOM_ACCESS)) {
		KdPrint(("  - FILE_RANDOM_ACCESS\n"));
	}
	if (FlagOn(opt, FILE_DELETE_ON_CLOSE)) {
		KdPrint(("  - FILE_DELETE_ON_CLOSE\n"));
	}
	if (FlagOn(opt, FILE_OPEN_BY_FILE_ID)) {
		KdPrint(("  - FILE_OPEN_BY_FILE_ID\n"));
	}
	if (FlagOn(opt, FILE_OPEN_FOR_BACKUP_INTENT)) {
		KdPrint(("  - FILE_OPEN_FOR_BACKUP_INTENT\n"));
	}
	if (FlagOn(opt, FILE_NO_COMPRESSION)) {
		KdPrint(("  - FILE_NO_COMPRESSION\n"));
	}
	if (FlagOn(opt, FILE_RESERVE_OPFILTER)) {
		KdPrint(("  - FILE_RESERVE_OPFILTER\n"));
	}
	if (FlagOn(opt, FILE_OPEN_REPARSE_POINT)) {
		KdPrint(("  - FILE_OPEN_REPARSE_POINT\n"));
	}
	if (FlagOn(opt, FILE_OPEN_NO_RECALL)) {
		KdPrint(("  - FILE_OPEN_NO_RECALL\n"));
	}
	if (FlagOn(opt, FILE_OPEN_FOR_FREE_SPACE_QUERY)) {
		KdPrint(("  - FILE_OPEN_FOR_FREE_SPACE_QUERY\n"));
	}

}



/*
	NOTE: you can add post call back to check if you altered the creation of a file from pre-callback, you can check it in the post-op using the 
	FltCreateFile.

	NOTE: HOW TO ACCESS THE IRP IN THE PRECALLBACK:
		 PIRP irp = Data->Iopb->Parameters.Irp.SystemBuffer; // Accessing IRP


	Q: Which is better to use, FltObjects->FileObject->FileName or FltGetFileNameInformation to get the file name ?
	A: 
		Here's a breakdown of the two approaches for retrieving file names in a minifilter driver's pre-operation callback routine:
		
		1. FltGetFileNameInformation:
		
		Advantages:
		
		Reliable: Ensures you get the correct and up-to-date file name information.
		Flexibility: Offers various information classes (e.g., FLT_FILE_NAME_NORMALIZED for full path, FLT_FILE_NAME_QUERY_DEFAULT for opened name) to suit your needs.
		Consistency: Provides a standardized approach for retrieving file names, potentially making your code more maintainable.
		Disadvantages:
		
		Overhead: Involves an additional function call, which might introduce a slight performance overhead compared to directly accessing FltObjects->FileObject->FileName.
		2. FltObjects->FileObject->FileName:
		
		Advantages:
		
		Performance: Can be slightly faster as it avoids an extra function call.
		Direct Access: Offers a more direct way to obtain the file name stored in the file object.
		Disadvantages:
		
		Reliability: The file name stored in FltObjects->FileObject->FileName might not always be accurate or complete. It may reflect the name used when the file object was created, not necessarily the full path or the user's specific way of opening the file.
		Limited Flexibility: Doesn't provide different information class options like FltGetFileNameInformation.
		Less Maintainability: Reliance on internal structures might require adjustments if driver development practices change.
		
		
			//	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP | FLT_FILE_NAME_OPENED, &pFltNameInfo); // get the opened file name.
	//
	//	if (!NT_SUCCESS(status)) // if failed (NOW IN BOTH NORMALIZED AND OPENED)
	//	{
	//		KdPrint(("FILTER DRIVER: FAIL to get the opened file name too.\r\n"));
	//	}
	//
	//	else { // now we have an opened file name
	//		KdPrint(("FILTER DRIVER: dealing with OPENED FILE NAME : %wZ", &pFltNameInfo->Name));
	//	}


*/