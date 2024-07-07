#include <fltKernel.h>
#include "mainHeader.h"
#include "Communication.h"

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

FLT_PREOP_CALLBACK_STATUS
PreWriteandSetInfoCallBack(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

#ifdef __cplusplus
EXTERN_C_END
#endif


//
// the context registration.
//

const FLT_CONTEXT_REGISTRATION ContextRegistration[] =
{
	{FLT_STREAMHANDLE_CONTEXT, 0, NULL, KL_STREAMHANDLE_CONTEXT_SIZE, KL_STREAMHANDLE_CONTEXT_TAG},
	{FLT_STREAM_CONTEXT, 0, KlStreamContextCleanUp, KL_STREAM_CONTEXT_SIZE, KL_STREAM_CONTEXT_TAG},
	{FLT_CONTEXT_END}
};


const FLT_OPERATION_REGISTRATION Callbacks[] =
{
	{IRP_MJ_CREATE, 0, PreCreateCallBack, PostCreateCallBack},
	{IRP_MJ_WRITE, 0, PreWriteandSetInfoCallBack, 0},
	{IRP_MJ_SET_INFORMATION, 0, PreWriteandSetInfoCallBack, 0},
	{IRP_MJ_OPERATION_END}
};

const FLT_REGISTRATION Registration = {
	sizeof(FLT_REGISTRATION),
	FLT_REGISTRATION_VERSION,
	0,
	ContextRegistration, // registeration context structure
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



#ifdef ALLOC_PRAGMA // to check if alloc_text pragma is supported or not. 
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, FilterUnload)
#pragma alloc_text(PAGA, KlGetFileNameHelper)
#pragma alloc_text(PAGE, PreCreateCallBack)
#pragma alloc_text(PAGE, PostCreateCallBack)
#endif


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

	// init this global var
	gNumofFileNeedScan = 0;
	
	status = FltStartFiltering(pRetFilter);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("Minifilter Driver: FAIL in start filtering. error 0x%x\r\n", status));
		FltUnregisterFilter(pRetFilter);
		return status;
	}

	// init the communicatio utility.
	KlInitCommunication();
	
	return STATUS_SUCCESS;
}

NTSTATUS FilterUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
	KdPrint(("ENTERING : %s\r\n", __FUNCTION__));
	KdPrint(("[KL]: the num of files needed to be scanned is : %d\n", gNumofFileNeedScan));
	UNREFERENCED_PARAMETER(Flags);
	KlFilterCommunicationUnload();
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
	//KdPrint(("--------------------------------------------\r\n"));
	//KdPrint(("[KernelLover]: entering %s", __FUNCTION__));

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
		//KdPrint(("[KernelLover]: it's a directory access. just fail\n"));
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}


	/* first skip the stack based file object */
	
	IoGetStackLimits(&stackLow, &stackHigh);
	if (((ULONG_PTR)FltObjects->FileObject < stackHigh) &&
		((ULONG_PTR)FltObjects->FileObject > stackLow)) // is it in the address range of my stack frame
	{
		KdPrint(("[KernelLover]: it's a stack based file object\n"));

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	/* also skip the pre-rename operation that open the parent directory : */
	if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY))
	{
		//KdPrint(("[KernelLover]: a pre-name operation just skip.\n"));

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	/* skip the paging files */
	if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE))
	{
		KdPrint(("[KernelLover]: a paging file open. \n"));

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	/* also skip the DASD (direct access storage device) open requests. */
	if (FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN))
	{
		KdPrint(("[KernelLover]: a DASD open request.\n"));

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	/* also skip the prefetch file open (we should flag it on a global structure to skip any incoming I/O operation to it. */
	if ( IsPrefetchEcpExist(Data) )
	{
		KdPrint(("[KernelLover]: a prefetch file creation from PreCreateCallback.\n"));
		SetFlag(objectContext.flags, KL_PREFETCH_FOUND_FLAG);
	}

	/* also skip the CSVFS request. (this is not mandatory because this AV won't run in a server). */
	if (IsCsvfsEcpExist(Data))
	{
		KdPrint(("[KernelLover]: a CSVFS open request.\n"));

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	/* let's skip also the request came from kernel mode at this moment. */
	if (Data->RequestorMode == KernelMode)
	{
		KdPrint(("[KernelLover]: request from kernel mode \n"));

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	/* ignore the NTFS repase point (RP) */
	if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_OPEN_REPARSE_POINT))
	{
		//KdPrint(("[KernelLover]: a NTFS repase point\n"));

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	/* let's try to print the name for the object file */

	pFltNameInfo = KlGetFileNameHelper(Data);

	if (pFltNameInfo != NULL)
	{
		//KdPrint(("[AV_MINIFILTER]: got a creation of a file \r\n"));
		//KdPrint(("[AV_MINIFILTER]: the name of the file is %wZ", &pFltNameInfo->Name));
		//PrintCreateDisposition(Data->Iopb->Parameters.Create.Options);
		//PrintCreateOptions(Data->Iopb->Parameters.Create.Options);
	}

	else
	{
		KdPrint(("[AV_MINIFILTER]: error: could not resolve the name of the file object. \r\n"));
	}

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
	NTSTATUS status;
	BOOLEAN isDir;
	ACCESS_MASK desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;

	KdPrint(("--------------------------------------------\r\n"));
	KdPrint(("[KernelLover]: ENTERING : %s\n", __FUNCTION__));

	/* first check if the create request is failed or not from NTFS */

	if (!NT_SUCCESS(Data->IoStatus.Status) ||
		Data->IoStatus.Status == STATUS_REPARSE)
	{
		// there's no file creation ...
		//KdPrint(("[KernelLover]: FILE CREATION FAILED. \n"));
		return FLT_POSTOP_FINISHED_PROCESSING;

	}

	/* check if it's a dir */
	status = FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &isDir);

	if (NT_SUCCESS(status) &&
		isDir)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	/* now check for file encryption open for backup */
	if( !FlagOn(desiredAccess, FILE_READ_DATA) &&
		!FlagOn(desiredAccess, FILE_WRITE_DATA) )
	{
		//
		// so now it's not a read or write to an encrypted file, let's then check if it's encrypted or not
		// and if so, we will ignore it because it's now a try to backup.
		// we will check it by reading the FileAttributes member to see it is = FILE_ATTRIBUTE_ENCRYPTED or not.
		//

		BOOLEAN isEncrypted = FALSE;
		status = KlCheckEncryptedFile(FltObjects, &isEncrypted);

		if (!NT_SUCCESS(status))
		{
			// so there's an error while getting the file attribute. just print an error message
			KdPrint(("[KernelLover]: ERROR KlCheckEncryptedFile failed !. \n"));
		}

		if (isEncrypted)
		{
			// so it's a request for backup, just skip
			KdPrint(("[KernelLover]: a request to backup encrypted file: %wZ", FltObjects->FileObject->FileName));

			return FLT_POSTOP_FINISHED_PROCESSING;
		}

	}
	
	// 
	// if the file object has ADS, I will just print a caution and pass, I won't scan it. 
	//

	BOOLEAN isContainAds = FALSE;
	status = KlIsFileHasADS(FltObjects, &isContainAds, Data);

	if (NT_SUCCESS(status))
	{
		if (isContainAds)
		{
			return FLT_POSTOP_FINISHED_PROCESSING;
		}
	}

	else // status failed.
	{ 
		KdPrint(("[kernelLover]: ERROR KlIsFileHasADS failed !. \n"));
	}


	// 
	// Now deal with the prefetch file. 
	// we should first flag it so if it did any I/O operation in the future we gonna skip it.
	// so we will flag it using the stream context handle, then skip the request do not scan it.
	// 
	// this going to be useful if you register for read and write IRPs. (I not going to register
	// read and write trace, but I will add this code for future updates.
	//

	if ( FlagOn((ULONG_PTR)CompletionContext, KL_PREFETCH_FOUND_FLAG) )
	{
		//
		// now it's a prefetch file.
		// check if it support stream handle context
		//

		status = FltSupportsStreamHandleContexts(FltObjects->FileObject);

		if (!NT_SUCCESS(status))
		{
			KdPrint(("[KernelLover]: stream handle context is not supported for this prefetch file object. \n"));
			return FLT_POSTOP_FINISHED_PROCESSING;
		}

		PKL_STREAMHANDLE_CONTEXT streamHandleContext;
		status = KlCreateStreamHandleContext(FltObjects, &streamHandleContext);

		if (!NT_SUCCESS(status))
		{
			KdPrint(("[KernelLover] : ERROR function KlCreateStreamHandleContext failed !. \n"));
			return FLT_POSTOP_FINISHED_PROCESSING;
		}

		// set the flags needed
		SetFlag(streamHandleContext->flags, KL_PREFETCH_FOUND_FLAG);

		// now set the new handle context
		status = FltSetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, FLT_SET_CONTEXT_KEEP_IF_EXISTS, streamHandleContext, NULL);
		

		// decrement the reference count for the context
		if (NULL != streamHandleContext)
			FltReleaseContext(streamHandleContext);
		
		// whether the set call succeded or not, we should decrement the reference count for the context
		if (!NT_SUCCESS(status))
		{
			KdPrint(("[KernelLover]: error while setting the new handle context for prefetech file, error code 0x%x", status));
		}

		return FLT_POSTOP_FINISHED_PROCESSING;
	
	}

	// 
	// now time for checking if there's a stream context or not for that file object
	// and create one if there's not.
	//
	PKL_STREAM_CONTEXT streamContext = NULL;
	PKL_STREAM_CONTEXT oldStreamContext = NULL;


	status = FltGetFileContext(FltObjects->Instance, FltObjects->FileObject, &streamContext);

	//
	// herer we have 3 options:
	// 1- the context is not supported
	// 2- there's no context attached to the file object
	// 3- the call success and we got a context.
	//

	// testing option 1 :

	if (status == STATUS_NOT_SUPPORTED)
	{
		KdPrint(("[KernelLover]: ERROR the context is not supported for this file object, just skipping.\n"));
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	// testing option 2 :
	else if (status == STATUS_NOT_FOUND)
	{
		// then we have to create one for it an attach it :
		status = KlCreateAndInitStreamContext(FltObjects, &streamContext);

		if (!NT_SUCCESS(status) || streamContext == NULL)
		{
			// so there's a fail in the create function, print an error message then exit:
			KdPrint(("[KernelLover]: ERROR function KlCreateAndInitStreamContext failed!.\n"));
			return FLT_POSTOP_FINISHED_PROCESSING;
		}
		//
		// and if not ..
		// then now we need to first try to see if it's loaded in cache or not (much faster)
		// this step is optional for this project.
		//

#ifdef KL_PERFORMANCE

		// first check if we can obtain the file id.
		KL_FILE_ID fileId;
		status = KlObtainFileId(FltObjects->FileObject, FltObjects->Instance, &fileId);

		if (!NT_SUCCESS(status))
		{
			// it's optional, we won't stop the scan.
			KdPrint(("[KL] ERROR: while calling function KlObtainFileId.\n"));
		}
		else
		{
			// now we should call a function to retrieve the file state from cache using FILE ID.
			status = KlGetFileStateFromCache();
		}
#endif

		// 
		// now we should set the new context to the file object ..
		//

		status = FltSetStreamContext(FltObjects->Instance, FltObjects->FileObject, FLT_SET_CONTEXT_KEEP_IF_EXISTS, 
			streamContext, &oldStreamContext);

		if (NT_SUCCESS(status))
			KdPrint(("[KL] SUCCESS: the new context is now set to the file : %wZ\n", FltObjects->FileObject->FileName));
		else
		{
			// JUST BEFORE WE SET THE NEW CONTEXT, SOMEONE DID.
			if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED)
			{
				//KdPrint(("[KL] WARNING: RACE CONDITION FOR FILE : %wZ\n", FltObjects->FileObject->FileName));
				
				FltReleaseContext(streamContext);

				// so to use it to decide whether it needs to be scanned or not.
				streamContext = oldStreamContext;
				
			}
			// some other error ..
			else
			{
				KdPrint(("[KL] ERROR: some unknown error happened while setting new context for file : %wZ.\n", FltObjects->FileObject->FileName));
				goto CLEAN;
			}
		}

	}

	// check if it's on scanning state;
	if (streamContext->fileState == KlFileScanning)
	{
		KdPrint(("the file is in the scanning state, just complete it.\n"));
		goto CLEAN;
	}

	// 
	// then check if it's an exe file ..
	//
	
	status = KlIsFileExectuable(Data, FltObjects->FileObject, streamContext);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[KL] ERROR: couldn't resolve if it's an exe or not.\n"));
		streamContext->isExeFile = FALSE; // JUST AVOID IT FOR NOW FOR TEST.
	}

	
	//
	// NOW IF THERE'S ALREADY CONTEXT ..
	// in this case we continue to work as usual.
	// 
	// Now we need to decide whether this file object need to be scanned or not.
	// we decide using two flags:
	// 1- if the file is modified since the last scan or not.
	// 2- if the file is exe file (not a reliable thing but just useful for our project.)
	//
	PFLT_FILE_NAME_INFORMATION pFileNameInfo = NULL;

	pFileNameInfo = KlGetFileNameHelper(Data);

	if (pFileNameInfo == NULL)
	{
		KdPrint(("[KL] ERROR: while trying to resolve the file name. \n"));
		goto CLEAN;
	}

	FltParseFileNameInformation(pFileNameInfo);


#ifdef DESKTOP

	if(pFileNameInfo != NULL)
		if ((wcsstr((pFileNameInfo->Name.Buffer), L"\\Desktop\\")) == NULL)
			streamContext->isFromDesktop = FALSE;
#endif

	if (streamContext->isFromDesktop)
		KdPrint(("[KL]this file is from desktop : %wZ\n", pFileNameInfo->Name));
	else
		KdPrint(("[KL] this file is NOT from DESKTOP : %wZ\n", pFileNameInfo->Name));



	if (KlIsFileNeedScan(streamContext))
	{ 
		BOOLEAN isInfected;
		SetFileScanning(streamContext->fileState); // set the scanning context

		POBJECT_NAME_INFORMATION objectNameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(OBJECT_NAME_INFORMATION), KL_MSDOS_FILE_NAME_TAG);

		// get the MSDOS FILE NAME
		status = IoQueryFileDosDeviceName(FltObjects->FileObject, &objectNameInfo);

		if (!NT_SUCCESS(status))
		{
			KdPrint(("[KL]ERROR: while calling IoQueryFileDosDeviceName.\n"));
		}
		else
		{
			KdPrint(("[KL]SUCCESS: the file name from IoQueryFileDosDeviceName is %wZ.\n", objectNameInfo->Name));
		}

		status = KlSendFileToEngine(objectNameInfo->Name, &isInfected);


		if (NT_SUCCESS(status))
		{
			if (isInfected)
			{
				SetFileInfected(streamContext->fileState);
				KdPrint(("[KL] this file name flaged as infected : %wZ\n", pFileNameInfo->Name));
			}

			else
			{
				SetFileCleared(streamContext->fileState);
				KdPrint(("[KL] this file name flaged as cleared: %wZ\n", pFileNameInfo->Name));
			}

			KdPrint(("[KL] NOTE: SCAN FINISHED.\n"));
		}
		else
			KdPrint(("[KL] ERROR: KlSendFileToEngine function failed.\n"));

		gNumofFileNeedScan++;

		if (objectNameInfo != NULL)
			ExFreePoolWithTag(objectNameInfo, KL_MSDOS_FILE_NAME_TAG);
	}
	else
		KdPrint(("[KL] NOTE: this file : %wZ DOES NOT need to be scanned.\n", FltObjects->FileObject->FileName));


	if (KlIsFileInfected(streamContext->fileState))
	{
		KdPrint(("this file is infected. don't open it : %wZ\n", pFileNameInfo->Name));
		// do farther actions...
		FltCancelFileOpen(FltObjects->Instance, FltObjects->FileObject);

		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		Data->IoStatus.Information = 0;

		KdPrint(("[KL] SUCCESS: the file open is failed succesfully.\n"));
	}

	else
	{
		KdPrint(("[KL] the file is safe to open.\n"));
		Data->IoStatus.Status = STATUS_SUCCESS;
		Data->IoStatus.Information = 0;
	}

	if (pFileNameInfo != NULL)
		FltReleaseFileNameInformation(pFileNameInfo);

	goto CLEAN;

	//KdPrint(("Try to print the context ... \n"));

	//KdPrint(("Data is : %d \n", (ULONG_PTR)CompletionContext ));

CLEAN:
	FltReleaseContext(streamContext);
	return FLT_POSTOP_FINISHED_PROCESSING;
	
}


FLT_PREOP_CALLBACK_STATUS
PreWriteandSetInfoCallBack(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
	//
	// the PRE write and set file info callback routine..
	//

	NTSTATUS status;
	PKL_STREAMHANDLE_CONTEXT streamHandleContext = NULL;
	PKL_STREAM_CONTEXT streamContext = NULL;

	KdPrint(("[KL] ENTERING : %s\n", __FUNCTION__));

	if (!KlOperationsModifyingFile(Data)) {

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	status = FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, &streamHandleContext);

	// if there's a stream handle context .. (PREFETECH FILE ..)
	if(NT_SUCCESS(status))
		if (FlagOn(streamHandleContext->flags, KL_PREFETCH_FOUND_FLAG))
		{
			FltReleaseContext(streamHandleContext);
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}

	// now get the stream context it self
	status = FltGetStreamContext(FltObjects->Instance, FltObjects->FileObject, &streamContext);

	if (NT_SUCCESS(status))
	{
		KdPrint(("[KL] now setting the file to be modified.\n"));
		
		SetFileModified(streamContext->fileState);
		
		FltReleaseContext(streamContext);
	} else // no stream context, it's an error
	{
		KdPrint(("[KL]ERROR: can't find a stream context for that file.\n"));
	}

	return FLT_PREOP_SUCCESS_NO_CALLBACK;

}

PFLT_FILE_NAME_INFORMATION KlGetFileNameHelper(PFLT_CALLBACK_DATA Data)
{

/* ROUTINE EXPLAINATION:
	- this routine retrive the info about the object file name represented in FLT_FILE_NAME_INFORMATION.
	
	PARAMETERS:
		-Data: to get the file object from it.
		
	RETURN:
		- pointer to FLT_FILE_NAME_INFORMATION: if it could find one (whether it's normalized or opened file name.
		- NULL: if it couldn't find one.
*/
	//KdPrint(("ENTERING : %s \r\n", __FUNCTION__));

	NTSTATUS status;
	PFLT_FILE_NAME_INFORMATION pFltNameInfo = NULL;

	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP | FLT_FILE_NAME_NORMALIZED, &pFltNameInfo);
	
	/*
	WE ARE GOING TO FIRST GET THE NORMALIZED FILE NAME, IF IT FAILED, THEN WE WILL GET THE OPENED FILE NAME
	(BY OF COURSE CHANGING THE FLAGS USED)
	*/

	//failed to get the normalized name, now try to get the open name : 
	if (!NT_SUCCESS(status))
	{
		status = FltGetFileNameInformation(Data, FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP | FLT_FILE_NAME_OPENED, &pFltNameInfo);

		if(NT_SUCCESS(status))
			return pFltNameInfo; // return the opened file name
		
		return NULL;
	}

	return pFltNameInfo; // return the normalized name
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

NTSTATUS KlCheckEncryptedFile(PCFLT_RELATED_OBJECTS FltObjects, PBOOLEAN isEncrypted)
{
	NTSTATUS status;
	FILE_BASIC_INFORMATION  fileInfo;

	status = FltQueryInformationFile(FltObjects->Instance, FltObjects->FileObject, (PVOID)&fileInfo, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation, NULL);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("[KernelLover]: ERROR while getting the FILE_BASIC_INFORMATION \n"));
		return status;
	}

	*isEncrypted = (BOOLEAN)( (fileInfo.FileAttributes & FILE_ATTRIBUTE_ENCRYPTED) != 0);

	return status;
}

NTSTATUS KlIsFileHasADS(PCFLT_RELATED_OBJECTS FltObjects, PBOOLEAN isContainAds, PFLT_CALLBACK_DATA Data)
{
	NTSTATUS status;
	PFLT_FILE_NAME_INFORMATION pFileNameInfo = NULL;

	// first get the file name : 
	pFileNameInfo = KlGetFileNameHelper(Data);
	
	if (pFileNameInfo == NULL)
		return STATUS_UNSUCCESSFUL;
	status = FltParseFileNameInformation(pFileNameInfo);

	if (NT_SUCCESS(status))
	{
	//	KdPrint(("file name analysis to check if there are ADS or not. \n"));
		//KdPrint(("File Name : %wZ, volume : %wZ, extension : %wZ, stream : %wZ\n", pFileNameInfo->Name, 
		//																		   pFileNameInfo->Volume,
		//																		   pFileNameInfo->Extension, 
		//																		   pFileNameInfo->Stream));
		*isContainAds = (BOOLEAN)(pFileNameInfo->Stream.Length != 0);

	}

	// do a clean up :
	if (pFileNameInfo != NULL) // just to make sure ..
		FltReleaseFileNameInformation(pFileNameInfo);

	return status;
}


NTSTATUS KlObtainFileId(_In_ PFILE_OBJECT FileObject, PFLT_INSTANCE Instance,_Out_ PKL_FILE_ID FileId)
{
	NTSTATUS status;
	FLT_FILESYSTEM_TYPE FileSystemType = { 0 };
	//
	// so first we need to know which file system is used to choose whether to use file id 128 or 64.
	//
	status = FltGetFileSystemType(Instance, &FileSystemType);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("[KL] ERROR: in function %s, couldn't call FltGetFileSystemType.\n", __FUNCTION__));
		return status;
	}
	
	// REFS only support file id 128
	if (FileSystemType == FLT_FSTYPE_REFS)
	{
		FILE_ID_INFORMATION FileIdInfo128;
		status = FltQueryInformationFile(Instance, FileObject, &FileIdInfo128, sizeof(FILE_ID_INFORMATION), FileIdInformation, NULL);

		// now move the result.
		RtlCopyMemory(&(FileId->FileId128), &(FileIdInfo128.FileId), sizeof(FileId->FileId128));

	}

	else
	{ 
		// now it's another file system type, which is normaly uses file id 64.
		
		FILE_INTERNAL_INFORMATION FileIdInfo64;
		
		status = FltQueryInformationFile(Instance, FileObject, &FileIdInfo64, sizeof(FILE_INTERNAL_INFORMATION), FileInternalInformation, NULL);
		
		RtlCopyMemory(&(FileId->Fields.value64), &(FileIdInfo64.IndexNumber), sizeof(FileId->Fields.value64));
		FileId->Fields.upperZeroes = 0ll; // to fit the whole 64 bit;
	}

	if (!NT_SUCCESS(status))
		KdPrint(("[KL] ERROR: in function : %s, from function FltQueryInformationFile.\n", __FUNCTION__));

	return status;
}

NTSTATUS KlIsFileExectuable(_In_ PFLT_CALLBACK_DATA Data ,_In_ PFILE_OBJECT FileObject, _Out_ PKL_STREAM_CONTEXT StreamContext)
{
	NTSTATUS status;
	UNICODE_STRING fileExtensionCheck;

	//
	// we can check in it's file name if it contain the .exe extension or not, but we will use another better and 
	// reliable way.
	//
	PFLT_FILE_NAME_INFORMATION FileNameInfo = NULL;
	FileNameInfo = KlGetFileNameHelper(Data);

	if (FileNameInfo == NULL)
		return STATUS_UNSUCCESSFUL;
	status = FltParseFileNameInformation(FileNameInfo);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("[KL] ERROR: failed to get file name info in function : %s.\n", __FUNCTION__));
		return status;
	}
	RtlInitUnicodeString(&fileExtensionCheck, L"exe");

	// now do the check ..
	StreamContext->isExeFile = RtlEqualUnicodeString(&FileNameInfo->Extension, &fileExtensionCheck, TRUE);

	if (FileNameInfo != NULL) // just to make sure ..
		FltReleaseFileNameInformation(FileNameInfo);

	return status;

}


NTSTATUS KlGetFileStateFromCache()
{

	return STATUS_SUCCESS;
}

void KlStreamContextCleanUp(
	_In_ PFLT_CONTEXT Context,
	_In_ FLT_CONTEXT_TYPE ContextType
)
{
	UNREFERENCED_PARAMETER(ContextType);

	// because we may access paged data ..
	PAGED_CODE();

	// in our case, we only allocated space for KEVENT, we just need to deallocate it.
	PKL_STREAM_CONTEXT streamContext = (PKL_STREAM_CONTEXT)Context;

	ExFreePoolWithTag(streamContext->event, KL_KEVENT_TAG);

}


NTSTATUS KlCreateAndInitStreamContext(PCFLT_RELATED_OBJECTS FltObjects, PKL_STREAM_CONTEXT* retStreamContext)
{
	NTSTATUS status;
	PKL_STREAM_CONTEXT streamContext;

	//
	// now we need to initialize the members of the stream context,
	// but first, we need to create a synchronization event to make sure
	// that there's no race condition happens in the future 
	//

	// first allocate a space for it in a nonpagedpool
	PKEVENT allocatedKevent = NULL;
	allocatedKevent = (PKEVENT)ExAllocatePoolZero(NonPagedPool, sizeof(KEVENT), KL_KEVENT_TAG);
	if (allocatedKevent == NULL)
	{
		// so there's no sufficient memory :
		KdPrint(("[KernelLover]: ERROR while allocating a pool for KEVENT, no sufficient memory. \n"));
		return STATUS_UNSUCCESSFUL;
	}


	// the event is created well ..
	status = FltAllocateContext(pRetFilter, FLT_STREAM_CONTEXT, KL_STREAM_CONTEXT_SIZE, PagedPool, &streamContext);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("[KernelLover]: ERROR while while allocating a new context. error code : 0x%x\n", status));

		// do a clean up :
		ExFreePoolWithTag((PVOID)allocatedKevent, KL_KEVENT_TAG);

		return status;
	}

	RtlZeroMemory(streamContext, KL_STREAM_CONTEXT_SIZE);


	// now init the members:
	streamContext->event = allocatedKevent;

	// create the event :
	KeInitializeEvent(streamContext->event, SynchronizationEvent, TRUE);

	// we gonna make it modified because we are creating a new context for that new stream.
	SetFileModified(streamContext->fileState);
	// BY DEFAULT
	streamContext->isExeFile = FALSE;
	streamContext->isFromDesktop = TRUE;
	streamContext->flags = 0;

	*retStreamContext = streamContext;

	return status;
}

NTSTATUS KlCreateStreamHandleContext(PCFLT_RELATED_OBJECTS FltObjects, PKL_STREAMHANDLE_CONTEXT* retContext)
{
	NTSTATUS status;
	// first allocate the conext
	PKL_STREAMHANDLE_CONTEXT context;
	status = FltAllocateContext(pRetFilter, FLT_STREAMHANDLE_CONTEXT, KL_STREAMHANDLE_CONTEXT_SIZE, PagedPool, &context);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("[KernelLover]- [KlCreateStreamHandleContext] : error while trying to allocate context. error code 0x%x", status));
		return status;
	}

	// initialize that allocated memory

	RtlZeroMemory(context, KL_STREAMHANDLE_CONTEXT_SIZE);


	// let's just now return the context and make the caller set it to the object.
	*retContext = context;

	return status;
}


BOOLEAN IsPrefetchEcpExist(PFLT_CALLBACK_DATA Data)
{
	/* ROUTINE EXPLAINATION:
		- it finds if the prefetch GUID is existed in the ECP_LIST, if there's and ECP_LIST in the first place.

		PARAMETERS:
			- Data: a pointer to FLT_CALLBACK_DATA structure to get the file object

		RETURN:
			-TRUE: found the ECP context.
			-FALSE: not found.
	*/
	//KdPrint(("Entering function : %s", __FUNCTION__));
	NTSTATUS status;
	PECP_LIST ecpList = NULL;
	PVOID ecpContext = NULL;
	status = FltGetEcpListFromCallbackData(pRetFilter, Data, &ecpList);

	if ((NT_SUCCESS(status)) && (NULL != ecpList))
	{
		status = FltFindExtraCreateParameter(pRetFilter, ecpList, &GUID_ECP_PREFETCH_OPEN, &ecpContext, NULL);
		if (NT_SUCCESS(status))
		{
			if (!FltIsEcpFromUserMode(pRetFilter, ecpContext))
				return TRUE;
		}

	}

	return FALSE; // there's no ECP_LIST in the first place or can't find the ecp context.
}

BOOLEAN IsCsvfsEcpExist(PFLT_CALLBACK_DATA Data)
{
	/* ROUTINE EXPLAINATION:
		- it finds if the Csvfs GUID is existed in the ECP_LIST, if there's and ECP_LIST in the first place.

		PARAMETERS:
			- Data: a pointer to FLT_CALLBACK_DATA structure to get the file object
			- Guid: a pointer to a GUID to search for the ECP_CONTEXT.

		RETURN:
			-TRUE: found the ECP context.
			-FALSE: not found.
	*/
//	KdPrint(("Entering function : %s", __FUNCTION__));
	NTSTATUS status;
	PECP_LIST ecpList = NULL;
	status = FltGetEcpListFromCallbackData(pRetFilter, Data, &ecpList);

	if ((NT_SUCCESS(status)) && (NULL != ecpList))
	{
		status = FltFindExtraCreateParameter(pRetFilter, ecpList, &GUID_ECP_CSV_DOWN_LEVEL_OPEN, NULL, NULL);
		if (NT_SUCCESS(status))
		{
			return TRUE;
		}

	}

	return FALSE; // there's no ECP_LIST in the first place or can't find the ecp context.
}

NTSTATUS KlIsFromDesktop(PFLT_FILE_NAME_INFORMATION pFileNameInfo, PBOOLEAN IsFromDesktop)
{
	BOOLEAN fromDesk;

	if (pFileNameInfo->Name.Buffer == NULL)
	{ 
		*IsFromDesktop = FALSE;
		return STATUS_UNSUCCESSFUL;
	}

	if ((wcsstr(pFileNameInfo->Name.Buffer, L"Desktop\\")) != NULL)
		fromDesk = TRUE;
	else
		fromDesk = FALSE;

	*IsFromDesktop = fromDesk;

	return STATUS_SUCCESS;
}

BOOLEAN
KlOperationsModifyingFile(
	_In_ PFLT_CALLBACK_DATA Data
)
/*++

Routine Description:

	This identifies those operations we need to set the file to be modified.

Arguments:

	Data - Pointer to the filter callbackData that is passed to us.

Return Value:

	TRUE - If we want the file associated with the request to be modified.
	FALSE - If we don't

--*/
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

	PAGED_CODE();

	switch (iopb->MajorFunction) {

	case IRP_MJ_WRITE:
		return TRUE;

	case IRP_MJ_FILE_SYSTEM_CONTROL:
		switch (iopb->Parameters.FileSystemControl.Common.FsControlCode) {
		case FSCTL_OFFLOAD_WRITE:
		case FSCTL_WRITE_RAW_ENCRYPTED:
		case FSCTL_SET_ZERO_DATA:
			return TRUE;
		default: break;
		}
		break;

	case IRP_MJ_SET_INFORMATION:
		switch (iopb->Parameters.SetFileInformation.FileInformationClass) {
		case FileEndOfFileInformation:
		case FileValidDataLengthInformation:
			return TRUE;
		default: break;
		}
		break;
	default:
		break;
	}
	return FALSE;
}

//
// in this function, we should clean up every allocated space that's done in the context creation.
//


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