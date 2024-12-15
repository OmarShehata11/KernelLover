#include <ntddk.h>
#include <wdm.h>
#include <string.h>

/*
	THIS MODULE WILL ONLY FOCUS ON MONITORING THE PROCESS CREATION BY USING KERNEL CALLBACKS.
*/

void DriverUnload(_In_ DRIVER_OBJECT* DriverObject);
NTSTATUS CreateCloseCallback(PDEVICE_OBJECT DeviceObject, PIRP Irp);
void ProcessNotifyCallback(PEPROCESS process, HANDLE hProcess, PPS_CREATE_NOTIFY_INFO createInfo);


extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING)
{
	NTSTATUS status = STATUS_SUCCESS;

	KdPrint(("[KernelLover] Entering %s\n", __FUNCTION__));
	UNICODE_STRING DeviceName;
	UNICODE_STRING SymbLink;

	DEVICE_OBJECT *DeviceObject;

	RtlInitUnicodeString(&DeviceName, L"\\Device\\KernelLover");
	RtlInitUnicodeString(&SymbLink, L"\\??\\KernelLover");

	status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, NULL, false, &DeviceObject);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("[KernelLover] ERROR: while Creating the device object.\n"));
		return status;
	}

	status = IoCreateSymbolicLink(&SymbLink, &SymbLink);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("[KernelLover] ERROR: while Creating the Symbolic link.\n"));
		IoDeleteDevice(DeviceObject);
		return status;
	}

	DriverObject->DriverUnload = DriverUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateCloseCallback;

	status = PsSetCreateProcessNotifyRoutineEx((PCREATE_PROCESS_NOTIFY_ROUTINE_EX) ProcessNotifyCallback, FALSE);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("[KernelLover] ERROR: while registering for process creating event.\n"));
		IoDeleteDevice(DeviceObject);
		IoDeleteSymbolicLink(&SymbLink);
		return status;
	}

	return status;
}

void DriverUnload(_In_ DRIVER_OBJECT *DriverObject)
{
	KdPrint(("[KernelLover] Entering %s\n", __FUNCTION__));

	UNICODE_STRING SymbLink;
	RtlInitUnicodeString(&SymbLink, L"\\??\\KernelLover");

	PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, TRUE);

	IoDeleteDevice(DriverObject->DeviceObject);
	IoDeleteSymbolicLink(&SymbLink);

}

NTSTATUS CreateCloseCallback(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	KdPrint(("[KernelLover] Entering %s\n", __FUNCTION__));

	Irp->IoStatus.Status= STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

void ProcessNotifyCallback(PEPROCESS process, HANDLE hProcess, PPS_CREATE_NOTIFY_INFO createInfo)
{
	KdPrint(("[KernelLover] Entering %s\n", __FUNCTION__));

	UNREFERENCED_PARAMETER(hProcess);
	UNREFERENCED_PARAMETER(process);

	// just print the exe file name :
	if (createInfo != NULL)
	{
		createInfo->CreationStatus = STATUS_SUCCESS;
		if (!createInfo->IsSubsystemProcess)
		{ 
			KdPrint(("[KernelLover] catched a process creation : %ws.\n", createInfo->ImageFileName->Buffer));
			if (wcsstr(createInfo->ImageFileName->Buffer, L"omarahmed.exe") != NULL)
			{
				KdPrint(("[KernelLover] reporting process creation.\n"));
				createInfo->CreationStatus = STATUS_ACCESS_DENIED;
			}
		}
	}
}



/*
NOTES:
	- I can't register a callback for file creation, this needs a filter driver; but I can register for process creation, and I will
	firstly check the file on disk, then check the process after it loads. 
	
	- I can't control the process when it request to start, to stop it and so, I can only analyze it after it starts. 

	- for my project I would need two modules, a mini-filter driver that monitor the file access and so, and a kernel drive 
	that monitor the process creation.

	- I'm going to use the INVERTED CALL MODEL to notify the user-mode engine about any new notifications.

	- you can prevent the process from being created using the member value (processInfo->CreationStatus).



*/