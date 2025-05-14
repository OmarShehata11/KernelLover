#include <ntddk.h>
#include <wdm.h>
#include "DriverHeader.h"
#include "MemoryHeader.h"
#include "vmxHeader.h"


EXTERN_C_START;


/* Driver Entry */
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING);

/* Driver Unload routine */
VOID DriverUnload(PDRIVER_OBJECT DriverObject);


EXTERN_C_END;
/* dispatch routines */


/* local functions */
int HvMathPower(int base, int exp);

#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverUnload)


NTSTATUS DriverClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DriverCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DriverRead(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DriverWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DriverControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

/* note:
		it's not a good practicse*/
/* GLOBAL */

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING)
{
	KdPrint(("[HYPERVISOR]: ENTER %s", __FUNCTION__));

	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_OBJECT DeviceObject;
	UNICODE_STRING DeviceName, SymLink;


	RtlInitUnicodeString(&DeviceName, L"\\Device\\HypervisorTest");
	RtlInitUnicodeString(&SymLink, L"\\??\\HypervisorTest");

	IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
	IoCreateSymbolicLink(&SymLink, &DeviceName);

	DriverObject->DriverUnload = DriverUnload;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverClose;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreate;
	DriverObject->MajorFunction[IRP_MJ_READ] = DriverRead;
	DriverObject->MajorFunction[IRP_MJ_WRITE] = DriverWrite;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverControl;

	/*
	DriverObject->Flags |= IO_TYPE_DEVICE;
	DriverObject->Flags &= (~DO_DEVICE_INITIALIZING);
	*/

	PHV_EPTP lpEptp = NULL;
	HV_VIRTUAL_MACHINE_STATE VirtualMachineState;
	status = HvInitPageTables(&lpEptp, &VirtualMachineState.GuestVirtualMemAddress);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("[HV] ERROR: the init for the page tables has failed. \n"));
		goto FinishCall;
	}

	KdPrint(("[HV] SUCCESS: the page tables are initialized correctly.\n"));

	status = HvInitVmx();

	if (!NT_SUCCESS(status))
	{
		KdPrint(("[HV]: ERROR HvInitVmx failed.\n"));
	}
	else
	{
		KdPrint(("[HV]: SUCCESS the init process.\n"));
	}

	// now fill the guest memory with the HLT instruction : \xf4
	
	/*
	PVOID Instruction = "\xF4";  // HLT instruction
	for (int i = 0; i < (HV_GUEST_MEMORY_SIZE - 1); i++)
	{
		memcpy_s((PVOID)((UINT64)(VirtualMachineState.GuestVirtualMemAddress) + 1), HV_GUEST_MEMORY_SIZE, Instruction, 1);
	}
	*/

	// we will run our VM on the first core only
	BOOLEAN isSuccess = HvLaunchVm(1);

	if (!isSuccess)
	{
		KdPrint(("[HV]: ERROR HvLaunchVm failed.\n"));
	}
	else
	{
		KdPrint(("[HV]: SUCCESS HvLaunchVm succeded.\n"));
	}

	goto FinishCall;

FinishCall:
	/* I should not but I will try ...*/
	return status;
}

void DriverUnload(PDRIVER_OBJECT DriverObject)
{
	KdPrint(("[HYPERVISOR]: ENTER %s", __FUNCTION__));

	UNICODE_STRING SymLink;
	RtlInitUnicodeString(&SymLink, L"\\??\\HypervisorTest");

	IoDeleteSymbolicLink(&SymLink);
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS DriverClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	KdPrint(("[HYPERVISOR]: ENTER %s", __FUNCTION__));

	UNREFERENCED_PARAMETER(DeviceObject);
	NTSTATUS status;

	status = HvVmxExit();
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[HV]: FAILED VmxExit failed.\n"));
	}
	else
	{
		KdPrint(("[HV]: SUCCESS vmxExit is done broo\n"));
	}

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DriverCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	KdPrint(("[HYPERVISOR]: ENTER %s", __FUNCTION__));

	UNREFERENCED_PARAMETER(DeviceObject);


	goto FinishCall;

FinishCall:
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DriverRead(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	KdPrint(("[HYPERVISOR]: ENTER %s", __FUNCTION__));

	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DriverWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	KdPrint(("[HYPERVISOR]: ENTER %s", __FUNCTION__));

	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;

}

NTSTATUS DriverControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) 
{
	PAGED_CODE();
	//KAFFINITY kAffinity;

	KdPrint(("[HYPERVISOR]: ENTER %s", __FUNCTION__));
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	UNREFERENCED_PARAMETER(DeviceObject);

	PHV_BUFFER lpBuffer = NULL;
	PIO_STACK_LOCATION stackLocation = NULL;
	stackLocation = IoGetCurrentIrpStackLocation(Irp);
	
	// first check the size ..
	if (stackLocation->Parameters.DeviceIoControl.InputBufferLength < HV_BUFFER_SIZE)
	{
		KdPrint(("[HV]: error, the size of input or output buffer is small.\n"));
		goto TheEnd;
	}

	// Then check the value ..
	switch (stackLocation->Parameters.DeviceIoControl.IoControlCode)
	{
	case HV_CTL_CODE:
		// try to print the buffered data he passed to us :

		lpBuffer = (PHV_BUFFER)Irp->AssociatedIrp.SystemBuffer;

		KdPrint(("the passed data is : %ws\n", lpBuffer->Buffer));
		status = STATUS_SUCCESS;
		break;

	default:
		KdPrint(("[HV]: error, the passed ctl code is unknown.\n"));
		break;
	}

	goto TheEnd;

TheEnd:
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
