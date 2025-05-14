#include <ntddk.h>
#include <wdm.h>
#include <intrin.h>
#include "DriverHeader.h"
#include "MemoryHeader.h"

/* global */

PVOID HvFromPhysicalToVirtual(UINT64 physicalQuadPart)
{
	KdPrint(("[HV]: ENTERING %s", __FUNCTION__));

	PHYSICAL_ADDRESS physicalAddress;
	
	physicalAddress.QuadPart = physicalQuadPart;

	return MmGetVirtualForPhysical(physicalAddress);
}

UINT64 HvFromVirtualToPhysical(VOID *BaseAddress)
{
	KdPrint(("[HV]: ENTERING %s", __FUNCTION__));

	return MmGetPhysicalAddress(BaseAddress).QuadPart;
}

// 
// to allocate the vmxon region :
//

NTSTATUS HvAllocateVmxonRegion(PHV_VIRTUAL_MACHINE_STATE VMState)
{
	KdPrint(("[HV]: ENTERING %s", __FUNCTION__));

	PHYSICAL_ADDRESS physicalAddress = { 0 };
	physicalAddress.QuadPart = MAXULONG64;
	SIZE_T bufferSize = HV_VMXON_REGION_SIZE * 2; // 4096 * 2

	// at IRQL > DISPATCH_LEVEL memory allocation routines don't work
	if (KeGetCurrentIrql() > DISPATCH_LEVEL)
		KeRaiseIrqlToDpcLevel();

	PVOID Buffer = MmAllocateContiguousMemory(bufferSize + HV_VMXON_REGION_PADDING, physicalAddress);
	if (Buffer == NULL)
	{
		KdPrint(("[HV]: ERROR, could not allocate contiguous memory space for the vmxon region. \n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	

	// init the allocated memory :

	RtlSecureZeroMemory(Buffer, bufferSize);

	// now we need the physical address :
	PHYSICAL_ADDRESS vmxonPhysicalAddress;
	vmxonPhysicalAddress.QuadPart = HvFromVirtualToPhysical(Buffer);

	// now let's ensure that the address is 4-KB alligned with the math trick (with both physical and virtual address):
	ULONG64 allignedPhysicalAddress = (ULONG64)(ULONG_PTR)((vmxonPhysicalAddress.QuadPart + HV_VMXON_REGION_PADDING - 1) & ~(HV_VMXON_REGION_PADDING - 1));
	ULONG64 allignedVirtualAddress = (ULONG64)(ULONG_PTR)(((ULONG64)Buffer + HV_VMXON_REGION_PADDING - 1) & ~(HV_VMXON_REGION_PADDING - 1));

	// PRINT IT OUT:
	KdPrint(("[HV]: SUCCESS, the virtual address for vmxon region : %p", Buffer));
	KdPrint(("[HV]: SUCCESS, the alligned virtual address for vmxon region : %llx", allignedVirtualAddress));
	KdPrint(("[HV]: SUCCESS, the alligned physical address for vmxon region : %llx", allignedPhysicalAddress));

	// now we should store the vmcs revision identifier in the vmxon region :
	HV_IA32_VMX_BASIC msrVmxBasic = { 0 };
	msrVmxBasic.AllValues = __readmsr(HV_MSR_IA23_VMX_BASIC);

	// now submit the value inside the vmxon region :
	*(ULONG64*)allignedVirtualAddress = msrVmxBasic.Fields.VmcsRevisionId;

	int status = __vmx_on(&allignedPhysicalAddress);

	if (status == 0)
		KdPrint(("[HV]: SUCCESS, THE vmxon instruction successed. \n"));
	else
	{
		KdPrint(("[HV]: FAIL, the vmxon instruction failed. \n"));
		return STATUS_UNSUCCESSFUL;
	}

	VMState->VmxonRegion = allignedPhysicalAddress;

	return STATUS_SUCCESS;
}

NTSTATUS HvInitVmcsRegion(PHV_VIRTUAL_MACHINE_STATE VMState)
{
	KdPrint(("[HV]: ENTERING %s", __FUNCTION__));

	// at IRQL > DISPATCH_LEVEL memory allocation routines don't work
	if (KeGetCurrentIrql() > DISPATCH_LEVEL)
		KeRaiseIrqlToDpcLevel();
	
	SIZE_T regionSize = HV_VMCS_REGION_SIZE * 2;
	PHYSICAL_ADDRESS physicalAddress;

	physicalAddress.QuadPart = MAXULONG64;
	
	PVOID regionVirtualAddress = MmAllocateContiguousMemory(regionSize + HV_VMCS_REGION_PADDING, physicalAddress);

	if (regionVirtualAddress == NULL)
	{
		KdPrint(("[HV]: ERROR, can't allocate memory for vmcs region. returning. \n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// now get the physical address
	physicalAddress.QuadPart = HvFromVirtualToPhysical(regionVirtualAddress);

	// to try to make sure that the memory is alligned with the math trick again ..
	ULONG64 allignedPhysicalAddress = (ULONG64)(ULONG_PTR)((physicalAddress.QuadPart + HV_VMCS_REGION_PADDING - 1) & ~(HV_VMCS_REGION_PADDING - 1));
	ULONG64 allignedVirtualAddress = (ULONG64)(ULONG_PTR)(((ULONG64)regionVirtualAddress + HV_VMCS_REGION_PADDING - 1) & ~(HV_VMCS_REGION_PADDING - 1));

	// get the vmcs revision id
	HV_IA32_VMX_BASIC msr;
	msr.AllValues = __readmsr(HV_MSR_IA23_VMX_BASIC);


	// now set the values inside vmcs region 
	*(ULONG64*)allignedVirtualAddress = msr.Fields.VmcsRevisionId;

	unsigned char retValue = __vmx_vmptrld(&allignedPhysicalAddress);

	if (retValue == 0)
	{
		KdPrint(("[HV]: SUCCES, the VMPTRLD is well.\n"));
	}
	else
	{
		KdPrint(("[HV]: FAIL, the VMPTRLD failed!.\n"));
		return STATUS_UNSUCCESSFUL;
	}

	VMState->VmcsRegion = allignedPhysicalAddress;

	return STATUS_SUCCESS;
}

NTSTATUS HvInitPageTables(_Out_ PHV_EPTP *tablePointerRet, _Out_ PVOID *GuestMemAddressRet)
{
	PAGED_CODE();

	PHV_EPTP TablePointer = (PHV_EPTP) ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, HV_EPTP_TAG);
	if (TablePointer == NULL)
	{
		KdPrint(("[HV] ERROR: while allocat space for eptp \n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	PHV_EPT_PDE pdeTable = (PHV_EPT_PDE)ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, HV_EPT_PDE_TAG);
	if (pdeTable == NULL)
	{
		KdPrint(("[HV] ERROR: while allocat space for PDE \n"));
		
		ExFreePoolWithTag(TablePointer, HV_EPTP_TAG);

		return STATUS_INSUFFICIENT_RESOURCES;
	}

	PHV_EPT_PDPTE pdpteTable = (PHV_EPT_PDPTE)ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, HV_EPT_PDPTE_TAG);
	if (pdpteTable == NULL)
	{
		KdPrint(("[HV] ERROR: while allocat space for PDPTE \n"));

		ExFreePoolWithTag(TablePointer, HV_EPTP_TAG);
		ExFreePoolWithTag(pdeTable, HV_EPT_PDE_TAG);

		return STATUS_INSUFFICIENT_RESOURCES;
	} 

	PHV_EPT_PML4E pmleTable = (PHV_EPT_PML4E)ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, HV_EPT_PML4E_TAG);
	if (pmleTable == NULL)
	{
		KdPrint(("[HV] ERROR: while allocat space for PML4E \n"));

		ExFreePoolWithTag(TablePointer, HV_EPTP_TAG);
		ExFreePoolWithTag(pdeTable, HV_EPT_PDE_TAG);
		ExFreePoolWithTag(pdpteTable, HV_EPT_PDPTE_TAG);


		return STATUS_INSUFFICIENT_RESOURCES;
	}
	
	PHV_EPT_PTE pteTable = (PHV_EPT_PTE)ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, HV_EPT_PTE_TAG);
	if (pteTable == NULL)
	{
		KdPrint(("[HV] ERROR: while allocat space for PTE \n"));

		ExFreePoolWithTag(TablePointer, HV_EPTP_TAG);
		ExFreePoolWithTag(pdeTable, HV_EPT_PDE_TAG);
		ExFreePoolWithTag(pdpteTable, HV_EPT_PDPTE_TAG);
		ExFreePoolWithTag(pmleTable, HV_EPT_PML4E_TAG);


		return STATUS_INSUFFICIENT_RESOURCES;
	}

	//
	// now we should allocate space in the guest memory space
	// 2 pages, 1 for data that's gonna be used by RIP,
	// and anothe for data going to be used with RSP.
	// but we will allocate 10 pages with 4-kb alligned
	//

	PVOID guestMem = ExAllocatePool2(POOL_FLAG_NON_PAGED, HV_GUEST_MEMORY_SIZE, HV_GUEST_MEM_TAG);

	if (guestMem == NULL)
	{
		KdPrint(("[HV] ERROR : while allocating space for Guest Memory\n"));

		ExFreePoolWithTag(TablePointer, HV_EPTP_TAG);
		ExFreePoolWithTag(pdeTable, HV_EPT_PDE_TAG);
		ExFreePoolWithTag(pdpteTable, HV_EPT_PDPTE_TAG);
		ExFreePoolWithTag(pmleTable, HV_EPT_PML4E_TAG);
		ExFreePoolWithTag(pteTable, HV_EPT_PTE_TAG);

		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(guestMem, HV_GUEST_MEMORY_SIZE);

	*GuestMemAddressRet = guestMem;

	// now init like every page in the PTE :
	for (int i = 0; i < HV_GUEST_MEMORY_NUM_OF_PAGES; i++)
	{
		pteTable[i].Fields.AccessedFlag = 0;
		pteTable[i].Fields.DirtyFlag = 0;
		pteTable[i].Fields.EPTMemoryType = 6;
		pteTable[i].Fields.Execute = 1;
		pteTable[i].Fields.ExecuteForUserMode = 0;
		pteTable[i].Fields.IgnorePAT = 0;
		pteTable[i].Fields.PhysicalAddress = (HvFromVirtualToPhysical( (PVOID)((UINT64)guestMem + (i * PAGE_SIZE) )) / PAGE_SIZE);
		pteTable[i].Fields.Read = 1;
		pteTable[i].Fields.SuppressVE = 0;
		pteTable[i].Fields.Write = 1;

	}

	//
// Setting up PDE
//
	pdeTable->Fields.Accessed = 0;
	pdeTable->Fields.Execute = 1;
	pdeTable->Fields.ExecuteForUserMode = 0;
	pdeTable->Fields.Ignored1 = 0;
	pdeTable->Fields.Ignored2 = 0;
	pdeTable->Fields.Ignored3 = 0;
	pdeTable->Fields.PhysicalAddress = (HvFromVirtualToPhysical(pteTable) / PAGE_SIZE);
	pdeTable->Fields.Read = 1;
	pdeTable->Fields.Reserved1 = 0;
	pdeTable->Fields.Reserved2 = 0;
	pdeTable->Fields.Write = 1;

	//
	// Setting up PDPTE
	//
	pdpteTable->Fields.Accessed = 0;
	pdpteTable->Fields.Execute = 1;
	pdpteTable->Fields.ExecuteForUserMode = 0;
	pdpteTable->Fields.Ignored1 = 0;
	pdpteTable->Fields.Ignored2 = 0;
	pdpteTable->Fields.Ignored3 = 0;
	pdpteTable->Fields.PhysicalAddress = (HvFromVirtualToPhysical(pdeTable) / PAGE_SIZE);
	pdpteTable->Fields.Read = 1;
	pdpteTable->Fields.Reserved1 = 0;
	pdpteTable->Fields.Reserved2 = 0;
	pdpteTable->Fields.Write = 1;

	//
	// Setting up PML4E
	//
	pmleTable->Fields.Accessed = 0;
	pmleTable->Fields.Execute = 1;
	pmleTable->Fields.ExecuteForUserMode = 0;
	pmleTable->Fields.Ignored1 = 0;
	pmleTable->Fields.Ignored2 = 0;
	pmleTable->Fields.Ignored3 = 0;
	pmleTable->Fields.PhysicalAddress = (HvFromVirtualToPhysical(pdpteTable) / PAGE_SIZE);
	pmleTable->Fields.Read = 1;
	pmleTable->Fields.Reserved1 = 0;
	pmleTable->Fields.Reserved2 = 0;
	pmleTable->Fields.Write = 1;

	//
	// Setting up EPTP
	//
	TablePointer->Fields.DirtyAndAceessEnabled = 1;
	TablePointer->Fields.MemoryType = 6; // 6 = Write-back (WB)
	TablePointer->Fields.PageWalkLength = 3; // 4 (tables walked) - 1 = 3
	TablePointer->Fields.PML4Address = (HvFromVirtualToPhysical(pmleTable) / PAGE_SIZE);
	TablePointer->Fields.Reserved1 = 0;
	TablePointer->Fields.Reserved2 = 0;

	*tablePointerRet = TablePointer;

	KdPrint(("[*] Extended Page Table Pointer allocated at %llx", TablePointer));


	return STATUS_SUCCESS;
}