#include <ntddk.h>
#include <wdm.h>
#include <intrin.h>
#include "DriverHeader.h"
#include "MemoryHeader.h"
#include "vmxHeader.h"

/* the vm state transition : */
/* vmclear => vmptrld => vmlaunch => VMXOFF => vmresume */
/* you should set up the vmcs field before the vmlaunch */

/* GLOBAL */
PHV_VIRTUAL_MACHINE_STATE  g_pVMState;
ULONG64 g_processCount;
UINT64 g_Cr3TargetCount;

NTSTATUS HvInitVmx()
{
	KdPrint(("[HV]: ENTERING %s", __FUNCTION__));

	NTSTATUS status;
	// first see if the vmx is supported or not :
	if (!HvIsVmxSupported())
	{
		KdPrint(("[HV]: the vmx is not supported. exit.\n"));
		return STATUS_UNSUCCESSFUL;
	}
	
	// get the process count
	g_processCount = KeQueryActiveProcessorCount(0);
	KdPrint(("[HV]: the active count of processors core are : %d\n", g_processCount));

	// allocate space for the global variable
	 g_pVMState = (PHV_VIRTUAL_MACHINE_STATE)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(HV_VIRTUAL_MACHINE_STATE) * g_processCount, HV_VM_STATE_TAG);
	
	if (g_pVMState == NULL)
	{
		KdPrint(("[HV]: ERROR, can't allocate space for vm state struct.\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	KdPrint(("[HV]: allocated pool for the vmstate is done well. \n"));

	// now make it run on every logical process
	KAFFINITY affinity;
	for (int i = 0; i < g_processCount; i++)
	{
		affinity = HvMathPower(2, i);
		KeSetSystemAffinityThread(affinity);

		// here we should now enable the vmx operation from the assembly code
		HvAsmEnableVmx();

		// init the vmcs and vmxon regions
		status = HvAllocateVmxonRegion(&g_pVMState[i]);

		if (!NT_SUCCESS(status))
		{
			KdPrint(("[HV] error while init the vmxon region for logical process number : %d\n", i));
		}

		status = HvInitVmcsRegion(&g_pVMState[i]);

		if (!NT_SUCCESS(status))
		{

			KdPrint(("[HV] error while init the vmxon region for logical process number : %d\n", i));
		}
		
		// try to print the location of both vmcs and vmxon regions :

		KdPrint(("[HV]: the location for vmcs region is : 0x%x", g_pVMState[i].VmcsRegion));
		KdPrint(("[HV]: the location for vmxon region is : 0x%x", g_pVMState[i].VmxonRegion));

		KdPrint(("\n==============================================\n"));
	}

	return STATUS_SUCCESS;
}

BOOLEAN HvIsVmxSupported()
{
	KdPrint(("[HV]: ENTERING %s", __FUNCTION__));

	HV_CPUID_REGISTERS cpuRegisters = { 0 };
	HV_IA32_FEATURE_CONTROL msrRegister = { 0 };

	 

	//static_assert(sizeof(cpuRegisters) == (sizeof(int) * 4), "cpuRegisters has not the same size as 4 int.");

	__cpuid((int*)&cpuRegisters, 1); // the struct will be stored as an array

	//
	// now we need to print out the data from registers ..
	// we need to get the 5th bit from ecx
	//

	if (FlagOn((cpuRegisters.ecx >> 5), 1))
	{
		KdPrint(("[HV]: the vmx bit is set from cpuid. the vmx is supported.\n"));

		// now check for the bits in msr register ia32_feature enable ..
		msrRegister.AllValues = __readmsr(HV_MSR_IA32_FEATURE_CONTROL); // 3BH

		if (msrRegister.Fields.lockBit == 0)
		{
			KdPrint(("[HV] : the lockbit = 0 \n"));

			msrRegister.Fields.vmxEnableOutsideSmx = 1;
			msrRegister.Fields.lockBit = 1; // to disable any further modification to the register ..
			__writemsr(HV_MSR_IA32_FEATURE_CONTROL, msrRegister.AllValues);

		}
		else if(msrRegister.Fields.vmxEnableOutsideSmx == 0) // the EnableVmxon bit
		{
			KdPrint(("[HV]: the lockbit is set already, can't modify the msr register.\n"));
			return FALSE;
		}

		return TRUE;

	}

	KdPrint(("[HV]: VMX is not supported bro.\n"));
	return FALSE;
}

NTSTATUS HvVmxExit()
{
	/* here we should execute the vmxoff instruction and clear allocated memory for regions */

	KdPrint(("[HV]: ENTERING %s", __FUNCTION__));

	// we should execute vmxoff for every logical processor you have :
	KAFFINITY AffinityMask;
	for (size_t CoreId = 0; CoreId < g_processCount; CoreId++)
	{
		KdPrint(("\t\t[HV]: Current thread is executing in %d th logical processor.", CoreId));

		KAFFINITY affinity = HvMathPower(2, CoreId);
		
		HvSendCpuidForVmxoff(affinity);

		// free the space
		MmFreeContiguousMemory(HvFromPhysicalToVirtual(g_pVMState[CoreId].VmxonRegion));
		MmFreeContiguousMemory(HvFromPhysicalToVirtual((g_pVMState[CoreId].VmcsRegion)));
		MmFreeNonCachedMemory((PVOID)g_pVMState[CoreId].MsrBitmapVirtual, PAGE_SIZE);

		ExFreePoolWithTag((PVOID)g_pVMState[CoreId].StackAddress, HV_STACK_SIZE);

	}


	// then unallocate the pool with tag
	ExFreePoolWithTag(g_pVMState, HV_VM_STATE_TAG);
	return STATUS_SUCCESS;
}

NTSTATUS HvStoreVmPointerIns()
{
	PHYSICAL_ADDRESS PhysicallAdress;
	PhysicallAdress.QuadPart = 0;

	__vmx_vmptrst((unsigned __int64*)&PhysicallAdress.QuadPart);

	if (PhysicallAdress.QuadPart == NULL)
	{
		KdPrint(("[HV] ERROR: can't resolve the address for VMCS address. \n"));
		return STATUS_UNSUCCESSFUL;
	}

	KdPrint(("[HV]: VMCS address : 0x%x \n", PhysicallAdress.QuadPart));

	return STATUS_SUCCESS;
}


NTSTATUS HvClearVmStateIns(ULONG64 VmcsPhysicalAddress)
{
	int retValue = __vmx_vmclear((unsigned __int64*)&VmcsPhysicalAddress);

	if (retValue) // == 1 OR == 2
	{
		KdPrint(("[HV] ERROR: while executing the vmclear. \n"));
		KdPrint(("[HV]: THE ERROR CODE FROM VMCLEAR is : 1\n"));

		__vmx_off();
		return STATUS_UNSUCCESSFUL;
	}
	return STATUS_SUCCESS;
}


NTSTATUS HvLoadVmStateIns(ULONG64 VmcsPhysicalAddress)
{
	int retValue = __vmx_vmptrld((unsigned __int64*)&VmcsPhysicalAddress);

	if (retValue) // == 1 OR == 2
	{
		KdPrint(("[HV] ERROR: while executing the vmptrld. \n"));
		KdPrint(("[HV]: THE ERROR CODE FROM vmptrld is : 1\n"));

		return STATUS_UNSUCCESSFUL;
	}
	return STATUS_SUCCESS;
}

BOOLEAN HvLaunchVm(_In_ int CoreId)
{
	KdPrint(("[HYPERVISOR]: ENTER %s", __FUNCTION__));

	KdPrint(("\n======================== Launching VM =============================\n"));

	PVOID StackLocation = NULL;
	ULONG64 GuestStack = NULL;
	KAFFINITY affinity;
	KIRQL oldIrql;

	for(int i = 0; i < CoreId; i++ )
	{ 
		affinity = HvMathPower(2, i);
		KeSetSystemAffinityThread(affinity);

		KdPrint(("[HV]: Current thread is executing on the %d th logical core. \n", i));
		
		//
		// now allocate space for the stack that's gonna be used to store values of registers before entering the vm space:
		// we should also allocate space for stacks. every CPU should have one.
		// and I named the tag to point for every cpu id; like it starts with the index (i==0), than adding it to the 
		// tag name make it the same (Tsc0). then the next stack while adding on, to be (Tsc1) ...etc.
		//

		StackLocation = ExAllocatePool2(POOL_FLAG_NON_PAGED, HV_STACK_SIZE, HV_STACK_TAG_CORE_0 + i);

		if (StackLocation == NULL)
		{
			KdPrint(("[HV] ERROR: while allocating space for stack. \n"));
			return FALSE;
		}

		KdPrint(("[HV] SUCCESS : the stack is allocated for the %d th process. At address : 0x%x\n", i, StackLocation));

		// set to the global variable:
		g_pVMState[i].StackAddress = (ULONG64)StackLocation;
	

		// also allocate space for msr bitmap :
		PVOID msrBitmapLocation = MmAllocateNonCachedMemory(PAGE_SIZE); //4-kb alligned(every bit map 1024 * 4 bitmaps)

		if (msrBitmapLocation == NULL)
		{
			KdPrint(("[HV] ERROR: while allocating space for msr Bitmap. \n"));
			return FALSE;
		}
		KdPrint(("[HV] SUCCESS : the msr bitmap is allocated for the %d th process. \n", i));

		RtlZeroMemory(msrBitmapLocation, PAGE_SIZE);

		g_pVMState[i].MsrBitmapVirtual = (ULONG64)msrBitmapLocation;
		g_pVMState[i].MsrBitmapPhysical = HvFromVirtualToPhysical(msrBitmapLocation);


		// 
		// now we should save the state of that processor core before doing any reconfiguration for it.
		// BUT before this, we should raise the IRQL. then after we finish, we set it back to the old IRQL value.
		// then we have to do all the job needed to reset the system affinity thread (to make our code run on 
		// the rest of the cores) then continue to do the same again with other cores. 
		// 
		// Note: we should set the GUEST stack to the same as our host stack.(because we are going to run the same
		// os which is our host).
		//

		oldIrql = KeRaiseIrqlToDpcLevel();
		GuestStack = HvAsmSaveCoreState(); // take the RSP from it.



		// now clear the vmstate of the current logical processor :

		NTSTATUS status = HvClearVmStateIns(g_pVMState[i].VmcsRegion);

		if (!NT_SUCCESS(status))
		{
			KdPrint(("[HV] ERROR: couldn't clear the vm state. \n"));
			return FALSE;
		}

		// now the vmptrld
		status = HvLoadVmStateIns(g_pVMState[i].VmcsRegion);

		if (!NT_SUCCESS(status))
		{
			KdPrint(("[HV] ERROR: couldn't load the address of vm state. \n"));
			return FALSE;
		}

		// now setting up the vmcs fields ..
		KdPrint(("[HV]: SETTING UP THE VMCS FOR PROCESS NUMBER : %d.\n", i));

		status = HvSetUpVmcs(&g_pVMState[i], GuestStack);

		if (!NT_SUCCESS(status))
		{
			KdPrint(("[HV] ERROR: couldn't set up the vmcs. \n"));
			return FALSE;
		}

		// now the vmlaunch, BUT before that, we should save the state of rbp and rsp :
		HvAsmSafeStackState();

		// now execute the vmlaunch
		HvLaunchVmIns();
		
		KeLowerIrql(oldIrql);
		KeRevertToUserAffinityThread();

		// then repeat ...

	}

		// print the error code :
	//	KdPrint(("[HV] ERROR: error code for vmlaunch is : 0x%x", errorCode));
	//	DbgBreakPoint(); // when I'm going to use the kernel debugging.

		return STATUS_SUCCESS;
}

NTSTATUS HvSetUpVmcs(PHV_VIRTUAL_MACHINE_STATE VmState, ULONG64 GuestStack)
{
	// 
	// at first, we should configure the host segment registers.
	// Note: the purpose of 0xf8 that intel said that the three
	// less significant bits must be cleared (zero).
	//
	__vmx_vmwrite(HOST_ES_SELECTOR, GetEs() & 0xF8); 
	__vmx_vmwrite(HOST_CS_SELECTOR, GetCs() & 0xF8);
	__vmx_vmwrite(HOST_SS_SELECTOR, GetSs() & 0xF8);
	__vmx_vmwrite(HOST_DS_SELECTOR, GetDs() & 0xF8);
	__vmx_vmwrite(HOST_FS_SELECTOR, GetFs() & 0xF8);
	__vmx_vmwrite(HOST_GS_SELECTOR, GetGs() & 0xF8);
	__vmx_vmwrite(HOST_TR_SELECTOR, GetTr() & 0xF8);

	//
	// Next, is the link pointer (used in nested virtualization)
	// no need to use it here, so it's gonna be -1
	//
	__vmx_vmwrite(VMCS_LINK_POINTER, ~0ULL);

	//
	// Some fields are not important to us, but we should configure at as the same of our physical machine
	//
	__vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(HV_MSR_IA32_DEBUGCTL) & 0xFFFFFFFF);
	__vmx_vmwrite(GUEST_IA32_DEBUGCTL_HIGH, __readmsr(HV_MSR_IA32_DEBUGCTL) >> 32);

	//
	// and some other fields, we can ignore them by putting zero into it ..
	//

	__vmx_vmwrite(TSC_OFFSET, 0);
	__vmx_vmwrite(TSC_OFFSET_HIGH, 0);

	__vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
	__vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);

	__vmx_vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
	__vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);

	__vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
	__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);

	//
	// configure segment registers based on the gdt base address. 
	// (study GDT and segment registers agaiiinnnnn)
	//
	ULONG64 GdtBase = 0;
	GdtBase = GetGdtBase();

	HvFillGuestSelectorData((PVOID)GdtBase, ES, GetEs());
	HvFillGuestSelectorData((PVOID)GdtBase, CS, GetCs());
	HvFillGuestSelectorData((PVOID)GdtBase, SS, GetSs());
	HvFillGuestSelectorData((PVOID)GdtBase, DS, GetDs());
	HvFillGuestSelectorData((PVOID)GdtBase, FS, GetFs());
	HvFillGuestSelectorData((PVOID)GdtBase, GS, GetGs());
	HvFillGuestSelectorData((PVOID)GdtBase, LDTR, GetLdtr());
	HvFillGuestSelectorData((PVOID)GdtBase, TR, GetTr());


	//
	// now it's the GS and FS values in the MSRs:
	//
	__vmx_vmwrite(GUEST_FS_BASE, __readmsr(HV_MSR_FS_BASE));
	__vmx_vmwrite(GUEST_GS_BASE, __readmsr(HV_MSR_GS_BASE));
	

	//
	// some unknown fields ..
	//
	__vmx_vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
	__vmx_vmwrite(GUEST_ACTIVITY_STATE, 0);   //Active state 

	//
	// a very important part, from the VM-EXECUTION CONTROL FIELDS.
	// we going to deal with the primary and secodary only.
	// note that the default to all bits is zero, we only need to enable only the bits we are going to need,
	// but remember that some bits are dependent on other bits. 
	//


	// this works only if the IA32_MSR_BASIC[55] = 0.

	/*
	- CPU_BASED_ACTIVATE_MSR_BITMAP : to avoid the vmexit when ever there are a read or write for MSR.
	- 
	*/
	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, HvAdjustControls(CPU_BASED_HLT_EXITING | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS | CPU_BASED_ACTIVATE_MSR_BITMAP, HV_MSR_IA32_VMX_PROCBASED_CTLS));
	__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, HvAdjustControls(CPU_BASED_CTL2_RDTSCP | CPU_BASED_CTL2_ENABLE_INVPCID | CPU_BASED_CTL2_ENABLE_XSAVE_XRSTORS, HV_MSR_IA32_VMX_PROCBASED_CTLS2));

	//
	// other control fields going to be ignored, and we do so by putting zero in it.
	//

	__vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, HvAdjustControls(0, HV_MSR_IA32_VMX_PINBASED_CTLS));
	__vmx_vmwrite(VM_EXIT_CONTROLS, HvAdjustControls(VM_EXIT_IA32E_MODE | VM_EXIT_ACK_INTR_ON_EXIT, HV_MSR_IA32_VMX_EXIT_CTLS));
	__vmx_vmwrite(VM_ENTRY_CONTROLS, HvAdjustControls(VM_ENTRY_IA32E_MODE, HV_MSR_IA32_VMX_ENTRY_CTLS));


	//
	// now the control registers and debug registers.
	//

	/* CR3 target control */
	__vmx_vmwrite(CR3_TARGET_COUNT, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE0, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE1, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE2, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE3, 0);


	__vmx_vmwrite(CR0_GUEST_HOST_MASK, 0);
	__vmx_vmwrite(CR4_GUEST_HOST_MASK, 0);
	__vmx_vmwrite(CR0_READ_SHADOW, 0);
	__vmx_vmwrite(CR4_READ_SHADOW, 0);


	__vmx_vmwrite(GUEST_CR0, __readcr0());
	__vmx_vmwrite(GUEST_CR3, __readcr3());
	__vmx_vmwrite(GUEST_CR4, __readcr4());

	__vmx_vmwrite(HOST_CR0, __readcr0());
	__vmx_vmwrite(HOST_CR3, __readcr3());
	__vmx_vmwrite(HOST_CR4, __readcr4());

	//
	// RFLAGS
	//
	__vmx_vmwrite(GUEST_RFLAGS, GetRflags());
	

	//
	// GDT & IDT for guest, we will use the same as host
	//

	__vmx_vmwrite(GUEST_GDTR_BASE, GetGdtBase());
	__vmx_vmwrite(GUEST_IDTR_BASE, GetIdtBase());
	__vmx_vmwrite(GUEST_GDTR_LIMIT, GetGdtLimit());
	__vmx_vmwrite(GUEST_IDTR_LIMIT, GetIdtLimit());

	//
	// we going to ignore the support for SYSENTER.
	// BUT NOW configure the GDT and IDT but for host
	//
	HV_SEGMENT_SELECTOR SegmentSelector = { 0 };

	HvGetSegmentDescriptor(&SegmentSelector, GetTr(), (PUCHAR)GetGdtBase());
	__vmx_vmwrite(HOST_TR_BASE, SegmentSelector.BASE);

	__vmx_vmwrite(HOST_FS_BASE, __readmsr(HV_MSR_FS_BASE));
	__vmx_vmwrite(HOST_GS_BASE, __readmsr(HV_MSR_GS_BASE));

	__vmx_vmwrite(HOST_GDTR_BASE, GetGdtBase());
	__vmx_vmwrite(HOST_IDTR_BASE, GetIdtBase());


	//
	// now set the RIP, RSP for both guest and host.
	// the rip and rsp for guest will point to the same place, which is the guest memory area.
	// on the other hand, host; the rip will point to a handler that gonna handle the vm exit
	// and choose whether to close the hypervisor or resume.
	//

	__vmx_vmwrite(GUEST_RSP, GuestStack); // setup guest sp
	__vmx_vmwrite(GUEST_RIP, (ULONG64)HvAsmRestoreCoreState); // setup guest ip

	// when we give control back to host (vmexit) ..
	__vmx_vmwrite(HOST_RSP, ((ULONG64)VmState->StackAddress+ HV_STACK_SIZE - 1)); // because the stack is reversed, we start from the last address from the stack
	__vmx_vmwrite(HOST_RIP, (ULONG64)AsmVmexitHandler);

	return STATUS_SUCCESS;
}


VOID
HvFillGuestSelectorData(
	PVOID  GdtBase,
	ULONG  Segreg,
	USHORT Selector)
{
	HV_SEGMENT_SELECTOR SegmentSelector = { 0 };
	ULONG            AccessRights;

	HvGetSegmentDescriptor(&SegmentSelector, Selector, (PUCHAR)GdtBase);
	AccessRights = ((PUCHAR)&SegmentSelector.ATTRIBUTES)[0] + (((PUCHAR)&SegmentSelector.ATTRIBUTES)[1] << 12);

	if (!Selector)
		AccessRights |= 0x10000;

	__vmx_vmwrite(GUEST_ES_SELECTOR + Segreg * 2, Selector);
	__vmx_vmwrite(GUEST_ES_LIMIT + Segreg * 2, SegmentSelector.LIMIT);
	__vmx_vmwrite(GUEST_ES_AR_BYTES + Segreg * 2, AccessRights);
	__vmx_vmwrite(GUEST_ES_BASE + Segreg * 2, SegmentSelector.BASE);
}


BOOLEAN
HvGetSegmentDescriptor(PHV_SEGMENT_SELECTOR SegmentSelector,
	USHORT            Selector,
	PUCHAR            GdtBase)
{
	PHV_SEGMENT_DESCRIPTOR SegDesc;

	if (!SegmentSelector)
		return FALSE;

	if (Selector & 0x4)
	{
		return FALSE;
	}

	SegDesc = (PHV_SEGMENT_DESCRIPTOR)((PUCHAR)GdtBase + (Selector & ~0x7));

	SegmentSelector->SEL = Selector;
	SegmentSelector->BASE = SegDesc->BASE0 | SegDesc->BASE1 << 16 | SegDesc->BASE2 << 24;
	SegmentSelector->LIMIT = SegDesc->LIMIT0 | (SegDesc->LIMIT1ATTR1 & 0xf) << 16;
	SegmentSelector->ATTRIBUTES.UCHARs = SegDesc->ATTR0 | (SegDesc->LIMIT1ATTR1 & 0xf0) << 4;

	if (!(SegDesc->ATTR0 & 0x10))
	{ // LA_ACCESSED
		ULONG64 Tmp;
		// this is a TSS or callgate etc, save the base high part
		Tmp = (*(PULONG64)((PUCHAR)SegDesc + 8));
		SegmentSelector->BASE = (SegmentSelector->BASE & 0xffffffff) | (Tmp << 32);
	}

	if (SegmentSelector->ATTRIBUTES.Fields.G)
	{
		// 4096-bit granularity is enabled for this segment, scale the limit
		SegmentSelector->LIMIT = (SegmentSelector->LIMIT << 12) + 0xfff;
	}

	return TRUE;
}


ULONG
HvAdjustControls(ULONG Ctl, ULONG Msr)
{
	MSR MsrValue = { 0 };

	MsrValue.Content = __readmsr(Msr);
	Ctl &= MsrValue.Fields.High; /* bit == 0 in high word ==> must be zero */ /* allowed 1-settings. */
	Ctl |= MsrValue.Fields.Low;  /* bit == 1 in low word  ==> must be one  */ /* allowed 0-settings. */
	return Ctl;
}

VOID
MainVmexitHandler(PGUEST_REGS GuestRegs)
{
	UNREFERENCED_PARAMETER(GuestRegs);
	ULONG ExitReason = 0;
	ULONG64 isSuccess = 0;
	BOOLEAN Status = FALSE;

	__vmx_vmread(VM_EXIT_REASON, (size_t*)&ExitReason);

	ULONG ExitQualification = 0;
	__vmx_vmread(EXIT_QUALIFICATION, (size_t*)&ExitQualification);

	KdPrint(("\nVM_EXIT_REASION 0x%x\n", ExitReason & 0xffff));
	KdPrint(("\nEXIT_QUALIFICATION 0x%x\n", ExitQualification));


	switch (ExitReason)
	{
		//
		// 25.1.2  Instructions That Cause VM Exits Unconditionally
		// The following instructions cause VM exits when they are executed in VMX non-root operation: CPUID, GETSEC,
		// INVD, and XSETBV. This is also true of instructions introduced with VMX, which include: INVEPT, INVVPID,
		// VMCALL, VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMRESUME, VMXOFF, and VMXON.
		//

	case EXIT_REASON_VMCLEAR:
	case EXIT_REASON_VMPTRLD:
	case EXIT_REASON_VMPTRST:
	case EXIT_REASON_VMREAD:
	case EXIT_REASON_VMRESUME:
	case EXIT_REASON_VMWRITE:
	case EXIT_REASON_VMXOFF:
	case EXIT_REASON_VMXON:
	case EXIT_REASON_VMLAUNCH:
	{

		ULONG RFLAGS = 0;
		__vmx_vmread(GUEST_RFLAGS, (size_t *)&RFLAGS);
		__vmx_vmwrite(GUEST_RFLAGS, RFLAGS | 0x1); // cf=1 indicate vm instructions fail
		break;
	}

	case EXIT_REASON_CR_ACCESS:
	{
		HvHandleControlRegisterAccess(GuestRegs);

		break;
	}
	case EXIT_REASON_MSR_READ:
	{
		ULONG ECX = GuestRegs->rcx & 0xffffffff;

		// DbgPrint("[*] RDMSR (based on bitmap) : 0x%llx\n", ECX);
		HandleMSRRead(GuestRegs);

		break;
	}
	case EXIT_REASON_MSR_LOADING:
	{
		break;
	}
	case EXIT_REASON_MSR_WRITE:
	{
		ULONG ECX = GuestRegs->rcx & 0xffffffff;

		// DbgPrint("[*] WRMSR (based on bitmap) : 0x%llx\n", ECX);
		HandleMSRWrite(GuestRegs);

		break;
	}

	case EXIT_REASON_CPUID:
	{
		Status = HvHandleCPUID(GuestRegs); // Detect whether we have to turn off VMX or Not
		if (Status)
		{
			// We have to save GUEST_RIP & GUEST_RSP somewhere to restore them directly
			// WE WILL CALL THE ASM FUNCTION TO HANDLE THAT SWITCH BACK ..

			ULONG ExitInstructionLength = 0;
			ULONG64 guestRip = 0;
			ULONG64 guestRsp = 0;
			__vmx_vmread(GUEST_RIP, &guestRip);
			__vmx_vmread(GUEST_RSP, &guestRsp);

			// now we should pass those values as an arguments to the asm function..
			
			__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, (size_t*)&ExitInstructionLength);

			guestRip += ExitInstructionLength; // to make sure that we passed the CPUID instruction

			HvAsmVmxoffHandler(guestRip, guestRsp);
		}
		break;
	}

	case EXIT_REASON_HLT:
	{
		KdPrint(("[*] Execution of HLT detected... \n"));

		//
		// that's enough for now ;)
		//
		isSuccess = HvAsmRestoreState();
		if (isSuccess)
		{
			KdPrint(("[HV] SUCCESS: the Restore state worked fine. \n"));
		}

		break;
	}

	default:
	{
		isSuccess = HvAsmRestoreState();
		if (isSuccess)
		{
			KdPrint(("[HV] SUCCESS: the Restore state worked fine from the defualt state bro.... \n"));
		}
		// DbgBreakPoint();
		break;
	}
	}
}


VOID
ResumeToNextInstruction()
{
	PVOID ResumeRIP = NULL;
	PVOID CurrentRIP = NULL;
	ULONG ExitInstructionLength = 0;

	__vmx_vmread(GUEST_RIP, (size_t*)&CurrentRIP);
	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, (size_t*)&ExitInstructionLength);

	ResumeRIP = (PCHAR)CurrentRIP + ExitInstructionLength;

	__vmx_vmwrite(GUEST_RIP, (ULONG64)ResumeRIP);
}

VOID
VmResumeInstruction()
{
	__vmx_vmresume();

	// if VMRESUME succeeds will never be here !

	ULONG64 ErrorCode = 0;
	__vmx_vmread(VM_INSTRUCTION_ERROR, &ErrorCode);
	__vmx_off();
	KdPrint(("[*] VMRESUME Error : 0x%llx\n", ErrorCode));

	//
	// It's such a bad error because we don't where to go!
	// prefer to break
	//
	DbgBreakPoint();
}

void HvLaunchVmIns()
{
	KdPrint(("[HV] LAUNCHING : executing the vmlaunch instruction..\n"));
	__vmx_vmlaunch();

	//
	// IF THERE'S AN ERROR, WE WILL GET HERE ..
	//
	KdPrint(("[HV] ERROR: couldn't execute the vmlaunch instruction.\n"));

	// now read the error code :
	ULONG64 errorCode;
	__vmx_vmread(VM_INSTRUCTION_ERROR, &errorCode); // ONE OF THE VMCS FIELDS
	KdPrint(("[HV]: the error code is %d\n", errorCode));

	// CLOSE THE HYPERVISOR 
	__vmx_off();
}


/* used for cr3-target control operation, won't use it right now */
BOOLEAN SetTargetControls(UINT64 CR3, UINT64 Index)
{
	//
	// Index starts from 0 , not 1
	//
	if (Index >= 4)
	{
		//
		// Not supported for more than 4 , at least for now :(
		//
		return FALSE;
	}

	UINT64 temp = 0;

	if (CR3 == 0)
	{
		if (g_Cr3TargetCount <= 0)
		{
			//
			// Invalid command as g_Cr3TargetCount cannot be less than zero
			// s
			return FALSE;
		}
		else
		{
			g_Cr3TargetCount -= 1;
			if (Index == 0)
			{
				__vmx_vmwrite(CR3_TARGET_VALUE0, 0);
			}
			if (Index == 1)
			{
				__vmx_vmwrite(CR3_TARGET_VALUE1, 0);
			}
			if (Index == 2)
			{
				__vmx_vmwrite(CR3_TARGET_VALUE2, 0);
			}
			if (Index == 3)
			{
				__vmx_vmwrite(CR3_TARGET_VALUE3, 0);
			}
		}
	}
	else
	{
		if (Index == 0)
		{
			__vmx_vmwrite(CR3_TARGET_VALUE0, CR3);
		}
		if (Index == 1)
		{
			__vmx_vmwrite(CR3_TARGET_VALUE1, CR3);
		}
		if (Index == 2)
		{
			__vmx_vmwrite(CR3_TARGET_VALUE2, CR3);
		}
		if (Index == 3)
		{
			__vmx_vmwrite(CR3_TARGET_VALUE3, CR3);
		}
		g_Cr3TargetCount += 1;
	}

	__vmx_vmwrite(CR3_TARGET_COUNT, g_Cr3TargetCount);
	return TRUE;
}


BOOLEAN HvHandleCPUID(PGUEST_REGS state)
{
	INT32 CpuInfo[4];
	ULONG Mode = 0;

	//
	// Check for the magic CPUID sequence, and check that it is coming from
	// Ring 0. Technically we could also check the RIP and see if this falls
	// in the expected function, but we may want to allow a separate "unload"
	// driver or code at some point
	//

	__vmx_vmread(GUEST_CS_SELECTOR, (size_t *)&Mode);
	Mode = Mode & RPL_MASK;

	if ((state->rax == 0x4f4d4152) && (state->rcx == 0x4f4d4152) && Mode == DPL_SYSTEM) // check if it OMAR and from kernel mode ..
	{
		return TRUE; // Indicates we have to turn off VMX
	}

	//
	// Otherwise, issue the CPUID to the logical processor based on the indexes
	// on the VP's GPRs
	//
	__cpuidex(CpuInfo, (INT32)state->rax, (INT32)state->rcx);

	//
	// Check if this was CPUID 1h, which is the features request
	//
	if (state->rax == 1)
	{
		//
		// Set the Hypervisor Present-bit in RCX, which Intel and AMD have both
		// reserved for this indication
		//
		CpuInfo[2] |= HYPERV_HYPERVISOR_PRESENT_BIT;
	}

	else if (state->rax == HYPERV_CPUID_INTERFACE)
	{
		//
		// Return our interface identifier
		//
		CpuInfo[0] = 'KLHV'; // [K]ERNEL [L]OVER [H]YPER[V]ISOR
	}

	//
	// Copy the values from the logical processor registers into the VP GPRs
	//
	state->rax = CpuInfo[0];
	state->rbx = CpuInfo[1];
	state->rcx = CpuInfo[2];
	state->rdx = CpuInfo[3];

	return FALSE; // Indicates we don't have to turn off VMX
}

//
// not mandatory for me, but it is for the hypervisor 
// because some processors has controls like CR3-Load Exiting & CR3-Store Existing. 
// so we have to manage them. But it's recommended to avoid this if the processor has no default1 settings for it.
// (to reduce the vm exit as possible )
//

VOID HvHandleControlRegisterAccess(PGUEST_REGS GuestState)
{
	ULONG ExitQualification = 0;

	__vmx_vmread(EXIT_QUALIFICATION, (size_t*)&ExitQualification);

	PHV_MOV_CR_QUALIFICATION data = (PHV_MOV_CR_QUALIFICATION)&ExitQualification; // see the structure of ExitQualification from intel manual.

	PULONG64 RegPtr = (PULONG64)&GuestState->rax + data->Fields.Register;

	//
	// Because its RSP and as we didn't save RSP correctly (because of pushes)
	// so we have to make it points to the GUEST_RSP
	//
	if (data->Fields.Register == 4)
	{
		INT64 RSP = 0;
		__vmx_vmread(GUEST_RSP, (size_t*)&RSP);
		*RegPtr = RSP;
	}

	switch (data->Fields.AccessType)
	{
	case TYPE_MOV_TO_CR:
	{
		switch (data->Fields.ControlRegister)
		{
		case 0:
			__vmx_vmwrite(GUEST_CR0, *RegPtr);
			__vmx_vmwrite(CR0_READ_SHADOW, *RegPtr);
			break;
		case 3:

			__vmx_vmwrite(GUEST_CR3, (*RegPtr & ~(1ULL << 63)));

			//
			// In the case of using EPT, the context of EPT/VPID should be
			// invalidated
			//
			break;
		case 4:
			__vmx_vmwrite(GUEST_CR4, *RegPtr);
			__vmx_vmwrite(CR4_READ_SHADOW, *RegPtr);
			break;
		default:
			DbgPrint("[*] Unsupported register %d\n", data->Fields.ControlRegister);
			break;
		}
	}
	break;

	case TYPE_MOV_FROM_CR:
	{
		switch (data->Fields.ControlRegister)
		{
		case 0:
			__vmx_vmread(GUEST_CR0, RegPtr);
			break;
		case 3:
			__vmx_vmread(GUEST_CR3, RegPtr);
			break;
		case 4:
			__vmx_vmread(GUEST_CR4, RegPtr);
			break;
		default:
			DbgPrint("[*] Unsupported register %d\n", data->Fields.ControlRegister);
			break;
		}
	}
	break;

	default:
		DbgPrint("[*] Unsupported operation %d\n", data->Fields.AccessType);
		break;
	}
}


VOID HandleMSRRead(PGUEST_REGS GuestRegs)
{
	MSR msr = { 0 };

	//
	// RDMSR. The RDMSR instruction causes a VM exit if any of the following are true:
	//
	// The "use MSR bitmaps" VM-execution control is 0.
	// The value of ECX is not in the ranges 00000000H - 00001FFFH and C0000000H - C0001FFFH
	// The value of ECX is in the range 00000000H - 00001FFFH and bit n in read bitmap for low MSRs is 1,
	//   where n is the value of ECX.
	// The value of ECX is in the range C0000000H - C0001FFFH and bit n in read bitmap for high MSRs is 1,
	//   where n is the value of ECX & 00001FFFH.
	//

	if (((GuestRegs->rcx <= 0x00001FFF)) || ((0xC0000000 <= GuestRegs->rcx) && (GuestRegs->rcx <= 0xC0001FFF)))
	{
		msr.Content = MSRRead((ULONG)GuestRegs->rcx);
	}
	else
	{
		msr.Content = 0;
	}

	GuestRegs->rax = msr.Fields.Low;
	GuestRegs->rdx = msr.Fields.High;
}

VOID HandleMSRWrite(PGUEST_REGS GuestRegs)
{
	MSR msr = { 0 };

	//
	// Check for the sanity of MSR
	//
	if ((GuestRegs->rcx <= 0x00001FFF) || ((0xC0000000 <= GuestRegs->rcx) && (GuestRegs->rcx <= 0xC0001FFF)))
	{
		msr.Fields.Low = (ULONG)GuestRegs->rax;
		msr.Fields.High = (ULONG)GuestRegs->rdx;
		MSRWrite((ULONG)GuestRegs->rcx, msr.Content);
	}
}


BOOLEAN SetMsrBitmap(ULONG64 Msr, int ProcessID, BOOLEAN ReadDetection, BOOLEAN WriteDetection)
{
	if (!ReadDetection && !WriteDetection)
	{
		//
		// Invalid Command
		//
		return FALSE;
	}

	if (Msr <= 0x00001FFF)
	{
		if (ReadDetection)
		{
			SetBit((PVOID)g_pVMState[ProcessID].MsrBitmapVirtual, Msr, TRUE);
		}
		if (WriteDetection)
		{
			SetBit((PVOID)(g_pVMState[ProcessID].MsrBitmapVirtual + 2048), Msr, TRUE);
		}
	}
	else if ((0xC0000000 <= Msr) && (Msr <= 0xC0001FFF))
	{
		if (ReadDetection)
		{
			SetBit((PVOID)(g_pVMState[ProcessID].MsrBitmapVirtual + 1024), Msr - 0xC0000000, TRUE);
		}
		if (WriteDetection)
		{
			SetBit((PVOID)(g_pVMState[ProcessID].MsrBitmapVirtual + 3072), Msr - 0xC0000000, TRUE);
		}
	}
	else
	{
		return FALSE;
	}
	return TRUE;
}

VOID SetBit(PVOID Addr, UINT64 Bit, BOOLEAN Set)
{
	PAGED_CODE();

	UINT64 Byte = Bit / 8;
	UINT64 Temp = Bit % 8;
	UINT64 N = 7 - Temp;

	BYTE* Addr2 = (BYTE *)Addr;
	if (Set)
	{
		Addr2[Byte] |= (1 << N);
	}
	else
	{
		Addr2[Byte] &= ~(1 << N);
	}
}

VOID
GetBit(PVOID Addr, UINT64 Bit)
{
	UINT64 Byte = 0, K = 0;
	Byte = Bit / 8;
	K = 7 - Bit % 8;
	BYTE * Addr2 = (BYTE *)Addr;

   /*	return Addr2[Byte] & (1 << K));*/
}


void HvSendCpuidForVmxoff(KAFFINITY affinity)
{
	int cpuidInfo[4];
	KeSetSystemAffinityThread(affinity); // same as 2^CoreId ..
	KIRQL oldIrql = KeRaiseIrqlToDpcLevel();

	// send the EXIT CPUID CODE ...
	__cpuidex(cpuidInfo, 0x4f4d4152, 0x4f4d4152);

	KeLowerIrql(oldIrql);
	KeRevertToUserAffinityThread();
}