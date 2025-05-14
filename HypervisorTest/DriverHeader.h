#include <wdm.h>
#pragma once
// here we will define the IOCTL to be used for user mode

/* some typedef */
typedef UCHAR BYTE;

/* global variables */

#define HV_CTL_CODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8ccc, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define FlagOn(_x, _y) ((_x) & (_y))

// TAGS
#define HV_VM_STATE_TAG	'gTvH'

// MSRs
#define HV_MSR_IA32_FEATURE_CONTROL 0x3A // 3AH, 58
#define HV_MSR_IA23_VMX_BASIC		 0x480 // 480h, 1152 // this MSR in it's first 31 bit has the VMCS revision identifier.
#define HV_MSR_IA32_DEBUGCTL     0x1D9
#define HV_MSR_IA32_SYSENTER_CS  0x174
#define HV_MSR_IA32_SYSENTER_ESP 0x175
#define HV_MSR_IA32_SYSENTER_EIP 0x176
#define HV_MSR_FS_BASE        0xC0000100
#define HV_MSR_GS_BASE        0xC0000101
#define HV_MSR_SHADOW_GS_BASE 0xC0000102

#define HV_MSR_IA32_VMX_PINBASED_CTLS       0x481
#define HV_MSR_IA32_VMX_PROCBASED_CTLS      0x482
#define HV_MSR_IA32_VMX_EXIT_CTLS           0x483
#define HV_MSR_IA32_VMX_ENTRY_CTLS          0x484
#define HV_MSR_IA32_VMX_MISC                0x485
#define HV_MSR_IA32_VMX_CR0_FIXED0          0x486
#define HV_MSR_IA32_VMX_CR0_FIXED1          0x487
#define HV_MSR_IA32_VMX_CR4_FIXED0          0x488
#define HV_MSR_IA32_VMX_CR4_FIXED1          0x489
#define HV_MSR_IA32_VMX_VMCS_ENUM           0x48A
#define HV_MSR_IA32_VMX_PROCBASED_CTLS2     0x48B
#define HV_MSR_IA32_VMX_EPT_VPID_CAP        0x48C
#define HV_MSR_IA32_VMX_TRUE_PINBASED_CTLS  0x48D
#define HV_MSR_IA32_VMX_TRUE_PROCBASED_CTLS 0x48E
#define HV_MSR_IA32_VMX_TRUE_EXIT_CTLS      0x48F
#define HV_MSR_IA32_VMX_TRUE_ENTRY_CTLS     0x490
#define HV_MSR_IA32_VMX_VMFUNC              0x491


#define HV_VMXON_REGION_SIZE 4096
#define HV_VMXON_REGION_PADDING HV_VMXON_REGION_SIZE
#define HV_VMCS_REGION_SIZE 4096 // 4-KB 
#define HV_VMCS_REGION_PADDING HV_VMCS_REGION_SIZE


typedef struct _HV_BUFFER
{
	wchar_t Buffer[1024];
}HV_BUFFER, *PHV_BUFFER;


//#pragma pack(push, 1) // to disable the padding
typedef struct _HV_CPUID_REGISTERS
{
	int eax;
	int ebx;
	int ecx;
	int edx;
}HV_CPUID_REGISTERS, *PHV_CPUID_REGISTERS;
//#pragma pack(pop)


typedef union _HV_IA32_FEATURE_CONTROL // remember that all members inside a union share the same location, according to the largest member inside it.
{
	ULONG64 AllValues; 
	struct { // all fields specific to AllValues variable, 64 bit. 
		ULONG64 lockBit : 1;
		ULONG64 vmxEnableSmx : 1;
		ULONG64 vmxEnableOutsideSmx : 1;
		ULONG64 reserved_1 : 5;
		ULONG64 SENTER : 7;
		ULONG64 gSENTER : 1;
		ULONG64 reserved_2 : 1;
		ULONG64 SgxLaunch : 1;
		ULONG64 SgxGlobal : 1;
		ULONG64 reserved_3 : 1;
		ULONG64 LMCEon : 1;
		ULONG64 reserved_4 : 11;
		ULONG64 reserved_5 : 32;
	}Fields;

}HV_IA32_FEATURE_CONTROL, *PHV_IA32_FEATURE_CONTROL;


typedef union _HV_IA32_VMX_BASIC
{
	ULONG64 AllValues;
	struct
	{
		ULONG64 VmcsRevisionId : 31; // from 0:30
		ULONG64 ZeroBit : 1; // 31
		ULONG64 RegionSize : 13; // 32:44
		ULONG64 reserved1 : 3; // 45:48
		ULONG64 reserved2 : 16; // I WILL make the rest as reserved
	}Fields;
}HV_IA32_VMX_BASIC, *PHV_IA32_VMX_BASIC;

//
// we should make a structure that holds the state for our virtual machine .. 
// so every logical process should have an instance of this structure.
//
typedef struct _HV_VIRTUAL_MACHINE_STATE
{
	ULONG64 VmxonRegion;
	ULONG64 VmcsRegion;
	ULONG64 StackAddress;
	ULONG64 TablePointer;
	ULONG64 MsrBitmapVirtual;
	ULONG64 MsrBitmapPhysical;
	PVOID GuestVirtualMemAddress;

}HV_VIRTUAL_MACHINE_STATE, *PHV_VIRTUAL_MACHINE_STATE;

#define HV_BUFFER_SIZE sizeof(HV_BUFFER)
#define HV_CPUID_REGISTERS_SIZE sizeof(HV_CPUID_REGISTERS)

// assembly function call
extern "C" inline void __fastcall HvAsmEnableVmx(VOID);
extern "C" inline void __fastcall HvAsmSafeStackState(VOID);
extern "C" inline ULONG64 __fastcall HvAsmRestoreState(VOID);

extern "C" inline ULONG64 __fastcall HvAsmSaveCoreState(VOID);
extern "C" inline void __fastcall HvAsmRestoreCoreState(VOID);

extern "C" inline USHORT __fastcall GetCs(VOID);
extern "C" inline USHORT __fastcall GetDs(VOID);
extern "C" inline USHORT __fastcall GetEs(VOID);
extern "C" inline USHORT __fastcall GetSs(VOID);
extern "C" inline USHORT __fastcall GetFs(VOID);
extern "C" inline USHORT __fastcall GetGs(VOID);
extern "C" inline USHORT __fastcall GetLdtr(VOID);
extern "C" inline USHORT __fastcall GetTr(VOID);
extern "C" inline USHORT __fastcall GetIdtLimit(VOID);
extern "C" inline USHORT __fastcall GetGdtLimit(VOID);
extern "C" inline ULONG64 __fastcall GetRflags(VOID);
extern "C" inline ULONG64 __fastcall GetGdtBase(VOID);
extern "C" inline ULONG64 __fastcall GetIdtBase(VOID);
extern "C" inline void __fastcall AsmVmexitHandler(VOID);

extern "C" inline void __fastcall HvAsmVmxoffHandler(ULONG64 Rip, ULONG64 Rsp);

extern "C" inline ULONG64 __fastcall MSRRead(ULONG32 reg);
extern "C" inline void __fastcall MSRWrite(ULONG32 reg, ULONG64 MsrValue);


/* function support */
int HvMathPower(int base, int exp);


PVOID HvFromPhysicalToVirtual(UINT64 physicalQuadPart);
UINT64 HvFromVirtualToPhysical(VOID* BaseAddress);
NTSTATUS HvAllocateVmxonRegion(PHV_VIRTUAL_MACHINE_STATE VMState);
NTSTATUS HvInitVmcsRegion(PHV_VIRTUAL_MACHINE_STATE VMState);

NTSTATUS HvInitVmx();
BOOLEAN HvIsVmxSupported();
NTSTATUS HvVmxExit();

