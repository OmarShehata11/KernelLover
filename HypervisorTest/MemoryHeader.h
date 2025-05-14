#pragma once

#include "DriverHeader.h"



/* macros */
#define HV_EPTP_SIZE sizeof(HV_EPTP)
#define HV_EPT_PDE_SIZE sizeof(HV_EPT_PDE)
#define HV_EPT_PDPTE_SIZE sizeof(HV_EPT_PDPTE)
#define HV_EPT_PML4E_SIZE sizeof(HV_EPT_PML4E)
#define HV_EPT_PTE_SIZE sizeof(HV_EPT_PTE)

#define HV_GUEST_MEMORY_NUM_OF_PAGES 100
#define HV_GUEST_MEMORY_SIZE (HV_GUEST_MEMORY_NUM_OF_PAGES * PAGE_SIZE)

#define HV_STACK_SIZE 0x8000

/* TAGS */
#define HV_EPTP_TAG 'tpeT'
#define HV_EPT_PDE_TAG 'edpT'
#define HV_EPT_PDPTE_TAG 'pdpT'
#define HV_EPT_PML4E_TAG 'pmlT'
#define HV_EPT_PTE_TAG 'pteT'
#define HV_GUEST_MEM_TAG 'Ttsg'
#define HV_STACK_TAG_CORE_0 0x63735430 /* 'csT0' */


/* 4 LEVEL PAGING */
/* with 36 physical address long */
/* EPTP -> PMLE4 -> PDPTE -> PDE -> PTE -> Physical address */

/* pointer for EPT table */
typedef union _HV_EPTP 
{
	ULONG64 AllValues;
	struct {
        UINT64 MemoryType : 3; // bit 2:0 (0 = Uncacheable (UC) - 6 = Write - back(WB))
        UINT64 PageWalkLength : 3; // bit 5:3 (This value is 1 less than the EPT page-walk length) 
        UINT64 DirtyAndAceessEnabled : 1; // bit 6  (Setting this control to 1 enables accessed and dirty flags for EPT)
        UINT64 Reserved1 : 5; // bit 11:7 
        UINT64 PML4Address : 36;
        UINT64 Reserved2 : 16;
	}Fields;
}HV_EPTP, *PHV_EPTP;



/* PML4E TABLE (FIRST TABLE) */
typedef union _HV_EPT_PML4E
{
    ULONG64 AllValues;
    struct
    {
        UINT64 Read : 1; // bit 0
        UINT64 Write : 1; // bit 1
        UINT64 Execute : 1; // bit 2
        UINT64 Reserved1 : 5; // bit 7:3 (Must be Zero)
        UINT64 Accessed : 1; // bit 8
        UINT64 Ignored1 : 1; // bit 9
        UINT64 ExecuteForUserMode : 1; // bit 10
        UINT64 Ignored2 : 1; // bit 11
        UINT64 PhysicalAddress : 36; // bit (N-1):12 or Page-Frame-Number
        UINT64 Reserved2 : 4; // bit 51:N
        UINT64 Ignored3 : 12; // bit 63:52
    }Fields;
}HV_EPT_PML4E, *PHV_EPT_PML4E;


typedef union _HV_EPT_PDPTE
{
    ULONG64 AllVAlues;
    struct {
        UINT64 Read : 1; // bit 0
        UINT64 Write : 1; // bit 1
        UINT64 Execute : 1; // bit 2
        UINT64 Reserved1 : 5; // bit 7:3 (Must be Zero)
        UINT64 Accessed : 1; // bit 8
        UINT64 Ignored1 : 1; // bit 9
        UINT64 ExecuteForUserMode : 1; // bit 10
        UINT64 Ignored2 : 1; // bit 11
        UINT64 PhysicalAddress : 36; // bit (N-1):12 or Page-Frame-Number
        UINT64 Reserved2 : 4; // bit 51:N
        UINT64 Ignored3 : 12; // bit 63:52
    }Fields;
}HV_EPT_PDPTE, *PHV_EPT_PDPTE;


typedef union _HV_EPT_PDE {
    ULONG64 AllValues;
    struct {
        UINT64 Read : 1; // bit 0
        UINT64 Write : 1; // bit 1
        UINT64 Execute : 1; // bit 2
        UINT64 Reserved1 : 5; // bit 7:3 (Must be Zero)
        UINT64 Accessed : 1; // bit 8
        UINT64 Ignored1 : 1; // bit 9
        UINT64 ExecuteForUserMode : 1; // bit 10
        UINT64 Ignored2 : 1; // bit 11
        UINT64 PhysicalAddress : 36; // bit (N-1):12 or Page-Frame-Number
        UINT64 Reserved2 : 4; // bit 51:N
        UINT64 Ignored3 : 12; // bit 63:52
    }Fields;
}HV_EPT_PDE, * PHV_EPT_PDE;


typedef union _HV_EPT_PTE {
    ULONG64 AllValues;
    struct {
        UINT64 Read : 1; // bit 0
        UINT64 Write : 1; // bit 1
        UINT64 Execute : 1; // bit 2
        UINT64 EPTMemoryType : 3; // bit 5:3 (EPT Memory type)
        UINT64 IgnorePAT : 1; // bit 6
        UINT64 Ignored1 : 1; // bit 7
        UINT64 AccessedFlag : 1; // bit 8   
        UINT64 DirtyFlag : 1; // bit 9
        UINT64 ExecuteForUserMode : 1; // bit 10
        UINT64 Ignored2 : 1; // bit 11
        UINT64 PhysicalAddress : 36; // bit (N-1):12 or Page-Frame-Number
        UINT64 Reserved : 4; // bit 51:N
        UINT64 Ignored3 : 11; // bit 62:52
        UINT64 SuppressVE : 1; // bit 63
    }Fields;
}HV_EPT_PTE, * PHV_EPT_PTE;

NTSTATUS HvInitPageTables(_Out_ PHV_EPTP* tablePointerRet, _Out_ PVOID* GuestMemAddressRet);