PUBLIC HvAsmEnableVmx
PUBLIC HvAsmSafeStackState
PUBLIC HvAsmRestoreState

; this is needed for the virtualization of the whole system.
PUBLIC HvAsmSaveCoreState
PUBLIC HvAsmRestoreCoreState

PUBLIC GetCs
PUBLIC GetDs
PUBLIC GetEs
PUBLIC GetSs
PUBLIC GetFs
PUBLIC GetGs
PUBLIC GetLdtr
PUBLIC GetTr
PUBLIC GetGdtBase
PUBLIC GetIdtBase
PUBLIC GetGdtLimit
PUBLIC GetIdtLimit
PUBLIC GetRflags

PUBLIC MSRRead
PUBLIC MSRWrite

PUBLIC AsmVmexitHandler
PUBLIC HvAsmVmxoffHandler

EXTERN MainVmexitHandler:PROC
EXTERN VmResumeInstruction:PROC

.data
	g_rbpPreviousState QWORD 0  
	g_rspPreviousState QWORD 0	 
	

.code _text

;------------------------------------------------------------------------

HvAsmEnableVmx PROC PUBLIC

	PUSH RAX			    ; Save the state
	
	XOR RAX, RAX			; Clear the RAX
	MOV RAX, CR4

	OR RAX,02000h	    	; Set the 14th bit
	MOV CR4, RAX
	
	POP RAX			     	; Restore the state
	RET

HvAsmEnableVmx ENDP

;------------------------------------------------------------------------

HvAsmSafeStackState PROC PUBLIC
	MOV g_rbpPreviousState, RBP
	MOV g_rspPreviousState, RSP

	RET

HvAsmSafeStackState ENDP

;------------------------------------------------------------------------

HvAsmRestoreState PROC PUBLIC

	; TURN OFF BEFORE EXISTING
	VMXOFF


	; RESTORE THE STATE FOR THE STACK POINTERS
	MOV RSP, g_rspPreviousState
	MOV RBP, g_rbpPreviousState

	; MAKE RSP POINTS TO THE RET ADDRESS FOR RIP
	ADD RSP, 8h


	; RETURN TRUE
	MOV RAX, 1
	
	; RETURN SECTION
	ADD RSP, 50h
	POP RDI
	
	RET

HvAsmRestoreState ENDP

;------------------------------------------------------------------------

GetGdtBase PROC

	LOCAL	GDTR[10]:BYTE
	SGDT	GDTR
	MOV		RAX, QWORD PTR GDTR[2]

	RET

GetGdtBase ENDP

;------------------------------------------------------------------------

GetCs PROC

	MOV		RAX, CS
	RET

GetCs ENDP

;------------------------------------------------------------------------

GetDs PROC

	MOV		RAX, DS
	RET

GetDs ENDP

;------------------------------------------------------------------------

GetEs PROC

	MOV		RAX, ES
	RET

GetEs ENDP

;------------------------------------------------------------------------

GetSs PROC

	MOV		RAX, SS
	RET

GetSs ENDP

;------------------------------------------------------------------------

GetFs PROC

	MOV		RAX, FS
	RET

GetFs ENDP

;------------------------------------------------------------------------

GetGs PROC

	MOV		RAX, GS
	RET

GetGs ENDP

;------------------------------------------------------------------------

GetLdtr PROC

	SLDT	RAX
	RET

GetLdtr ENDP

;------------------------------------------------------------------------

GetTr PROC

	STR		RAX
	RET

GetTr ENDP

;------------------------------------------------------------------------

GetIdtBase PROC

	LOCAL	IDTR[10]:BYTE
	
	SIDT	IDTR
	MOV		RAX, QWORD PTR IDTR[2]
	RET

GetIdtBase ENDP

;------------------------------------------------------------------------

GetGdtLimit PROC

	LOCAL	GDTR[10]:BYTE

	SGDT	GDTR
	MOV		AX, WORD PTR GDTR[0]

	RET

GetGdtLimit ENDP

;------------------------------------------------------------------------

GetIdtLimit PROC

	LOCAL	IDTR[10]:BYTE
	
	SIDT	IDTR
	MOV		AX, WORD PTR IDTR[0]

	RET

GetIdtLimit ENDP

;------------------------------------------------------------------------

GetRflags PROC

	PUSHFQ
	POP		RAX
	RET

GetRflags ENDP

;------------------------------------------------------------------------

AsmVmexitHandler PROC

    PUSH R15
    PUSH R14
    PUSH R13
    PUSH R12
    PUSH R11
    PUSH R10
    PUSH R9
    PUSH R8        
    PUSH RDI
    PUSH RSI
    PUSH RBP
    PUSH RBP	; RSP
    PUSH RBX
    PUSH RDX
    PUSH RCX
    PUSH RAX	

	MOV RCX, RSP		; GuestRegs THAT HAS BEEN PUSHED TO THE STACK
	SUB	RSP, 28h

	CALL	MainVmexitHandler
	ADD	RSP, 28h	

	; IF WE REACHED HERE, DO THE CALL TO VMRESUME NORMALLY ..
	POP RAX
    POP RCX
    POP RDX
    POP RBX
    POP RBP		; RSP
    POP RBP
    POP RSI
    POP RDI 
    POP R8
    POP R9
    POP R10
    POP R11
    POP R12
    POP R13
    POP R14
    POP R15

	SUB RSP, 0100h ; to avoid error in future functions
	
    JMP VmResumeInstruction
	
AsmVmexitHandler ENDP

;------------------------------------------------------------------------

HvAsmSaveCoreState PROC
	PUSH RAX
	PUSH RCX
	PUSH RDX
	PUSH RBX
	PUSH RBP
	PUSH RSI
	PUSH RDI
	PUSH R8
	PUSH R9
	PUSH R10
	PUSH R11
	PUSH R12
	PUSH R13
	PUSH R14
	PUSH R15
	
	MOV RAX, RSP	;the GuestStack returned value

	RET 
HvAsmSaveCoreState ENDP

;------------------------------------------------------------------------

HvAsmRestoreCoreState PROC
	POP R15
	POP R14
	POP R13
	POP R12
	POP R11
	POP R10
	POP R9
	POP R8
	POP RDI
	POP RSI
	POP RBP
	POP RBX
	POP RDX
	POP RCX
	POP RAX

	RET
HvAsmRestoreCoreState ENDP

;------------------------------------------------------------------------

MSRRead PROC

	RDMSR				; MSR[ECX] --> EDX:EAX
	SHL		RDX, 32
	OR		RAX, RDX

	RET

MSRRead ENDP

;------------------------------------------------------------------------

MSRWrite PROC

	MOV		RAX, RDX
	SHR		RDX, 32
	WRMSR
	RET

MSRWrite ENDP

;------------------------------------------------------------------------

HvAsmVmxoffHandler PROC
	; IF WE REACHED HERE, THEN DO THE VMXOFF BUT DON'T FORGET TO REMOVE THE SHADOW SPACE ALLOCATED 
	; INSIDE THE AsmVmexitHandler FUNCTION.
	ADD RSP, 28h

	VMXOFF 

	POP RAX
    POP RCX
    POP RDX
    POP RBX
    POP RBP		; RSP
    POP RBP
    POP RSI
    POP RDI 
    POP R8
    POP R9
    POP R10
    POP R11
    POP R12
    POP R13
    POP R14
    POP R15

	; WE HAVE 2 ARGs, THE FIRST IS THE GUEST_RIP, SECOND : GUEST_RSP
	MOV RSP, RDX ; SECOND ARG

	JMP RCX ; FIRST ARG

HvAsmVmxoffHandler ENDP

;------------------------------------------------------------------------

END