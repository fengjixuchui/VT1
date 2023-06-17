.code

EXTERN MyOpenProcess:proc
EXTERN NtOpenProcessRet:dq

AsmNtOpenProcess proc
	push r15;
	push r14;
	push r13;
	push r12;
	push r11;
	push r10;
	push r9;
	push r8;
	push rdi;
	push rsi;
	push rbp;
	push rsp;
	push rbx;
	push rdx;
	push rcx;
	push rax;

	sub rsp,0100h
	call MyOpenProcess
	add rsp,0100h;

	pop rax;
	pop rcx;
	pop rdx;
	pop rbx;
	pop rsp;
	pop rbp;
	pop rsi;
	pop rdi;
	pop r8;
	pop r9;
	pop r10;
	pop r11;
	pop r12;
	pop r13;
	pop r14;
	pop r15;
	sub   rsp,38h
	mov   rax,qword ptr gs:[188h]
	mov     r10b,byte ptr [rax+232h]
	jmp qword ptr [NtOpenProcessRet]
AsmNtOpenProcess endp
end