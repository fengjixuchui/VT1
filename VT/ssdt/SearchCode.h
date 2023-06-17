#pragma once
#include <ntifs.h>
/*
Author:��� QQ:471194425 Ⱥ�ţ�1026716399
*/

typedef struct _FindCode
{
	UCHAR code[200];
	ULONG len;
	int offset;
	ULONG lastAddressOffset;
}FindCode, *PFindCode;

UCHAR charToHex(UCHAR * ch);

void initFindCodeStruct(PFindCode findCode, PCHAR code, ULONG64 offset, ULONG64 lastAddrOffset);
ULONG64 findAddressByCode(ULONG64 beginAddr, ULONG64 endAddr, PFindCode  findCode, ULONG size);

ULONG64 SearchNtCode(PCHAR code);

ULONG64 SearchNtCodeHead(PCHAR code, ULONG64 headOffset);

ULONG64 SearchCode(PCHAR code, ULONG_PTR saddr, ULONG_PTR size);

//����ģ��հ׵ط�
ULONG64 findSpaceCode(ULONG64 BaseAddress);


ULONG64 SearchNtCodeVar(PCHAR code, ULONG64 headOffset);

ULONG GetWindowsVersionNumber();

NTSTATUS GetNtModuleBaseAndSize(ULONG64 * pModule, ULONG64 * pSize);