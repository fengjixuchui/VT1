#include <ntifs.h>
#include "VMXTools.h"
#include "vmx.h"
#include "vmxs.h"
#include "vmxSsdt.h"
#include "VmxSsdtHook.h"
#include "ExportApi.h"
#include "PageHook.h"
#include "TestHook.h"

extern ULONG64 NtOpenProcessRet =0;

VOID VmxStartVT(_In_ struct _KDPC *Dpc,_In_opt_ PVOID DeferredContext,_In_opt_ PVOID SystemArgument1,_In_opt_ PVOID SystemArgument2)
{
	do 
	{
		
		if (!VmxIsCheckSupportVTCPUID())
		{
			DbgPrintEx(77, 0, "[db]:VmxIsCheckSupportVTCPUID  number = %d\r\n", KeGetCurrentProcessorNumber());
			break;
		}

		if (!VmxIsCheckSupportVTBIOS())
		{
			DbgPrintEx(77, 0, "[db]:VmxIsCheckSupportVTBIOS  number = %d\r\n", KeGetCurrentProcessorNumber());
			break;
		}

		if (!VmxIsCheckSupportVTCr4())
		{
			DbgPrintEx(77, 0, "[db]:VmxIsCheckSupportVTCr4  number = %d\r\n", KeGetCurrentProcessorNumber());
			break;
		}

		//VmxSetNewSysCallEntry(KiSystemCall64Shadow);

		VmxInit(DeferredContext);
	} while (0);
	

	KeSignalCallDpcDone(SystemArgument1);
	KeSignalCallDpcSynchronize(SystemArgument2);
}

VOID VmxStopVT(_In_ struct _KDPC *Dpc, _In_opt_ PVOID DeferredContext, _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2)
{
	AsmVmCall('babq',NULL,NULL,NULL,NULL);
	VmxDestory();
	//VmxDestorySsdtHook();
	KeSignalCallDpcDone(SystemArgument1);
	KeSignalCallDpcSynchronize(SystemArgument2);
}


EXTERN_C NTSTATUS NTAPI MyOpenProcess(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId
)
{

}

VOID DriverUnload(PDRIVER_OBJECT pDriver)
{
	KeGenericCallDpc(VmxStopVT, NULL);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg)
{
	//VmxInitSsdtHook();
	NtOpenProcessRet = (ULONG64)NtOpenProcess + 0x14;
	KeGenericCallDpc(VmxStartVT, AsmVmxExitHandler);
	

	EptPageHook(NtOpenProcess, AsmNtOpenProcess);

	pDriver->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}