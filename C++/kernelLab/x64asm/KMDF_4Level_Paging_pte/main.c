#include<ntddk.h>
#include "common.h"
#include "scan.h"



ULONG64 g_PTE_BASE;
ULONG64 g_PDE_BASE;
ULONG64 g_PPE_BASE;
ULONG64 g_PXE_BASE;

ULONG64 GetPteAddress(ULONG64 addr) {
	return (ULONG64)((((addr & 0xFFFFFFFFFFFF) >> 12) << 3) + g_PTE_BASE);
}
ULONG64 GetPdeAddress(ULONG64 addr) {
	return (ULONG64)((((addr & 0xFFFFFFFFFFFF) >> 21) << 3) + g_PDE_BASE);
}
ULONG64 GetPpeAddress(ULONG64 addr) {
	return (ULONG64)((((addr & 0xFFFFFFFFFFFF) >> 30) << 3) + g_PPE_BASE);
}
ULONG64 GetPxeAddress(ULONG64 addr) {
	return (ULONG64)((((addr & 0xFFFFFFFFFFFF) >> 39) << 3) + g_PXE_BASE);
}

//https://bbs.pediy.com/thread-262432.htm
//根据cr3获取pte_base
ULONG_PTR PTEBase = 0;
BOOLEAN hzqstGetPTEBase()
{
	BOOLEAN Result = FALSE;
	ULONG_PTR PXEPA = __readcr3() & 0xFFFFFFFFF000;
	PHYSICAL_ADDRESS PXEPAParam;
	PXEPAParam.QuadPart = (LONGLONG)PXEPA;
	ULONG_PTR PXEVA = (ULONG_PTR)MmGetVirtualForPhysical(PXEPAParam);
	if (PXEVA)
	{
		ULONG_PTR PXEOffset = 0;
		do
		{
			if ((*(PULONGLONG)(PXEVA + PXEOffset) & 0xFFFFFFFFF000) == PXEPA)
			{
				PTEBase = (PXEOffset + 0xFFFF000) << 36;
				Result = TRUE;
				break;
			}
			PXEOffset += 8;
		} while (PXEOffset < PAGE_SIZE);
	}
	return Result;
}

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	KdPrint(("退出驱动\n"));
}

//C:\Users\kernelDebug\Desktop\KMDF_4Level_Paging_pte.sys
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	pDriverObject->DriverUnload = DriverUnload;
	ULONG64 transfer_address = 0xfffff8034f25dfb0;

	g_PTE_BASE = *(ULONG64*)((ULONG64)MmProtectMdlSystemAddress + 0xc7 + 0x2);

	//hzqstGetPTEBase();
	//g_PTE_BASE = (ULONG64)PTEBase;
	//DbgPrint("%p\n", g_PTE_BASE);

	g_PDE_BASE = (g_PTE_BASE + ((g_PTE_BASE & 0xffffffffffff) >> 9));
	g_PPE_BASE = (g_PTE_BASE + ((g_PDE_BASE & 0xffffffffffff) >> 9));
	g_PXE_BASE = (g_PTE_BASE + ((g_PPE_BASE & 0xffffffffffff) >> 9));
	DbgPrint("pte at: %p\n", g_PTE_BASE);
	DbgPrint("pde at: %p\n", g_PDE_BASE);
	DbgPrint("ppe at: %p\n", g_PPE_BASE);
	DbgPrint("pxe at: %p\n", g_PXE_BASE);

	ScanBigPool();
	return STATUS_SUCCESS;
}