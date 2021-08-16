#include <ntddk.h>
#include "common.h"
#include "scan.h"
PMMPTE GetPxeAddress(PVOID addr)
{
    return (PMMPTE)(((((ULONG64)addr & 0xffffffffffff) >> 39) << 3) + g_PXE_BASE);
}
PMMPTE GetPpeAddress(PVOID addr)
{
    return (PMMPTE)(((((ULONG64)addr & 0xffffffffffff) >> 30) << 3) + g_PPE_BASE);
}
PMMPTE GetPdeAddress(PVOID addr)
{
    return (PMMPTE)(((((ULONG64)addr & 0xffffffffffff) >> 21) << 3) + g_PDE_BASE);
}
PMMPTE GetPteAddress(PVOID addr)
{
    return (PMMPTE)(((((ULONG64)addr & 0xffffffffffff) >> 12) << 3) + g_PTE_BASE);
}
NTSTATUS ScanBigPool()
{
    PSYSTEM_BIGPOOL_INFORMATION pBigPoolInfo;
    ULONG64 ReturnLength = 0;
    NTSTATUS status;
    ULONG i = 0;
    int num = 0;

    //����Ƿ�ҳ�أ����Ϊ��ttt'
    pBigPoolInfo = (PSYSTEM_BIGPOOL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, sizeof(SYSTEM_BIGPOOL_INFORMATION), 'ttt');
    /*
    * ��ΪZwQuerySystemInformation��ѯ���ǲ�������
    ���� �ȸ�ZwQuerySystemInformationһ��С���ڴ����򣬷��ش����status��
    Ȼ��ͨ��ReturnLength�õ�����Ҫ�ĳ��ȣ��ٴ�����һƬ�㹻����ڴ�ռ䣬
    ΪZwQuerySystemInformation����ֵ�ṩ�㹻�Ŀռ䣬���������õ�ϵͳ�е���Ϣ ��
    */
    status = ZwQuerySystemInformation(0x42/*SystemBigPoolInformation*/, pBigPoolInfo, sizeof(SYSTEM_BIGPOOL_INFORMATION), /*Out*/&ReturnLength);
    DbgPrint("pBigPoolInfo->Count - %d \n", pBigPoolInfo->Count);
    DbgPrint("ReturnLength - %p \n", ReturnLength);
    ExFreePool(pBigPoolInfo);
    pBigPoolInfo = (PSYSTEM_BIGPOOL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ReturnLength + 0x1000, 'ttt');
    if (!pBigPoolInfo)
        return STATUS_UNSUCCESSFUL;
    status = ZwQuerySystemInformation(0x42, pBigPoolInfo, ReturnLength + 0x1000, &ReturnLength);
    if (status != STATUS_SUCCESS)
    {
        DbgPrint("query BigPoolInfo failed: %p\n", status);
        return status;
    }
    DbgPrint("pBigPoolInfo: %p\n", pBigPoolInfo);
    //������ѯ
    for (i = 0; i < pBigPoolInfo->Count; i++)
    {
        PVOID addr = pBigPoolInfo->AllocatedInfo[i].VirtualAddress;
        ULONG64 size = (ULONG64)pBigPoolInfo->AllocatedInfo[i].SizeInBytes;
        PULONG64 ppte = (PULONG64)GetPteAddress(addr);
        ULONG64 pte = *ppte;
        PULONG64 ppde = (PULONG64)GetPdeAddress(addr);
        ULONG64 pde = *ppde;

        if (size >= 0x8000)
        {
            //Table 4-18. Format of a Page-Directory Entry that Maps a 2-MByte Page
            //8 (G) Global; if CR4.PGE = 1, determines whether the translation is global (see Section 4.10); ignored otherwise
            if (pde & 0x80) {//big page

            }
            else {

                if ((pte & 0x8000000000000000) == 0 && (pte & 1)) {
                    pte |= 0x8000000000000000;
                    //*ppte = pte;
                    DbgPrint("addr: %p, size: %p, pte: %p, nom\n", addr, size, pte);
                    num += 1;
                }
            }
        }
    }
    DbgPrint("num: %d\n", num);
    ExFreePool(pBigPoolInfo);
    return status;
}