#include"pch.h"
#include"help.h"

BOOL Inject(CString pszfilePath, CString pszdllPath,CString &pszLog) {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    BOOL bOK = FALSE;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    
    //�������
    if (CreateProcess(pszfilePath,
        NULL,
        NULL,
        FALSE,
        NULL,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi)) {
        CString pszProcess;
        pszProcess.Format(L"ProcessId: %d \r\n", pi.dwProcessId);
        pszLog += pszProcess.GetString();

        //EIP Hook
        CONTEXT Context = { 0 };
        Context.ContextFlags = CONTEXT_FULL;
        BYTE bHeadCode[6] = { 0 };
        if (GetThreadContext(pi.hThread, &Context)) {
            pszLog += "[+]��ȡ�����ĳɹ�! \r\n";
            //��ȡǰ���ֽ�
            if (ReadProcessMemory(pi.hProcess, (LPCVOID)Context.Eip, bHeadCode, sizeof(bHeadCode), NULL)) {
                pszLog += "[+]��ȡEIP�ɹ�! \r\n";
                //���뾲̬�����ռ�
                //����shellcode�ռ�
                if (VirtualAllocEx(pi.hProcess, NULL, pszdllPath.GetLength() + 1, MEM_COMMIT, PAGE_READWRITE)) {
                    pszLog += "[+]����Dll·���ڴ�ɹ�! \r\n";
                    //WriteProcessMemory(pi.hProcess, )

                    bOK = TRUE;
                }
                else {
                    pszLog += "[-]����Dll·���ڴ�ʧ��! \r\n";
                }
            }
            else {
                pszLog += "[-]��ȡEIPʧ��! \r\n";
            }
        }
        else {
            pszLog += "[-]��ȡ������ʧ��! \r\n";
        }

        ResumeThread(pi.hThread);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return bOK;
    }
    else {
        pszLog += "[-]���ؽ���ʧ��! \r\n";
        return bOK;
    }
}
