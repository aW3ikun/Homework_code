#include"sc.h"
inline void chMB(PCSTR szMsg) {
    char szTitle[MAX_PATH];
    GetModuleFileNameA(NULL, szTitle, _countof(szTitle));
    MessageBoxA(GetActiveWindow(), szMsg, szTitle, MB_OK);
}
BOOL SystemServiceOperate(CString lpszDriverPath, int iOperateType)
{
    BOOL bRet = TRUE;
    CString szName;
    szName.Append(lpszDriverPath);
    // ���˵��ļ�Ŀ¼����ȡ�ļ���
    PathStripPath((LPWSTR)szName.GetString());
    int tag = szName.Find(L".");
    szName = szName.Left(tag);
    SC_HANDLE shOSCM = NULL, shCS = NULL;
    SERVICE_STATUS ss;
    DWORD dwErrorCode = 0;
    BOOL bSuccess = FALSE;
    // �򿪷�����ƹ��������ݿ�
    shOSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!shOSCM)
    {        
        chMB("�򿪷��������ʧ��");
        return FALSE;
    }
    if (0 != iOperateType)
    {
        // ��һ���Ѿ����ڵķ���
        shCS = OpenService(shOSCM, szName, SERVICE_ALL_ACCESS);
        if (!shCS)
        {           
            chMB("�򿪷���ʧ��");
            CloseServiceHandle(shOSCM);
            shOSCM = NULL;
            return FALSE;
        }
    }
    switch (iOperateType)
    {
    case 0:
    {
        // ��������
        // SERVICE_AUTO_START   ��ϵͳ�Զ�����
        // SERVICE_DEMAND_START �ֶ�����
        shCS = CreateService(shOSCM, szName, szName,
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            lpszDriverPath, NULL, NULL, NULL, NULL, NULL);
        if (!shCS)
        {            
            int i = GetLastError();
            CString   cStr;
            cStr.Format(_T("%d"), i);
            MessageBox(NULL, cStr.GetString(), NULL, MB_OK);
            bRet = FALSE;
        }
        break;
    }
    case 1:
    {
        // ��������
        if (!StartService(shCS, 0, NULL))
        {            
            int i = GetLastError();
            CString   cStr;
            cStr.Format(_T("%d"), i);
            MessageBox(NULL, cStr.GetString(), NULL, MB_OK);
            bRet = FALSE;
        }
        break;
    }
    case 2:
    {
        // ֹͣ����
        if (!ControlService(shCS, SERVICE_CONTROL_STOP, &ss))
        {            
            int i = GetLastError();
            CString   cStr;
            cStr.Format(_T("%d"), i);
            MessageBox(NULL, cStr.GetString(), NULL, MB_OK);
            bRet = FALSE;
        }
        break;
    }
    case 3:
    {
        // ɾ������
        if (!DeleteService(shCS))
        {            
            int i = GetLastError();
            CString   cStr;
            cStr.Format(_T("%d"), i);
            MessageBox(NULL, cStr.GetString(), NULL, MB_OK);
            bRet = FALSE;
        }
        break;
    }
    default:
        break;
    }
    // �رվ��
    if (shCS)
    {
        CloseServiceHandle(shCS);
        shCS = NULL;
    }
    if (shOSCM)
    {
        CloseServiceHandle(shOSCM);
        shOSCM = NULL;
    }
    return bRet;
}