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
    // 过滤掉文件目录，获取文件名
    PathStripPath((LPWSTR)szName.GetString());
    int tag = szName.Find(L".");
    szName = szName.Left(tag);
    SC_HANDLE shOSCM = NULL, shCS = NULL;
    SERVICE_STATUS ss;
    DWORD dwErrorCode = 0;
    BOOL bSuccess = FALSE;
    // 打开服务控制管理器数据库
    shOSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!shOSCM)
    {        
        chMB("打开服务管理器失败");
        return FALSE;
    }
    if (0 != iOperateType)
    {
        // 打开一个已经存在的服务
        shCS = OpenService(shOSCM, szName, SERVICE_ALL_ACCESS);
        if (!shCS)
        {           
            chMB("打开服务失败");
            CloseServiceHandle(shOSCM);
            shOSCM = NULL;
            return FALSE;
        }
    }
    switch (iOperateType)
    {
    case 0:
    {
        // 创建服务
        // SERVICE_AUTO_START   随系统自动启动
        // SERVICE_DEMAND_START 手动启动
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
        // 启动服务
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
        // 停止服务
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
        // 删除服务
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
    // 关闭句柄
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