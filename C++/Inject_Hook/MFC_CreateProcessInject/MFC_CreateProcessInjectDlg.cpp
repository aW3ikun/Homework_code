
// MFC_CreateProcessInjectDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "MFC_CreateProcessInject.h"
#include "MFC_CreateProcessInjectDlg.h"
#include "afxdialogex.h"
#include"help.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CMFCCreateProcessInjectDlg 对话框



CMFCCreateProcessInjectDlg::CMFCCreateProcessInjectDlg(CWnd* pParent /*=nullptr*/)
	: CDialog(IDD_MFC_CREATEPROCESSINJECT_DIALOG, pParent)
	, pszLog(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMFCCreateProcessInjectDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT_Log, pszLog);
}

BEGIN_MESSAGE_MAP(CMFCCreateProcessInjectDlg, CDialog)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON_SelectFile, &CMFCCreateProcessInjectDlg::OnBnClickedButtonSelectfile)
	ON_EN_CHANGE(IDC_EDIT_FilePath, &CMFCCreateProcessInjectDlg::OnEnChangeEditFilepath)
	ON_BN_CLICKED(IDC_BUTTON_Inject, &CMFCCreateProcessInjectDlg::OnBnClickedButtonInject)
	ON_EN_CHANGE(IDC_EDIT_Log, &CMFCCreateProcessInjectDlg::OnEnChangeEditLog)
	ON_EN_CHANGE(IDC_EDIT_DllPath, &CMFCCreateProcessInjectDlg::OnEnChangeEditDllpath)
	ON_BN_CLICKED(IDC_BUTTON_SelectDll, &CMFCCreateProcessInjectDlg::OnBnClickedButtonSelectdll)
	ON_EN_UPDATE(IDC_EDIT_Log, &CMFCCreateProcessInjectDlg::OnEnUpdateEditLog)
END_MESSAGE_MAP()


// CMFCCreateProcessInjectDlg 消息处理程序

BOOL CMFCCreateProcessInjectDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CMFCCreateProcessInjectDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialog::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CMFCCreateProcessInjectDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CMFCCreateProcessInjectDlg::OnBnClickedButtonSelectfile()
{
	// TODO: 在此添加控件通知处理程序代码
	TCHAR szFilters[] = L"EXE Files (*.exe) |*.exe|All Files(*.*) |*.*|";
	CFileDialog fileDialog(TRUE, L"PE文件选择对话框",NULL, OFN_FILEMUSTEXIST | OFN_HIDEREADONLY, szFilters);

	if (fileDialog.DoModal() == IDOK) {
		CString pathName = fileDialog.GetPathName();

		CEdit *edit = (CEdit * )GetDlgItem(IDC_EDIT_FilePath);
		edit->SetWindowTextW(pathName);
	}

}

void CMFCCreateProcessInjectDlg::OnEnChangeEditFilepath()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialog::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
}


void CMFCCreateProcessInjectDlg::OnBnClickedButtonInject()
{
	// TODO: 在此添加控件通知处理程序代码
	CString filePath;
	CString dllPath;
	GetDlgItemText(IDC_EDIT_FilePath, filePath);
	GetDlgItemText(IDC_EDIT_DllPath, dllPath);


	if (!filePath.IsEmpty() && !dllPath.IsEmpty()) {

		pszLog += "[+]文件地址正确! \r\n";
		UpdateData(FALSE);
		if (Inject(filePath,dllPath,pszLog)) {
			pszLog += "[+]注入成功! \r\n ";
			UpdateData(FALSE);
		}
		else {
			pszLog += "[-]注入失败! \r\n";
			UpdateData(FALSE);
		}

	}
	else {
		pszLog += "[-]文件地址错误! \r\n";
		UpdateData(FALSE);
	}
}


void CMFCCreateProcessInjectDlg::OnEnChangeEditLog()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialog::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码

	CEdit* edit = (CEdit*)GetDlgItem(IDC_EDIT_Log);
	edit->SetWindowTextW(pszLog);
	//自动滚动
	edit->LineScroll(edit->GetLineCount());
	
}


void CMFCCreateProcessInjectDlg::OnEnChangeEditDllpath()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialog::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
}


void CMFCCreateProcessInjectDlg::OnBnClickedButtonSelectdll()
{
	// TODO: 在此添加控件通知处理程序代码

	TCHAR szFilters[] = L"DLL Files (*.dll) |*.dll|All Files(*.*) |*.*|";
	CFileDialog fileDialog(TRUE, L"DLL文件选择对话框", NULL, OFN_FILEMUSTEXIST | OFN_HIDEREADONLY, szFilters);

	if (fileDialog.DoModal() == IDOK) {
		CString pathName = fileDialog.GetPathName();

		CEdit* edit = (CEdit*)GetDlgItem(IDC_EDIT_DllPath);
		edit->SetWindowTextW(pathName);
	}
}


void CMFCCreateProcessInjectDlg::OnEnUpdateEditLog()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialog::OnInitDialog()
	// 函数，以将 EM_SETEVENTMASK 消息发送到该控件，
	// 同时将 ENM_UPDATE 标志“或”运算到 lParam 掩码中。

	// TODO:  在此添加控件通知处理程序代码
	
}
