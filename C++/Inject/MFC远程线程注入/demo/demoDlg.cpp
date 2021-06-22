
// demoDlg.cpp : implementation file
//

#include "pch.h"
#include "framework.h"
#include "demo.h"
#include "demoDlg.h"
#include "afxdialogex.h"
#include"help.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CAboutDlg dialog used for App About

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

	// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CdemoDlg dialog



CdemoDlg::CdemoDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_DEMO_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CdemoDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CdemoDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON_Inject, &CdemoDlg::OnBnClickedButtonInject)
	ON_BN_CLICKED(IDC_BUTTON_Dll, &CdemoDlg::OnBnClickedButtonDll)
	ON_BN_CLICKED(IDC_BUTTON_UnLoad, &CdemoDlg::OnBnClickedButtonUnload)
END_MESSAGE_MAP()


// CdemoDlg message handlers

BOOL CdemoDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here

	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CdemoDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CdemoDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CdemoDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CdemoDlg::OnBnClickedButtonInject()
{
	// TODO: 在此添加控件通知处理程序代码
	//DWORD dwProcessId = 0;
	//CString szEdit;
	//GetDlgItem(IDC_EDIT_ProcessId)->GetWindowText(szEdit);
	//dwProcessId = _ttoi(szEdit);
	DWORD dwProcessId = GetDlgItemInt(IDC_EDIT_ProcessId, NULL, 0);
	if (dwProcessId == 0) {
		dwProcessId = GetCurrentProcessId();
	}
	CString dllPath;
	GetDlgItemText(IDC_EDIT_DllPath, dllPath);
	if (!dllPath.IsEmpty()) {
		if (InjectLib(dwProcessId, (LPWSTR)dllPath.GetString())) {
			chMB("Inject Success!\t");
		}
		else {
			chMB("Inject Failed!");
		}
	}
	else {
		chMB("Dll Empty!");
	}
}


void CdemoDlg::OnBnClickedButtonDll()
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


void CdemoDlg::OnBnClickedButtonUnload()
{
	// TODO: 在此添加控件通知处理程序代码
	CString dllPath;
	GetDlgItemText(IDC_EDIT_DllPath, dllPath);
	if (!dllPath.IsEmpty()) {
		DWORD dwProcessId = GetDlgItemInt(IDC_EDIT_ProcessId, NULL, 0);
		if (dwProcessId == 0) {
			dwProcessId = GetCurrentProcessId();
		}

		if (FreeLib(dwProcessId, (LPWSTR)dllPath.GetString())) {
			chMB("Free Success!\t");
		}
		else {
			chMB("Free Failed!");
		}
	}
	else {
		chMB("Dll Empty!");
	}
}
