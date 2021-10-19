
// MFC_CreateProcessInjectDlg.h: 头文件
//

#pragma once


// CMFCCreateProcessInjectDlg 对话框
class CMFCCreateProcessInjectDlg : public CDialog
{
// 构造
public:
	CMFCCreateProcessInjectDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MFC_CREATEPROCESSINJECT_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButtonSelectfile();
	afx_msg void OnEnChangeEditFilepath();
	afx_msg void OnBnClickedButtonInject();
	CString pszLog;
	afx_msg void OnEnChangeEditLog();
	afx_msg void OnEnChangeEditDllpath();
	afx_msg void OnBnClickedButtonSelectdll();
	afx_msg void OnEnUpdateEditLog();
};
