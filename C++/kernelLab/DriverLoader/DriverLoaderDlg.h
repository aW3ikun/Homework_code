﻿
// DriverLoaderDlg.h: 头文件
//

#pragma once

// CDriverLoaderDlg 对话框
class CDriverLoaderDlg : public CDialogEx
{
// 构造
public:
	CDriverLoaderDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DRIVERLOADER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnEnChangeEditFile();
	afx_msg void OnBnClickedButtonstart();
	afx_msg void OnBnClickedButtonStop();
	afx_msg void OnBnClickedButtonUnload();
	afx_msg void OnBnClickedButtonInstall();
	CMFCEditBrowseCtrl my_syspath;
};
