#pragma once
#include "afxwin.h"


// CCertInfoDlg dialog

class CCertInfoDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CCertInfoDlg)

public:
	CCertInfoDlg(CWnd* pParent = NULL);   // standard constructor
	virtual ~CCertInfoDlg();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG1 };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	CEdit m_certinfoEditBox;
	CString m_content;
};
#pragma once


// CertInfoDlg dialog

class CertInfoDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CertInfoDlg)

public:
	CertInfoDlg(CWnd* pParent = NULL);   // standard constructor
	virtual ~CertInfoDlg();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_CERTINFO_DIALOG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
};
