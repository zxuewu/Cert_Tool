// CertInfoDlg.cpp : implementation file
//

#include "stdafx.h"
#include "CertTool.h"
#include "CertInfoDlg.h"
#include "afxdialogex.h"


// CCertInfoDlg dialog

IMPLEMENT_DYNAMIC(CCertInfoDlg, CDialogEx)

CCertInfoDlg::CCertInfoDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_DIALOG1, pParent)
	, m_content(_T(""))
{

}

CCertInfoDlg::~CCertInfoDlg()
{
}

void CCertInfoDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_CERTINFO_EDIT, m_certinfoEditBox);
	DDX_Text(pDX, IDC_CERTINFO_EDIT, m_content);
}


BEGIN_MESSAGE_MAP(CCertInfoDlg, CDialogEx)
END_MESSAGE_MAP()


// CCertInfoDlg message handlers
// CertInfoDlg.cpp : implementation file
//

#include "stdafx.h"
#include "CertTool.h"
#include "CertInfoDlg.h"
#include "afxdialogex.h"


// CertInfoDlg dialog

IMPLEMENT_DYNAMIC(CertInfoDlg, CDialogEx)

CertInfoDlg::CertInfoDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_CERTINFO_DIALOG, pParent)
{

}

CertInfoDlg::~CertInfoDlg()
{
}

void CertInfoDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CertInfoDlg, CDialogEx)
END_MESSAGE_MAP()


// CertInfoDlg message handlers
