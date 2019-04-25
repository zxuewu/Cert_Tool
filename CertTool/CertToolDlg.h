
// CertToolDlg.h : header file
//

#pragma once
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/gm.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/objects.h>

#include "afxwin.h"
#include "CertInfoDlg.h"
#include "PFXCOMBDlg.h"
#include "DebugPrint.h"
#include "PFXDISADlg.h"

#ifdef SIGPIPE
#define do_pipe_sig()	signal(SIGPIPE,SIG_IGN)
#else
#define do_pipe_sig()
#endif

// CCertToolDlg dialog
class CCertToolDlg : public CDialogEx
{
// Construction
public:
	CCertToolDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_CERTTOOL_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedCertButton();
	CListBox m_ListBox;
	afx_msg void OnBnClickedCertDeleteButton();
	afx_msg void OnLbnDblclkCertList();
	afx_msg void OnBnClickedShowCertinfoButton();
	afx_msg void OnBnClickedP7bCombButton();
	afx_msg void OnBnClickedP7bSepaButton();
	afx_msg void OnBnClickedPemDerButton();
	afx_msg void OnBnClickedDerPemButton();
	afx_msg void OnBnClickedPfxPemButton();
	afx_msg void OnBnClickedPemPfxButton();
	afx_msg void OnBnClickedGenCaButton();
};
