#pragma once
#include "afxwin.h"
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

#ifdef SIGPIPE
#define do_pipe_sig()	signal(SIGPIPE,SIG_IGN)
#else
#define do_pipe_sig()
#endif

// PFXDISADlg dialog

class PFXDISADlg : public CDialogEx
{
	DECLARE_DYNAMIC(PFXDISADlg)

public:
	PFXDISADlg(CWnd* pParent = NULL);   // standard constructor
	virtual ~PFXDISADlg();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG2 };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedExpButton();
	CEdit m_certpin;
	CEdit m_keypin;
	afx_msg void OnBnClickedPfxFileButton();
	CEdit m_pfxfile;
};
