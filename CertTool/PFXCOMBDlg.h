#pragma once
#include "afxwin.h"
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define FORMAT_UNDEF	0
#define FORMAT_ASN1		1
#define FORMAT_TEXT		2
#define FORMAT_PEM		3
#define FORMAT_NETSCAPE	4
#define FORMAT_PKCS12	5
#define FORMAT_SMIME	6
#define FORMAT_ENGINE	7
#define FORMAT_IISSGC	8	/* XXX this stupid macro helps us to avoid
				 * adding yet another param to load_*key() */
#define FORMAT_PEMRSA	9	/* PEM RSAPubicKey format */
#define FORMAT_ASN1RSA	10	/* DER RSAPubicKey format */
#define FORMAT_MSBLOB	11	/* MS Key blob format */
#define FORMAT_PVK		12	/* MS PVK file format */

#define NOKEYS			0x1
#define NOCERTS 		0x2
#define INFO			0x4
#define CLCERTS			0x8
#define CACERTS			0x10

typedef struct pw_cb_data
{
	const void *password;
	const char *prompt_info;
} PW_CB_DATA;

// CPFXCOMBDlg dialog

class CPFXCOMBDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CPFXCOMBDlg)

public:
	CPFXCOMBDlg(CWnd* pParent = NULL);   // standard constructor
	virtual ~CPFXCOMBDlg();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_CONFIG_INFO_DIALOG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	virtual BOOL OnInitDialog();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedCaFileButton();
	CEdit m_cafile;
	CEdit m_crlfile;
	CEdit m_certfile;
	CEdit m_keyfile;
	afx_msg void OnBnClickedCertFileButton();
	afx_msg void OnBnClickedPrivateKeyButton();
	afx_msg void OnBnClickedCombButton();
	CEdit m_pin;
	CComboBox m_combo;
	
	CEdit m_expin;
};
