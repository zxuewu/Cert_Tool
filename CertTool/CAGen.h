#pragma once
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include "afxwin.h"
// CCAGen dialog

class CCAGen : public CDialogEx
{
	DECLARE_DYNAMIC(CCAGen)

public:
	CCAGen(CWnd* pParent = NULL);   // standard constructor
	virtual ~CCAGen();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_GEN_CA_DIALOG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedGenButton();
	CComboBox m_keylength;
	virtual BOOL OnInitDialog();
	CComboBox m_countryname;
	CEdit m_province;
	CEdit m_city;
	CEdit m_organization;
	CEdit m_organizationunit;
	CEdit m_commonname;
	CEdit m_privatekeypin;
};
