
// CertToolDlg.cpp : implementation file
//

#include "stdafx.h"
#include "CertTool.h"
#include "CertToolDlg.h"
#include "afxdialogex.h"
#include "windows.h"
#include <string>
#include "SSLTool.h"

#ifdef __cplusplus
extern "C" {
#endif
#include <openssl/applink.c>
#ifdef __cplusplus
}
#endif // __cplusplus

#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

# define PKCS12_F_OPENSSL_UNI2UTF8						127
# define NOKEYS											0x1
# define NOCERTS										0x2
# define INFO											0x4
# define CLCERTS										0x8
# define CACERTS										0x10

#define PASSWD_BUF_SIZE									2048
// CAboutDlg dialog used for App About

BIO *bio_err;

void print_client_certificate(char *path, wchar_t **buf);
void UTF_8StrToUnicode(WCHAR* pOut, int &nOutLen, const char *pText);
char* tolower(char *ch);
static int add_certs_from_file(STACK_OF(X509) *stack, char *certfile);
int dump_cert_text(BIO *out, X509 *x);
//static int bmp_to_utf8(char *str, unsigned char *utf16, int len);
//char *OPENSSL_uni2utf8(unsigned char *uni, int unilen);
//int dump_certs_keys_p12(BIO *out, PKCS12 *p12, const char *pass,
//	int passlen, int options, char *pempass,
//	const EVP_CIPHER *enc);
//int dump_certs_pkeys_bags(BIO *out, const STACK_OF(PKCS12_SAFEBAG) *bags,
//	const char *pass, int passlen, int options,
//	char *pempass, const EVP_CIPHER *enc);
//int dump_certs_pkeys_bag(BIO *out, PKCS12_SAFEBAG *bag, const char *pass,
//	int passlen, int options, char *pempass, const EVP_CIPHER *enc);
void ASN1_String2UTF_8(wchar_t** out, int &nOutLen, const char *src, int srclen);
void char2wchar_t(char *in, wchar_t** out);

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


// CCertToolDlg dialog



CCertToolDlg::CCertToolDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_CERTTOOL_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDI_ICON1);
}

void CCertToolDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_CERT_LIST, m_ListBox);
}

BEGIN_MESSAGE_MAP(CCertToolDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_CERT_ADD_BUTTON, &CCertToolDlg::OnBnClickedCertButton)
	ON_BN_CLICKED(IDC_CERT_DELETE_BUTTON, &CCertToolDlg::OnBnClickedCertDeleteButton)
	ON_LBN_DBLCLK(IDC_CERT_LIST, &CCertToolDlg::OnLbnDblclkCertList)
	ON_BN_CLICKED(IDC_SHOW_CERTINFO_BUTTON, &CCertToolDlg::OnBnClickedShowCertinfoButton)
	ON_BN_CLICKED(IDC_P7B_COMB_BUTTON, &CCertToolDlg::OnBnClickedP7bCombButton)
	ON_BN_CLICKED(IDC_P7B_SEPA_BUTTON, &CCertToolDlg::OnBnClickedP7bSepaButton)
	ON_BN_CLICKED(IDC_PEM_DER_BUTTON, &CCertToolDlg::OnBnClickedPemDerButton)
	ON_BN_CLICKED(IDC_DER_PEM_BUTTON, &CCertToolDlg::OnBnClickedDerPemButton)
	ON_BN_CLICKED(IDC_PFX_PEM_BUTTON, &CCertToolDlg::OnBnClickedPfxPemButton)
	ON_BN_CLICKED(IDC_PEM_PFX_BUTTON, &CCertToolDlg::OnBnClickedPemPfxButton)
	ON_BN_CLICKED(IDC_GEN_CA_BUTTON, &CCertToolDlg::OnBnClickedGenCaButton)
END_MESSAGE_MAP()


// CCertToolDlg message handlers

BOOL CCertToolDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
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
	SSL_library_init();
	SSL_load_error_strings();
	GM_load_library_ex();
	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CCertToolDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

void CCertToolDlg::OnPaint()
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
HCURSOR CCertToolDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CCertToolDlg::OnBnClickedCertButton()
{
	// TODO: Add your control notification handler code here
	BOOL isOpen = TRUE;		//是否打开(否则为保存)
	CString defaultDir = L"C:\\";	//默认打开的文件路径
	CString fileName = L"";			//默认打开的文件名
	CString filter = L"文件 (*.cer; *.crt; *.pem; *.pfx)|*.cer; *.crt; *.pem; *.pfx||";	//文件过虑的类型
	CFileDialog openFileDlg(isOpen, defaultDir, fileName, OFN_HIDEREADONLY | OFN_READONLY, filter, NULL);
	openFileDlg.GetOFN().lpstrInitialDir = L"E:\\FileTest\\test.doc";
	INT_PTR result = openFileDlg.DoModal();
	CString filePath = L"";
	if (result == IDOK) {
		filePath = openFileDlg.GetPathName();
		m_ListBox.LockWindowUpdate();//禁止本listbox刷新。
									 //添加数据
		m_ListBox.AddString(filePath);
		m_ListBox.UnlockWindowUpdate();
	}
	//CListBox *pList = (CListBox*)GetDlgItem(IDC_CERT_LIST); //获取控件指针
}


void CCertToolDlg::OnBnClickedCertDeleteButton()
{
	// TODO: Add your control notification handler code here
	CListBox *pList = (CListBox*)GetDlgItem(IDC_CERT_LIST); //获取控件指针  
	int Index = pList->GetCurSel(); //获取鼠标选中条目
	pList->DeleteString(Index);  //删除该条目
}


void CCertToolDlg::OnLbnDblclkCertList()
{
	// TODO: Add your control notification handler code here
	CString certname, certinfo;
	CCertInfoDlg certinfoDlg;
	wchar_t *cert_info;

	cert_info = new wchar_t[1024];

	int Index = m_ListBox.GetCurSel(); //获取鼠标选中条目
	if (Index < 0)
	{
		AfxMessageBox(_T("请选择一张证书!"));
		return;
	}
	m_ListBox.GetText(Index, certname); //删除该条目
	print_client_certificate(_bstr_t(certname), &cert_info);
	//print_client_certificate2(_bstr_t(certname), &cstr);
	//WideCharToMultiByte(CP_ACP, 0, cert_info, wcslen(cert_info), cstr, wcslen(cert_info), NULL, NULL);
	CString cstring(cert_info);
	certinfoDlg.m_content = cstring;
	certinfoDlg.DoModal();
}


void CCertToolDlg::OnBnClickedShowCertinfoButton()
{
	// TODO: Add your control notification handler code here
	CString certname;
	CCertInfoDlg certinfoDlg;

	
	gen_X509Req(&certname);
	
	certinfoDlg.m_content = certname;
	certinfoDlg.DoModal();
}

void print_client_certificate(char *path, wchar_t **buf)
{
	X509			*cert = NULL;
	X509_NAME		*name = NULL;
	X509_NAME_ENTRY *name_entry = NULL;
	int				Nid;
	ASN1_INTEGER	*serial = NULL;
	BIGNUM			*bnser = NULL;
	BIO				*bio_cert = NULL;
	FILE			*fp = NULL;
	int				bufLen = 0;
	char			*Infotmp = NULL;
	int 			nInfotmp;
	int				nLen;
	wchar_t			*pwText = NULL;
	int				dwNum;
	unsigned char	*out = NULL;
	long			version;
	int				entriesNum;
	char			country[256];
	char			organization[256];
	char			organizationalUnit[256];
	char			commonName[256];
	int				subjectLen = 0;
	
	fp = fopen(path, "rb");
	cert = PEM_read_X509(fp, NULL, NULL, cert);

	version = X509_get_version(cert);
	wsprintf(*buf, L"Certificate Version = V%ld\r\n", version);
	bufLen = wcslen(*buf);

	serial = X509_get_serialNumber(cert);
	bnser = ASN1_INTEGER_to_BN(serial, NULL);
	Infotmp = tolower(BN_bn2hex(bnser));
	nInfotmp = strlen(Infotmp);
	char2wchar_t(Infotmp, &pwText);
	wsprintf(*buf + bufLen, L"Serial Number = %s\r\n", pwText);
	/*nLen = MultiByteToWideChar(CP_ACP, 0, Infotmp, strlen(Infotmp), NULL, 0);
	pwText[nLen];
	MultiByteToWideChar(CP_ACP, 0, Infotmp, strlen(Infotmp), pwText, nLen);
	wsprintf(buf + bufLen, L"Serial Number = %s\r\n", pwText);*/
	//Infotmp = NULL;
	bufLen = wcslen(*buf);
	
	name = X509_get_subject_name(cert);

	entriesNum = sk_X509_NAME_ENTRY_num(name->entries);
	
	
	for (int i = 0; i < entriesNum; i++)
	{
		name_entry = sk_X509_NAME_ENTRY_value(name->entries, i);
		Nid = OBJ_obj2nid(name_entry->object);
		Infotmp = NULL;
		if ((nLen = ASN1_STRING_to_UTF8(&out, name_entry->value)) < 0)
		{
			continue;
		}

		if (Nid == NID_countryName)
		{
			if (name_entry->value->type != V_ASN1_PRINTABLESTRING)
			{
				ASN1_String2UTF_8(&pwText, dwNum, (char *)out, nLen);
				wsprintf(*buf + bufLen, L"L = %s\r\n", pwText);
				bufLen = wcslen(*buf);
			}
			else
			{
				char2wchar_t((char *)out, &pwText);
				wsprintf(*buf + bufLen, L"C = %s\r\n", pwText);
				bufLen = wcslen(*buf);
			}
		}
		else if(Nid == NID_localityName)
		{
			if (name_entry->value->type != V_ASN1_PRINTABLESTRING)
			{
				ASN1_String2UTF_8(&pwText, dwNum, (char *)out, nLen);
				wsprintf(*buf + bufLen, L"L = %s\r\n", pwText);
				bufLen = wcslen(*buf);
			}
			else
			{
				char2wchar_t((char *)out, &pwText);
				wsprintf(*buf + bufLen, L"C = %s\r\n", pwText);
				bufLen = wcslen(*buf);
			}
		}
		else if (Nid == NID_stateOrProvinceName)
		{
			if (name_entry->value->type != V_ASN1_PRINTABLESTRING)
			{
				ASN1_String2UTF_8(&pwText, dwNum, (char *)out, nLen);
				wsprintf(*buf + bufLen, L"ST = %s\r\n", pwText);
				bufLen = wcslen(*buf);
			}
			else
			{
				char2wchar_t((char *)out, &pwText);
				wsprintf(*buf + bufLen, L"ST = %s\r\n", pwText);
				bufLen = wcslen(*buf);
			}
		}
		else if (Nid == NID_organizationName)
		{
			if (name_entry->value->type != V_ASN1_PRINTABLESTRING)
			{
				ASN1_String2UTF_8(&pwText, dwNum, (char *)out, nLen);
				wsprintf(*buf + bufLen, L"O = %s\r\n", pwText);
				bufLen = wcslen(*buf);
			}
			else
			{
				char2wchar_t((char *)out, &pwText);
				wsprintf(*buf + bufLen, L"O = %s\r\n", pwText);
				bufLen = wcslen(*buf);
			}
		}
		else if (Nid == NID_organizationalUnitName)
		{
			if (name_entry->value->type != V_ASN1_PRINTABLESTRING)
			{
				ASN1_String2UTF_8(&pwText, dwNum, (char *)out, nLen);
				wsprintf(*buf + bufLen, L"OU = %s\r\n", pwText);
				bufLen = wcslen(*buf);
			}
			else
			{
				char2wchar_t((char *)out, &pwText);
				wsprintf(*buf + bufLen, L"OU = %s\r\n", pwText);
				bufLen = wcslen(*buf);
			}
		}
		else if (Nid == NID_commonName)
		{
			if (name_entry->value->type != V_ASN1_PRINTABLESTRING)
			{
				ASN1_String2UTF_8(&pwText, dwNum, (char *)out, nLen);
				wsprintf(*buf + bufLen, L"CN = %s\r\n", pwText);
				bufLen = wcslen(*buf);
			}
			else
			{
				char2wchar_t((char *)out, &pwText);
				wsprintf(*buf + bufLen, L"CN = %s\r\n", pwText);
				bufLen = wcslen(*buf);
			}
		}
	}


	if (bio_cert)
	{
		BIO_free(bio_cert);
	}

	if (fp)
	{
		fclose(fp);
	}

	if (cert)
	{
		X509_free(cert);
	}
	else if (name)
	{
		X509_NAME_free(name);
	}
	else if (serial)
	{
		ASN1_INTEGER_free(serial);
	}

	if (bnser)
	{
		BN_free(bnser);
	}
}

char* tolower(char *ch)
{
	int i;
	for (i = 0; ch[i] != '\0'; i++)
	{
		if (ch[i] >= 'A'&&ch[i] <= 'Z')
		{
			ch[i] += 32;
		}
	}

	return ch;
}

void ASN1_String2UTF_8(wchar_t** out, int &nOutLen, const char *src, int srclen)
{
	nOutLen = MultiByteToWideChar(CP_ACP, 0, (char *)src, srclen, NULL, 0);

	*out = new wchar_t[nOutLen];
	if (!out)
	{
		delete[]*out;
		*out = NULL;
	}

	MultiByteToWideChar(CP_UTF8, 0, (char *)src, srclen, *out, nOutLen);
	(*out)[nOutLen - 1] = '\0';
}

void char2wchar_t(char *in, wchar_t** out)
{
	int nin, nLen;

	nin = strlen(in);
	nLen = MultiByteToWideChar(CP_ACP, 0, in, nin, NULL, 0);
	*out = new wchar_t[nLen + 1];
	MultiByteToWideChar(CP_ACP, 0, in, nin, *out, nLen);
	(*out)[nLen] = '\0';
	//wsprintf(buf + bufLen, L"Serial Number = %s\r\n", lpszFile);
}

void UTF_8StrToUnicode(WCHAR* pOut, int &nOutLen, const char *pText)
{
	//UTF8 to Unicode
	//预转换，得到所需空间的大小
	int wcsLen = MultiByteToWideChar(CP_UTF8, NULL, pText, (int)strlen(pText), NULL, 0);
	if (NULL == pOut || nOutLen < wcsLen)
	{
		nOutLen = wcsLen;
	}
	else
	{
		//转换
		MultiByteToWideChar(CP_UTF8, NULL, pText, (int)strlen(pText), pOut, nOutLen);
		//最后加上'\0'
		pOut[wcsLen] = '\0';
		nOutLen = wcsLen;
	}
}

void CCertToolDlg::OnBnClickedP7bCombButton()
{
	// TODO: Add your control notification handler code here
	PKCS7						*p7 = NULL;
	PKCS7_SIGNED				*p7s = NULL;
	FILE						*fp=NULL;
	X509						*cert = NULL;
	BIO							*out = NULL;
	STACK_OF(OPENSSL_STRING)	*certflst = NULL;
	STACK_OF(X509)				*cert_stack = NULL;
	STACK_OF(X509_CRL)			*crl_stack = NULL;
	X509_CRL					*crl = NULL;
	char						*certfile, *outfile = "CA_chain.p7b";
	_bstr_t						aaa[10];
	CArray<CString, CString>	ary_filename;
	BOOL						isOpen = TRUE;		//是否打开(否则为保存)
	CString						defaultDir = L"C:\\";	//默认打开的文件路径
	CString						fileName = L"";			//默认打开的文件名
	CString						filter = L"文件 (*.cer; *.crt; *.pem; *.pfx)|*.cer; *.crt; *.pem; *.pfx||";	//文件过虑的类型
	CFileDialog					openFileDlg(isOpen, defaultDir, fileName, OFN_HIDEREADONLY | OFN_READONLY | OFN_ALLOWMULTISELECT, filter, NULL);
	//openFileDlg.GetOFN().lpstrInitialDir = L"E:\\FileTest\\test.doc";
	openFileDlg.m_ofn.nMaxFile = 500 * MAX_PATH;

	wchar_t* ch = new TCHAR[openFileDlg.m_ofn.nMaxFile];
	openFileDlg.m_ofn.lpstrFile = ch;

	//对内存块清零
	ZeroMemory(openFileDlg.m_ofn.lpstrFile, sizeof(TCHAR) * openFileDlg.m_ofn.nMaxFile);

	INT_PTR						result = openFileDlg.DoModal();
	CString						filePath = L"";
	int							i, rc = 0;
	
	if ((certflst == NULL)
		&& (certflst = sk_OPENSSL_STRING_new_null()) == NULL)
	{
		goto exit;
	}

	if (result == IDOK) {
		POSITION pos_file;
		pos_file = openFileDlg.GetStartPosition();
		while (pos_file != NULL) 
		{

			filePath = openFileDlg.GetNextPathName(pos_file);
			ary_filename.Add(filePath);
			
			//char *bbb = aaa;
			//if (!sk_OPENSSL_STRING_push(certflst, (char *)aaa))
				//goto exit;
			
		}

		for (i = 0; i < ary_filename.GetCount(); i++)
		{
			aaa[i] = ary_filename.GetAt(i);
			if (!sk_OPENSSL_STRING_push(certflst, (char *)aaa[i]))
				goto exit;
		}

		
		p7 = PKCS7_new();
		if (p7 == NULL)
		{
			goto exit;
		}
		p7s = PKCS7_SIGNED_new();
		if (p7s == NULL)
		{
			goto exit;
		}

		p7->type = OBJ_nid2obj(NID_pkcs7_signed);
		//PKCS7_set_type(p7, NID_pkcs7_signed);
		p7->d.sign = p7s;
		p7s->contents->type = OBJ_nid2obj(NID_pkcs7_data);
		//PKCS7_content_new(p7, NID_pkcs7_data);
		if (!ASN1_INTEGER_set(p7s->version, 1))
		{
			goto exit;
		}

		if ((crl_stack = sk_X509_CRL_new_null()) == NULL)
		{
			goto exit;
		}
		p7s->crl = crl_stack;

		if (crl != NULL) {
			sk_X509_CRL_push(crl_stack, crl);
			crl = NULL;             /* now part of p7 for OPENSSL_freeing */
		}

		if ((cert_stack = sk_X509_new_null()) == NULL)
		{
			goto exit;
		}
		p7s->cert = cert_stack;

		

		/*for (i = 0; i < ary_filename.GetCount(); i++)
		{
			if (!sk_OPENSSL_STRING_push(certflst, (void *)(char *)_bstr_t(ary_filename.GetAt(i))))
				goto exit;
		}*/

		if (certflst != NULL)
		{
			for (i = 0; i < sk_OPENSSL_STRING_num(certflst); i++) 
			{
				certfile = sk_OPENSSL_STRING_value(certflst, i);
				if (add_certs_from_file(cert_stack, certfile) < 0) 
				{
					BIO_printf(bio_err, "error loading certificates\n");
					ERR_print_errors(bio_err);
					goto exit;
				}
			}
		}

		out = BIO_new_file(outfile, "w"); //w or wb
		i = PEM_write_bio_PKCS7(out, p7);
		if (!i) 
		{
			BIO_printf(bio_err, "unable to write pkcs7 object\n");
			ERR_print_errors(bio_err);
			goto exit;
		}
		rc = 1;

	exit:

		sk_OPENSSL_STRING_free(certflst);
		X509_CRL_free(crl);

		if (out)
		{
			BIO_free(out);
		}


		if (p7)
		{
			PKCS7_free(p7);
		}

		if (cert)
		{
			X509_free(cert);
		}

		if (fp)
		{
			fclose(fp);
		}

		delete[]ch;
		
	}

	if (rc == 1)
	{
		AfxMessageBox(_T("P7B合成成功!"));
	}
	else 
	{
		AfxMessageBox(_T("P7B合成失败!"));
	}

	return;
}

static int add_certs_from_file(STACK_OF(X509) *stack, char *certfile)
{
	BIO *in = NULL;
	int count = 0;
	int ret = -1;
	STACK_OF(X509_INFO) *sk = NULL;
	X509_INFO *xi;

	in = BIO_new_file(certfile, "r");
	if (in == NULL) {
		BIO_printf(bio_err, "error opening the file, %s\n", certfile);
		goto end;
	}

	/* This loads from a file, a stack of x509/crl/pkey sets */
	sk = PEM_X509_INFO_read_bio(in, NULL, NULL, NULL);
	if (sk == NULL) {
		BIO_printf(bio_err, "error reading the file, %s\n", certfile);
		goto end;
	}

	/* scan over it and pull out the CRL's */
	while (sk_X509_INFO_num(sk)) {
		xi = sk_X509_INFO_shift(sk);
		if (xi->x509 != NULL) {
			sk_X509_push(stack, xi->x509);
			xi->x509 = NULL;
			count++;
		}
		X509_INFO_free(xi);
	}

	ret = count;
end:
	/* never need to OPENSSL_free x */
	BIO_free(in);
	sk_X509_INFO_free(sk);
	return ret;
}

void CCertToolDlg::OnBnClickedP7bSepaButton()
{
	// TODO: Add your control notification handler code here
	PKCS7					*p7 = NULL;
	X509					*cert = NULL;
	BIO						*in = NULL, *out = NULL;
	STACK_OF(X509)			*certs = NULL;
	STACK_OF(X509_CRL)		*crls = NULL;
	int						i, rc = 0;
	char					*outfile = "cert", outname[20];
	_bstr_t					tmp;
	BOOL					isOpen = TRUE;		//是否打开(否则为保存)
	CString					defaultDir = L"C:\\";	//默认打开的文件路径
	CString					fileName = L"";			//默认打开的文件名
	CString					filter = L"文件 (*.p7b)|*.p7b||";	//文件过虑的类型

	CFileDialog openFileDlg(isOpen, defaultDir, fileName, OFN_HIDEREADONLY | OFN_READONLY, filter, NULL);
	//openFileDlg.GetOFN().lpstrInitialDir = L"E:\\FileTest\\test.doc";

	/*CRYPTO_malloc_init();
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();*/

	INT_PTR result = openFileDlg.DoModal();
	CString filePath = L"";
	if (result == IDOK) 
	{
		filePath = openFileDlg.GetPathName();
		tmp = filePath;
		//in = BIO_new_file((char *)tmp, "r");
		in = BIO_new(BIO_s_file());
		if (in == NULL)
		{
			goto exit;
		}
		if (BIO_read_filename(in, (char *)tmp) <= 0)
			if (in == NULL)
			{
				//perror((char *)tmp);
				goto exit;
			}

		p7 = d2i_PKCS7_bio(in, NULL);
		if (p7 == NULL)
		{
			if (BIO_read_filename(in, (char *)tmp) <= 0)
				if (in == NULL)
				{
					//perror((char *)tmp);
					goto exit;
				}

			p7 = PEM_read_bio_PKCS7(in, NULL, NULL, NULL);
			if (p7 == NULL)
			{
				goto exit;
			}
		}

		i = OBJ_obj2nid(p7->type);
		switch (i) {
		case NID_pkcs7_signed:
			if (p7->d.sign != NULL) {
				certs = p7->d.sign->cert;
				crls = p7->d.sign->crl;
			}
			break;
		case NID_pkcs7_signedAndEnveloped:
			if (p7->d.signed_and_enveloped != NULL) {
				certs = p7->d.signed_and_enveloped->cert;
				crls = p7->d.signed_and_enveloped->crl;
			}
			break;
		default:
			break;
		}
		
		if (certs != NULL)
		{
			for (i = 0; certs && i < sk_X509_num(certs); i++)
			{
				cert = sk_X509_value(certs, i);
				//outfile = outfile + i;
				sprintf(outname, "%s%d%s", outfile, i, ".cer");
				out = BIO_new_file(outname, "w");
				dump_cert_text(out, cert);
				PEM_write_bio_X509(out, cert);
				BIO_puts(out, "\n");
				BIO_free(out);
				out = NULL;
			}
		}

		if (crls != NULL) 
		{
			X509_CRL *crl;
			out = BIO_new_file("crls.crl", "w");
			for (i = 0; i < sk_X509_CRL_num(crls); i++) 
			{
				crl = sk_X509_CRL_value(crls, i);

				X509_CRL_print(out, crl);

				PEM_write_bio_X509_CRL(out, crl);
				BIO_puts(out, "\n");
			}
		}
	}
	rc = 1;
exit:

	if (p7)
	{
		PKCS7_free(p7);
	}

	if (in)
	{
		BIO_free(in);
	}

	if (rc == 1)
	{
		AfxMessageBox(_T("P7B分解成功!"));
	}
	else
	{
		AfxMessageBox(_T("P7B分解失败!"));
	}
}

int dump_cert_text(BIO *out, X509 *x)
{
	char *p;

	p = X509_NAME_oneline(X509_get_subject_name(x), NULL, 0);
	BIO_puts(out, "subject=");
	BIO_puts(out, p);
	OPENSSL_free(p);

	p = X509_NAME_oneline(X509_get_issuer_name(x), NULL, 0);
	BIO_puts(out, "\nissuer=");
	BIO_puts(out, p);
	BIO_puts(out, "\n");
	OPENSSL_free(p);

	return 0;
}

void CCertToolDlg::OnBnClickedPemDerButton()
{
	// TODO: Add your control notification handler code here
	X509					*incert = NULL;
	BIO						*cert = NULL, *out = NULL;
	_bstr_t					tmp;
	int						i, rc = 0;
	BOOL					isOpen = TRUE;		//是否打开(否则为保存)
	CString					defaultDir = L"C:\\";	//默认打开的文件路径
	CString					fileName = L"";			//默认打开的文件名
	CString					filter = L"文件 (*.*)|*.*||";	//文件过虑的类型

	CFileDialog openFileDlg(isOpen, defaultDir, fileName, OFN_HIDEREADONLY | OFN_READONLY, filter, NULL);

	INT_PTR result = openFileDlg.DoModal();
	CString filePath = L"";
	if (result == IDOK)
	{
		filePath = openFileDlg.GetPathName();
		
		tmp = filePath;
		out = BIO_new_file("certificate.der", "wb");
		if (out == NULL)
		{
			goto exit;
		}

		cert = BIO_new_file((char *)tmp, "r");
		if (cert == NULL)
		{
			goto exit;
		}
		incert = PEM_read_bio_X509_AUX(cert, NULL, NULL, NULL);
		if (incert == NULL)
		{
			goto exit;
		}
		BIO_free(cert);
		OBJ_create("2.99999.3", "SET.ex3", "SET x509v3 extension 3");
		i = i2d_X509_bio(out, incert);
		if (!i)
		{
			goto exit;
		}
		rc = 1;
	exit:
		if (out)
		{
			BIO_free(out);
		}

		if (incert)
		{
			X509_free(incert);
		}

		if (rc == 1)
		{
			AfxMessageBox(_T("PEM-->DER, 转换成功!"));
		}
		else
		{
			AfxMessageBox(_T("PEM-->DER, 转换失败!"));
		}
	}
}


void CCertToolDlg::OnBnClickedDerPemButton()
{
	// TODO: Add your control notification handler code here
	_bstr_t					tmp;
	int						i, rc = 0;
	X509					*incert = NULL;
	BIO						*out = NULL, *cert = NULL;
	BOOL					isOpen = TRUE;		//是否打开(否则为保存)
	CString					defaultDir = L"C:\\";	//默认打开的文件路径
	CString					fileName = L"";			//默认打开的文件名
	CString					filter = L"文件 (*.*)|*.*||";	//文件过虑的类型

	CFileDialog openFileDlg(isOpen, defaultDir, fileName, OFN_HIDEREADONLY | OFN_READONLY, filter, NULL);

	INT_PTR result = openFileDlg.DoModal();
	CString filePath = L"";
	if (result == IDOK)
	{
		filePath = openFileDlg.GetPathName();
		tmp = filePath;

		out = BIO_new_file("pem.crt", "w");
		if (out == NULL)
		{
			goto exit;
		}
		cert = BIO_new_file((char *)tmp, "rb");
		if (cert == NULL)
		{
			goto exit;
		}

		incert = d2i_X509_bio(cert, NULL);
		if (incert == NULL)
		{
			goto exit;
		}
		BIO_free(cert);

		OBJ_create("2.99999.3", "SET.ex3", "SET x509v3 extension 3");
		i = PEM_write_bio_X509(out, incert);
		if (!i)
		{
			goto exit;
		}
		rc = 1;
	exit:
		if (out)
		{
			BIO_free(out);
		}

		if (incert)
		{
			X509_free(incert);
		}

		if (rc == 1)
		{
			AfxMessageBox(_T("DER-->PEM, 转换成功!"));
		}
		else
		{
			AfxMessageBox(_T("DER-->PEM, 转换失败!"));
		}
	}
}


void CCertToolDlg::OnBnClickedPfxPemButton()
{
	// TODO: Add your control notification handler code here

	PFXDISADlg dlg;

	dlg.DoModal();
	//_bstr_t					tmp;
	//char					buf[8192] = { 0 };
	//char					pass[50] = { 0 }, macpass[50] = { 0 };
	//char					*cpass = NULL, *mpass = NULL, *badpass = NULL;
	//BIO						*infile = NULL, *outfile = NULL;
	//BIO						*bio_err_str = NULL;
	//PKCS12					*p12 = NULL;
	//FILE					*fp = NULL;
	//int						fd = -1, rc = 0;
	//const EVP_CIPHER		*enc;

	//BOOL					isOpen = TRUE;		//是否打开(否则为保存)
	//CString					defaultDir = L"C:\\";	//默认打开的文件路径
	//CString					fileName = L"";			//默认打开的文件名
	//CString					filter = L"文件 (*.*)|*.*||";	//文件过虑的类型

	//CFileDialog openFileDlg(isOpen, defaultDir, fileName, OFN_HIDEREADONLY | OFN_READONLY, filter, NULL);

	//INT_PTR result = openFileDlg.DoModal();
	//CString filePath = L"";
	//if (result == IDOK)
	//{
	//	filePath = openFileDlg.GetPathName();
	//	tmp = filePath;

	//	do_pipe_sig(); 
	//	CRYPTO_malloc_init(); 
	//	ERR_load_crypto_strings(); 
	//	OpenSSL_add_all_algorithms();

	//	enc = EVP_des_ede3_cbc();
	//	enc = NULL;

	//	bio_err_str = BIO_new(BIO_s_mem());

	//	cpass = pass;
	//	mpass = macpass;

	//	ERR_load_crypto_strings();

	//	infile = BIO_new_file((char *)tmp, "rb");
	//	if (infile == NULL)
	//	{
	//		goto exit;
	//	}

	//	/*fd = _open("outpem.pem", O_WRONLY | O_CREAT, 0600);
	//	if (fd < 0)
	//	{
	//		goto exit;
	//	}*/

	//	/*fp = _fdopen(fd, "w");
	//	if (fp == NULL)
	//	{
	//		goto exit;
	//	}

	//	outfile = BIO_new_fp(fp, BIO_CLOSE | BIO_FP_TEXT);
	//	if (outfile == NULL)
	//	{
	//		goto exit;
	//	}*/

	//	outfile = BIO_new_file("outpem.pem", "wb");
	//	if (outfile == NULL)
	//	{
	//		goto exit;
	//	}

	//	p12 = d2i_PKCS12_bio(infile, NULL);
	//	if (p12 == NULL)
	//	{
	//		ERR_print_errors(bio_err_str);
	//		BIO_read(bio_err_str, buf, 8191);
	//		goto exit;
	//	}
	//	pass[0] = 49;
	//	pass[1] = 50;
	//	pass[2] = 51;
	//	//BUF_strlcpy(macpass, pass, sizeof macpass);
	//	macpass[0] = 49;
	//	macpass[1] = 50;
	//	macpass[2] = 51;
	//	//macpass[3] = 52;
	//	//verify MAC
	//	if (!mpass[0] && PKCS12_verify_mac(p12, NULL, 0))
	//	{
	//		cpass = NULL;
	//	}
	//	else if (!PKCS12_verify_mac(p12, mpass, -1))
	//	{
	//		unsigned char *utmp;
	//		int utmplen;
	//		utmp = OPENSSL_asc2uni(mpass, -1, NULL, &utmplen);
	//		if (utmp == NULL)
	//			goto exit;
	//		badpass = OPENSSL_uni2utf8(utmp, utmplen);
	//		OPENSSL_free(utmp);
	//		if (!PKCS12_verify_mac(p12, badpass, -1)) {
	//			BIO_printf(bio_err, "Mac verify error: invalid password?\n");
	//			ERR_print_errors(bio_err);
	//			goto exit;
	//		}
	//		else {
	//			BIO_printf(bio_err, "Warning: using broken algorithm\n");
	//			cpass = badpass;
	//		}
	//		BIO_printf(bio_err, "Mac verify error: invalid password?\n");
	//		//ERR_print_errors(bio_err);
	//		goto exit;
	//	}

	//	BIO_printf(bio_err, "MAC verified OK\n");

	//	if (!dump_certs_keys_p12(outfile, p12, cpass, -1, 0, NULL, enc)) {
	//		BIO_printf(bio_err, "Error outputting keys and certificates\n");
	//		ERR_print_errors(bio_err);
	//		goto exit;
	//	}

	//	//OPENSSL_strlcpy()
	//	rc = 1;
	//exit:
	//	if (infile)
	//	{
	//		BIO_free(infile);
	//	}

	//	if (fp)
	//	{
	//		fclose(fp);
	//	}
	//	else if (fd >= 0)
	//	{
	//		_close(fd);
	//	}

	//	if (outfile)
	//	{
	//		BIO_free(outfile);
	//	}

	//	if (p12)
	//	{
	//		PKCS12_free(p12);
	//	}

	//	if (rc == 1)
	//	{
	//		AfxMessageBox(_T("PFX-->PEM, 转换成功!"));
	//	}
	//	else
	//	{
	//		AfxMessageBox(_T("PFX-->PEM, 转换失败!"));
	//	}
	//}
}

//static int bmp_to_utf8(char *str, unsigned char *utf16, int len)
//{
//	unsigned long utf32chr;
//
//	if (len == 0) return 0;
//
//	if (len < 2) return -1;
//
//	/* pull UTF-16 character in big-endian order */
//	utf32chr = (utf16[0] << 8) | utf16[1];
//
//	if (utf32chr >= 0xD800 && utf32chr < 0xE000) {   /* two chars */
//		unsigned int lo;
//
//		if (len < 4) return -1;
//
//		utf32chr -= 0xD800;
//		utf32chr <<= 10;
//		lo = (utf16[2] << 8) | utf16[3];
//		if (lo < 0xDC00 || lo >= 0xE000) return -1;
//		utf32chr |= lo - 0xDC00;
//		utf32chr += 0x10000;
//	}
//
//	return UTF8_putc((unsigned char *)str, len > 4 ? 4 : len, utf32chr);
//}
//
//char *OPENSSL_uni2utf8(unsigned char *uni, int unilen)
//{
//	int asclen, i, j;
//	char *asctmp;
//
//	/* string must contain an even number of bytes */
//	if (unilen & 1)
//		return NULL;
//
//	for (asclen = 0, i = 0; i < unilen; ) {
//		j = bmp_to_utf8(NULL, uni + i, unilen - i);
//		/*
//		* falling back to OPENSSL_uni2asc makes lesser sense [than
//		* falling back to OPENSSL_asc2uni in OPENSSL_utf82uni above],
//		* it's done rather to maintain symmetry...
//		*/
//		if (j < 0) return OPENSSL_uni2asc(uni, unilen);
//		if (j == 4) i += 4;
//		else        i += 2;
//		asclen += j;
//	}
//
//	/* If no terminating zero allow for one */
//	if (!unilen || (uni[unilen - 2] || uni[unilen - 1]))
//		asclen++;
//
//	if ((asctmp = (char *)OPENSSL_malloc(asclen)) == NULL) {
//		PKCS12err(PKCS12_F_OPENSSL_UNI2UTF8, ERR_R_MALLOC_FAILURE);
//		return NULL;
//	}
//
//	/* re-run the loop emitting UTF-8 string */
//	for (asclen = 0, i = 0; i < unilen; ) {
//		j = bmp_to_utf8(asctmp + asclen, uni + i, unilen - i);
//		if (j == 4) i += 4;
//		else        i += 2;
//		asclen += j;
//	}
//
//	/* If no terminating zero write one */
//	if (!unilen || (uni[unilen - 2] || uni[unilen - 1]))
//		asctmp[asclen] = '\0';
//
//	return asctmp;
//}
//
//int dump_certs_keys_p12(BIO *out, PKCS12 *p12, const char *pass,
//	int passlen, int options, char *pempass,
//	const EVP_CIPHER *enc)
//{
//	STACK_OF(PKCS7) *asafes = NULL;
//	STACK_OF(PKCS12_SAFEBAG) *bags;
//	int i, bagnid;
//	int ret = 0;
//	PKCS7 *p7;
//
//	if (!(asafes = PKCS12_unpack_authsafes(p12)))
//	{
//		return 0;
//	}
//
//	for (i = 0; i < sk_PKCS7_num(asafes); i++) 
//	{
//		p7 = sk_PKCS7_value(asafes, i);
//		bagnid = OBJ_obj2nid(p7->type);
//		if (bagnid == NID_pkcs7_data) 
//		{
//			bags = PKCS12_unpack_p7data(p7);
//			if (options & INFO)
//			{
//				BIO_printf(bio_err, "PKCS7 Data\n");
//			}
//		}
//		else if (bagnid == NID_pkcs7_encrypted) 
//		{
//			if (options & INFO) 
//			{
//				BIO_printf(bio_err, "PKCS7 Encrypted data: ");
//				//alg_print(p7->d.encrypted->enc_data->algorithm);
//			}
//			bags = PKCS12_unpack_p7encdata(p7, pass, passlen);
//		}
//		else 
//		{
//			continue;
//		}
//
//		if (!bags)
//		{
//			goto err;
//		}
//
//		if (!dump_certs_pkeys_bags(out, bags, pass, passlen, options, pempass, enc)) 
//		{
//			sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
//			goto err;
//		}
//		sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
//		bags = NULL;
//	}
//	ret = 1;
//
//err:
//	sk_PKCS7_pop_free(asafes, PKCS7_free);
//	return ret;
//}
//
//int dump_certs_pkeys_bags(BIO *out, const STACK_OF(PKCS12_SAFEBAG) *bags,
//	const char *pass, int passlen, int options,
//	char *pempass, const EVP_CIPHER *enc)
//{
//	int i;
//	for (i = 0; i < sk_PKCS12_SAFEBAG_num(bags); i++) 
//	{
//		if (!dump_certs_pkeys_bag(out, sk_PKCS12_SAFEBAG_value(bags, i), pass, passlen, options, pempass, enc))
//		{
//			return 0;
//		}
//	}
//
//	return 1;
//}
//
//int dump_certs_pkeys_bag(BIO *out, PKCS12_SAFEBAG *bag, const char *pass,
//	int passlen, int options, char *pempass, const EVP_CIPHER *enc)
//{
//	EVP_PKEY *pkey;
//	PKCS8_PRIV_KEY_INFO *p8;
//	X509 *x509;
//
//	switch (M_PKCS12_bag_type(bag))
//	{
//	case NID_keyBag:
//		if (options & INFO) BIO_printf(bio_err, "Key bag\n");
//		if (options & NOKEYS) return 1;
//		//print_attribs(out, bag->attrib, "Bag Attributes");
//		p8 = bag->value.keybag;
//		if (!(pkey = EVP_PKCS82PKEY(p8))) return 0;
//		//print_attribs(out, p8->attributes, "Key Attributes");
//		PEM_write_bio_PrivateKey(out, pkey, enc, NULL, 0, NULL, pempass);
//		EVP_PKEY_free(pkey);
//		break;
//
//	case NID_pkcs8ShroudedKeyBag:
//		if (options & INFO) {
//			BIO_printf(bio_err, "Shrouded Keybag: ");
//			//alg_print(bio_err, bag->value.shkeybag->algor);
//		}
//		if (options & NOKEYS) return 1;
//		//print_attribs(out, bag->attrib, "Bag Attributes");
//		if (!(p8 = PKCS12_decrypt_skey(bag, pass, passlen)))
//			return 0;
//		if (!(pkey = EVP_PKCS82PKEY(p8))) {
//			PKCS8_PRIV_KEY_INFO_free(p8);
//			return 0;
//		}
//		//print_attribs(out, p8->attributes, "Key Attributes");
//		PKCS8_PRIV_KEY_INFO_free(p8);
//		PEM_write_bio_PrivateKey(out, pkey, enc, NULL, 0, NULL, pempass);
//		EVP_PKEY_free(pkey);
//		break;
//
//	case NID_certBag:
//		if (options & INFO) BIO_printf(bio_err, "Certificate bag\n");
//		if (options & NOCERTS) return 1;
//		if (PKCS12_get_attr(bag, NID_localKeyID)) {
//			if (options & CACERTS) return 1;
//		}
//		else if (options & CLCERTS) return 1;
//		//print_attribs(out, bag->attrib, "Bag Attributes");
//		if (M_PKCS12_cert_bag_type(bag) != NID_x509Certificate)
//			return 1;
//		if (!(x509 = PKCS12_certbag2x509(bag))) return 0;
//		dump_cert_text(out, x509);
//		PEM_write_bio_X509(out, x509);
//		X509_free(x509);
//		break;
//
//	case NID_safeContentsBag:
//		if (options & INFO) BIO_printf(bio_err, "Safe Contents bag\n");
//		//print_attribs(out, bag->attrib, "Bag Attributes");
//		return dump_certs_pkeys_bags(out, bag->value.safes, pass,
//			passlen, options, pempass, enc);
//
//	default:
//		BIO_printf(bio_err, "Warning unsupported bag type: ");
//		i2a_ASN1_OBJECT(bio_err, bag->type);
//		BIO_printf(bio_err, "\n");
//		return 1;
//		break;
//	}
//	return 1;
//}

void CCertToolDlg::OnBnClickedPemPfxButton()
{
	// TODO: Add your control notification handler code here
	CPFXCOMBDlg dlg;

	dlg.DoModal();
}

void CCertToolDlg::OnBnClickedGenCaButton()
{
	// TODO: Add your control notification handler code here
}
