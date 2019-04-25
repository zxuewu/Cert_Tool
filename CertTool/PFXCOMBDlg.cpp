// PFXCOMBDlg.cpp : implementation file
//

#include "stdafx.h"
#include "CertTool.h"
#include "PFXCOMBDlg.h"
#include "afxdialogex.h"

//static int seeded = 0;
//static int egdsocket = 0;

EVP_PKEY *load_key(BIO *err, const char *file, int format,
	const char *pass, const char *key_descrip);
static int load_pkcs12(BIO *err, BIO *in, const char *desc,
	pem_password_cb *pem_cb, void *cb_data,
	EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca);
STACK_OF(X509) *load_certs(BIO *err, const char *file, int format,
	const char *pass, const char *desc);
int password_callback(char *buf, int bufsiz, int verify,
	PW_CB_DATA *cb_tmp);
static int load_certs_crls(BIO *err, const char *file, int format,
	const char *pass, const char *desc,
	STACK_OF(X509) **pcerts, STACK_OF(X509_CRL) **pcrls);
// CPFXCOMBDlg dialog

IMPLEMENT_DYNAMIC(CPFXCOMBDlg, CDialogEx)

CPFXCOMBDlg::CPFXCOMBDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_CONFIG_INFO_DIALOG, pParent)
{

}

CPFXCOMBDlg::~CPFXCOMBDlg()
{
}

void CPFXCOMBDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_CA_FILE_EDIT, m_cafile);
	DDX_Control(pDX, IDC_CERT_FILE_EDIT, m_certfile);
	DDX_Control(pDX, IDC_KEY_FILE_EDIT, m_keyfile);
	DDX_Control(pDX, IDC_KEY_PIN_EDIT, m_pin);
	DDX_Control(pDX, IDC_COMB_TYPE_COMBO, m_combo);
	DDX_Control(pDX, IDC_EXPORT_PIN_EDIT, m_expin);
}


BEGIN_MESSAGE_MAP(CPFXCOMBDlg, CDialogEx)
	ON_BN_CLICKED(IDC_CA_FILE_BUTTON, &CPFXCOMBDlg::OnBnClickedCaFileButton)
	ON_BN_CLICKED(IDC_CERT_FILE_BUTTON, &CPFXCOMBDlg::OnBnClickedCertFileButton)
	ON_BN_CLICKED(IDC_PRIVATE_KEY_BUTTON, &CPFXCOMBDlg::OnBnClickedPrivateKeyButton)
	ON_BN_CLICKED(IDC_COMB_BUTTON, &CPFXCOMBDlg::OnBnClickedCombButton)
END_MESSAGE_MAP()


// CPFXCOMBDlg message handlers
BOOL CPFXCOMBDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  Add extra initialization here
	m_combo.AddString(L"证书与私钥");
	m_combo.AddString(L"证书");
	m_combo.AddString(L"私钥");
	m_combo.AddString(L"不导出");
	m_combo.SetCurSel(0);
	return TRUE;  // return TRUE unless you set the focus to a control
				  // EXCEPTION: OCX Property Pages should return FALSE
}

void CPFXCOMBDlg::OnBnClickedCaFileButton()
{
	// TODO: Add your control notification handler code here
	BOOL isOpen = TRUE;		//是否打开(否则为保存)
	CString defaultDir = L"C:\\";	//默认打开的文件路径
	CString fileName = L"";			//默认打开的文件名
	CString filter = L"文件 (*.cer; *.crt; *.pem)|*.cer; *.crt; *.pem||";	//文件过虑的类型
	CFileDialog openFileDlg(isOpen, defaultDir, fileName, OFN_HIDEREADONLY | OFN_READONLY, filter, NULL);
	INT_PTR result = openFileDlg.DoModal();
	CString filePath = L"";

	if (result == IDOK) {
		filePath = openFileDlg.GetPathName();
		m_cafile.SetWindowTextW(filePath);
	}
}


void CPFXCOMBDlg::OnBnClickedCertFileButton()
{
	// TODO: Add your control notification handler code here
	BOOL isOpen = TRUE;		//是否打开(否则为保存)
	CString defaultDir = L"C:\\";	//默认打开的文件路径
	CString fileName = L"";			//默认打开的文件名
	CString filter = L"文件 (*.cer; *.crt; *.pem)|*.cer; *.crt; *.pem||";	//文件过虑的类型
	CFileDialog openFileDlg(isOpen, defaultDir, fileName, OFN_HIDEREADONLY | OFN_READONLY, filter, NULL);
	INT_PTR result = openFileDlg.DoModal();
	CString filePath = L"";

	if (result == IDOK) {
		filePath = openFileDlg.GetPathName();
		m_certfile.SetWindowTextW(filePath);
	}
}


void CPFXCOMBDlg::OnBnClickedPrivateKeyButton()
{
	// TODO: Add your control notification handler code here
	BOOL isOpen = TRUE;		//是否打开(否则为保存)
	CString defaultDir = L"C:\\";	//默认打开的文件路径
	CString fileName = L"";			//默认打开的文件名
	CString filter = L"文件 (*.key; *.pem)|*.key; *.pem||";	//文件过虑的类型
	CFileDialog openFileDlg(isOpen, defaultDir, fileName, OFN_HIDEREADONLY | OFN_READONLY, filter, NULL);
	INT_PTR result = openFileDlg.DoModal();
	CString filePath = L"";

	if (result == IDOK) {
		filePath = openFileDlg.GetPathName();
		m_keyfile.SetWindowTextW(filePath);
	}
}


void CPFXCOMBDlg::OnBnClickedCombButton()
{
	// TODO: Add your control notification handler code here
	_bstr_t					filetmp, passtmp;
	BIO						*in = NULL, *out = NULL, *bio_err_str = NULL;
	PKCS12					*p12 = NULL;
	EVP_PKEY				*key = NULL;
	X509					*ucert = NULL, *x = NULL;
	STACK_OF(X509)			*certs = NULL;
	int						maciter = PKCS12_DEFAULT_ITER;
	const EVP_MD			*macmd = NULL;
	unsigned char			*catmp = NULL;
	int						i, index, options = 0, chain = 0, rc = 0;
	int						key_pbe = NID_pbe_WithSHA1And3_Key_TripleDES_CBC;
	int						cert_pbe = NID_pbe_WithSHA1And40BitRC2_CBC;
	int						iter = PKCS12_DEFAULT_ITER;
	int						keytype = 0;

	CString					CAfile = L"", Certfile = L"", Keyfile = L"", PIN = L"", EXPIN = L"";
	CString					Outfile = L"";
	CFileDialog				FileDlg(FALSE, L"pfx");

	UpdateData(TRUE);
	index = m_combo.GetCurSel();
	bio_err_str = BIO_new(BIO_s_mem());

	FileDlg.m_ofn.lpstrTitle = L"保存文件";
	FileDlg.m_ofn.lpstrFilter = L"PKCS12 Files(*pfx)\0\0";
	if (IDOK == FileDlg.DoModal())
	{
		Outfile = FileDlg.GetPathName();
		
		m_cafile.GetWindowTextW(CAfile);
		m_certfile.GetWindowTextW(Certfile);
		m_keyfile.GetWindowTextW(Keyfile);
		m_pin.GetWindowTextW(PIN);
		m_expin.GetWindowTextW(EXPIN);
		if (index == 0)
		{
			options = 0;
		}
		else if (index == 1)
		{
			options |= NOKEYS;
		}
		else if (index == 2)
		{
			options |= NOCERTS;
		}
		else if (index == 3)
		{
			options |= (NOKEYS | NOCERTS);
		}
		else 
		{
			AfxMessageBox(_T("下拉菜单选项错误!"));
			return;
		}
		
		if (Certfile == L"")
		{
			AfxMessageBox(_T("请选择证书文件!"));
			return;
		}
		filetmp = Certfile;
		in = BIO_new_file((char *)filetmp, "rb");
		if (!in)
		{
			BIO_printf(bio_err_str, "Error opening input file %s\n", filetmp);
			goto exit;
		}

		filetmp = Outfile;
		out = BIO_new_file((char *)filetmp, "wb");
		if (!out)
		{
			BIO_printf(bio_err_str, "Error opening output file %s\n", filetmp);
			goto exit;
		}

		if ((options & (NOCERTS | NOKEYS)) == (NOCERTS | NOKEYS))
		{
			BIO_printf(bio_err_str, "Nothing to do!\n");
			goto exit;
		}

		if (options & NOCERTS)
		{
			chain = 0;
		}

		if (!(options & NOKEYS))
		{
			if (Keyfile != L"")
			{
				filetmp = Keyfile;
			}
			else
			{
				filetmp = Certfile;
			}

			passtmp = PIN;
			key = load_key(bio_err_str, (char *)filetmp,
				FORMAT_PEM, (char *)passtmp, "private key");
			if (!key)
			{
				goto exit;
			}
		}

		if (!(options & NOCERTS))
		{
			filetmp = Certfile;
			certs = load_certs(bio_err_str, filetmp, FORMAT_PEM, NULL,
				"certificates");

			if (!certs)
			{
				goto exit;
			}

			if (key)
			{
				for (i = 0; i < sk_X509_num(certs); i++)
				{
					x = sk_X509_value(certs, i);
					if (X509_check_private_key(x, key))
					{
						ucert = x;
						X509_keyid_set1(ucert, NULL, 0);
						X509_alias_set1(ucert, NULL, 0);

						sk_X509_delete(certs, i);
						break;
					}
				}

				if (!ucert)
				{
					BIO_printf(bio_err_str, "No certificate matches private key\n");
					goto exit;
				}
			}
		}

		if (CAfile != L"")
		{
			STACK_OF(X509) *morecerts = NULL;

			filetmp = CAfile;
			if (!(morecerts = load_certs(bio_err_str, (char *)filetmp, FORMAT_PEM, NULL, "certificates from CAfile")))
			{
				goto exit;
			}

			while (sk_X509_num(morecerts) > 0)
			{
				sk_X509_push(certs, sk_X509_shift(morecerts));
				sk_X509_free(morecerts);
			}
		}

		if (chain)
		{
			int vret = 0;
			STACK_OF(X509) *chain2 = NULL;
			X509_STORE *store = X509_STORE_new();
			if (!store)
			{
				BIO_printf(bio_err_str, "Memory allocation error\n");
				goto exit;
			}
			if (!X509_STORE_load_locations(store, NULL, NULL))
			{
				X509_STORE_set_default_paths(store);
			}
			X509_STORE_free(store);

			if (!vret) {
				/* Exclude verified certificate */
				for (i = 1; i < sk_X509_num(chain2); i++)
					sk_X509_push(certs, sk_X509_value(chain2, i));
				/* Free first certificate */
				X509_free(sk_X509_value(chain2, 0));
				sk_X509_free(chain2);
			}
			else 
			{
				if (vret >= 0)
				{
					BIO_printf(bio_err_str, "Error %s getting chain.\n",
						X509_verify_cert_error_string(vret));
				}
				else
				{
					ERR_print_errors(bio_err_str);
				}
				goto exit;
			}
		}

		passtmp = EXPIN;
		filetmp = Outfile;

		p12 = PKCS12_create((char *)passtmp, (char *)filetmp, key, ucert, certs,
			key_pbe, cert_pbe, iter, -1, keytype);

		if (!p12)
		{
			ERR_print_errors(bio_err_str);
			goto exit;
		}

		if (maciter != -1)
		{
			PKCS12_set_mac(p12, (char *)passtmp, -1, NULL, 0, maciter, macmd);
		}

		i2d_PKCS12_bio(out, p12);

		rc = 1;
	exit:
		if (p12)
		{
			PKCS12_free(p12);
		}
		if (key)
		{
			EVP_PKEY_free(key);
		}
		if (certs) 
		{
			sk_X509_pop_free(certs, X509_free);
		}
		if (ucert)
		{
			X509_free(ucert);
		}
		if (in)
		{
			BIO_free(in);
		}

		if (out)
		{
			BIO_free(out);
		}

		if (rc == 1)
		{
			AfxMessageBox(_T("PEM-->PFX, 转换成功!"));
		}
		else
		{
			AfxMessageBox(_T("PEM-->PFX, 转换失败!"));
		}

	}
}

EVP_PKEY *load_key(BIO *err, const char *file, int format,
	const char *pass, const char *key_descrip)
{
	BIO *key = NULL;
	EVP_PKEY *pkey = NULL;
	PW_CB_DATA cb_data;

	cb_data.password = pass;
	cb_data.prompt_info = file;

	if (file == NULL)
	{
		BIO_printf(err, "no keyfile specified\n");
		goto end;
	}

	key = BIO_new(BIO_s_file());
	if (key == NULL)
	{
		ERR_print_errors(err);
		goto end;
	}

	if (BIO_read_filename(key, file) <= 0)
	{
		BIO_printf(err, "Error opening %s %s\n",
			key_descrip, file);
		ERR_print_errors(err);
		goto end;
	}

	if (format == FORMAT_ASN1)
	{
		pkey = d2i_PrivateKey_bio(key, NULL);
	}
	else if (format == FORMAT_PEM)
	{
		pkey = PEM_read_bio_PrivateKey(key, NULL,
			(pem_password_cb *)password_callback, &cb_data);
	}
	else if (format == FORMAT_PKCS12)
	{
		if (!load_pkcs12(err, key, key_descrip,
			(pem_password_cb *)password_callback, &cb_data,
			&pkey, NULL, NULL))
			goto end;
	}
	else
	{
		BIO_printf(err, "bad input format specified for key file\n");
		goto end;
	}
end:
	if (key != NULL)
	{
		BIO_free(key);
	}

	if (pkey == NULL)
	{
		BIO_printf(err, "unable to load %s\n", key_descrip);
		ERR_print_errors(err);
	}

	return pkey;
}

int password_callback(char *buf, int bufsiz, int verify,
	PW_CB_DATA *cb_tmp)
{
	int res = 0;
	const char *prompt_info = NULL;
	const char *password = NULL;
	PW_CB_DATA *cb_data = (PW_CB_DATA *)cb_tmp;

	if (cb_data)
	{
		if (cb_data->password)
			password = (char *)cb_data->password;
		if (cb_data->prompt_info)
			prompt_info = cb_data->prompt_info;
	}

	if (password)
	{
		res = strlen(password);
		if (res > bufsiz)
			res = bufsiz;
		memcpy(buf, password, res);
		return res;
	}

	return res;
}

static int load_pkcs12(BIO *err, BIO *in, const char *desc,
	pem_password_cb *pem_cb, void *cb_data,
	EVP_PKEY **pkey, X509 **cert, STACK_OF(X509) **ca)
{
	const char *pass;
	char tpass[PEM_BUFSIZE];
	int len, ret = 0;
	PKCS12 *p12;
	p12 = d2i_PKCS12_bio(in, NULL);
	if (p12 == NULL)
	{
		BIO_printf(err, "Error loading PKCS12 file for %s\n", desc);
		goto die;
	}
	/* See if an empty password will do */
	if (PKCS12_verify_mac(p12, "", 0) || PKCS12_verify_mac(p12, NULL, 0))
		pass = "";
	else
	{
		if (!pem_cb)
			pem_cb = (pem_password_cb *)password_callback;
		len = pem_cb(tpass, PEM_BUFSIZE, 0, cb_data);
		if (len < 0)
		{
			BIO_printf(err, "Passpharse callback error for %s\n",
				desc);
			goto die;
		}
		if (len < PEM_BUFSIZE)
			tpass[len] = 0;
		if (!PKCS12_verify_mac(p12, tpass, len))
		{
			BIO_printf(err,
				"Mac verify error (wrong password?) in PKCS12 file for %s\n", desc);
			goto die;
		}
		pass = tpass;
	}
	ret = PKCS12_parse(p12, pass, pkey, cert, ca);
die:
	if (p12)
		PKCS12_free(p12);
	return ret;
}

STACK_OF(X509) *load_certs(BIO *err, const char *file, int format,
	const char *pass, const char *desc)
{
	STACK_OF(X509) *certs;
	if (!load_certs_crls(err, file, format, pass, desc, &certs, NULL))
		return NULL;
	return certs;
}

static int load_certs_crls(BIO *err, const char *file, int format,
	const char *pass, const char *desc,
	STACK_OF(X509) **pcerts, STACK_OF(X509_CRL) **pcrls)
{
	int i;
	BIO *bio;
	STACK_OF(X509_INFO) *xis = NULL;
	X509_INFO *xi;
	PW_CB_DATA cb_data;
	int rv = 0;

	cb_data.password = pass;
	cb_data.prompt_info = file;

	if (format != FORMAT_PEM)
	{
		BIO_printf(err, "bad input format specified for %s\n", desc);
		return 0;
	}

	if (file == NULL)
		bio = BIO_new_fp(stdin, BIO_NOCLOSE);
	else
		bio = BIO_new_file(file, "r");

	if (bio == NULL)
	{
		BIO_printf(err, "Error opening %s %s\n",
			desc, file ? file : "stdin");
		ERR_print_errors(err);
		return 0;
	}

	xis = PEM_X509_INFO_read_bio(bio, NULL,
		(pem_password_cb *)password_callback, &cb_data);

	BIO_free(bio);

	if (pcerts)
	{
		*pcerts = sk_X509_new_null();
		if (!*pcerts)
			goto end;
	}

	if (pcrls)
	{
		*pcrls = sk_X509_CRL_new_null();
		if (!*pcrls)
			goto end;
	}

	for (i = 0; i < sk_X509_INFO_num(xis); i++)
	{
		xi = sk_X509_INFO_value(xis, i);
		if (xi->x509 && pcerts)
		{
			if (!sk_X509_push(*pcerts, xi->x509))
				goto end;
			xi->x509 = NULL;
		}
		if (xi->crl && pcrls)
		{
			if (!sk_X509_CRL_push(*pcrls, xi->crl))
				goto end;
			xi->crl = NULL;
		}
	}

	if (pcerts && sk_X509_num(*pcerts) > 0)
		rv = 1;

	if (pcrls && sk_X509_CRL_num(*pcrls) > 0)
		rv = 1;

end:

	if (xis)
		sk_X509_INFO_pop_free(xis, X509_INFO_free);

	if (rv == 0)
	{
		if (pcerts)
		{
			sk_X509_pop_free(*pcerts, X509_free);
			*pcerts = NULL;
		}
		if (pcrls)
		{
			sk_X509_CRL_pop_free(*pcrls, X509_CRL_free);
			*pcrls = NULL;
		}
		BIO_printf(err, "unable to load %s\n",
			pcerts ? "certificates" : "CRLs");
		ERR_print_errors(err);
	}
	return rv;
}


//int app_RAND_load_file(const char *file, BIO *bio_e, int dont_warn)
//{
//	int consider_randfile = (file == NULL);
//	char buffer[200];
//
//	if (file == NULL)
//	{
//		file = RAND_file_name(buffer, sizeof buffer);
//	}
//	else if (RAND_egd(file) > 0)
//	{
//		/* we try if the given filename is an EGD socket.
//		if it is, we don't write anything back to the file. */
//		egdsocket = 1;
//		return 1;
//	}
//	if (file == NULL || !RAND_load_file(file, -1))
//	{
//		if (RAND_status() == 0)
//		{
//			if (!dont_warn)
//			{
//				BIO_printf(bio_e, "unable to load 'random state'\n");
//				BIO_printf(bio_e, "This means that the random number generator has not been seeded\n");
//				BIO_printf(bio_e, "with much random data.\n");
//				if (consider_randfile) /* explanation does not apply when a file is explicitly named */
//				{
//					BIO_printf(bio_e, "Consider setting the RANDFILE environment variable to point at a file that\n");
//					BIO_printf(bio_e, "'random' data can be kept in (the file will be overwritten).\n");
//				}
//			}
//			return 0;
//		}
//	}
//	seeded = 1;
//	return 1;
//}
