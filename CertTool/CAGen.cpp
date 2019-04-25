// CAGen.cpp : implementation file
//

#include "stdafx.h"
#include "CertTool.h"
#include "CAGen.h"
#include "afxdialogex.h"

static int genpkey_cb(EVP_PKEY_CTX *ctx);
static EVP_PKEY_CTX *set_keygen_ctx(BIO *err, const char *gstr, int *pkey_type,
	long *pkeylen, char **palgnam,
	ENGINE *keygen_engine);
static int add_attribute_object(X509_NAME *subject, int nid, unsigned long chtype, CString buf);
// CCAGen dialog

IMPLEMENT_DYNAMIC(CCAGen, CDialogEx)

CCAGen::CCAGen(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_GEN_CA_DIALOG, pParent)
{

}

CCAGen::~CCAGen()
{
}

void CCAGen::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_NUMBITS_COMBO, m_keylength);
	DDX_Control(pDX, IDC_C_COMBO, m_countryname);
	DDX_Control(pDX, IDC_ST_EDIT, m_province);
	DDX_Control(pDX, IDC_LN_EDIT, m_city);
	DDX_Control(pDX, IDC_EDIT4, m_organization);
	DDX_Control(pDX, IDC_OU_EDIT, m_organizationunit);
	DDX_Control(pDX, IDC_EDIT6, m_commonname);
	DDX_Control(pDX, IDC_CA_PIN_EDIT, m_privatekeypin);
}


BEGIN_MESSAGE_MAP(CCAGen, CDialogEx)
	ON_BN_CLICKED(IDC_GEN_BUTTON, &CCAGen::OnBnClickedGenButton)
END_MESSAGE_MAP()

BOOL CCAGen::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  Add extra initialization here
	m_countryname.AddString(L"CN");
	m_countryname.AddString(L"AU");
	m_countryname.SetCurSel(0);

	m_keylength.AddString(L"1024");
	m_keylength.AddString(L"2048");
	m_keylength.AddString(L"4096");
	m_keylength.SetCurSel(1);

	return TRUE;  // return TRUE unless you set the focus to a control
				  // EXCEPTION: OCX Property Pages should return FALSE
}


// CCAGen message handlers


void CCAGen::OnBnClickedGenButton()
{
	// TODO: Add your control notification handler code here
	BIO						*in = NULL, *out = NULL, *bio_err_str = NULL;
	EVP_PKEY				*pkey = NULL;
	EVP_PKEY_CTX			*genctx = NULL;
	X509_REQ				*req = NULL;
	X509_NAME				*x509_name = NULL;
	X509					*x509ss = NULL;
	int						pkey_type = -1, multirdn = 0;
	long					newkey = 2048;
	char					*keyalgstr = NULL, *subj = NULL;
	char					*keyout = NULL, *passout = NULL;
	const EVP_CIPHER		*cipher = EVP_des_ede3_cbc();
	int						i = 0, ret = 0;
	int						days = 30;
	_bstr_t					tmp;

	CString					szCountry = L"", szProvince = L"", szCity = L"", szOrganization = L"", szOrganizationUnit = L"", szCommonName = L"";
	CString					Outfile = L"";
	CFileDialog				FileDlg(FALSE, L"crt");
	//const char		*szPath = "x509Req.csr";

	FileDlg.m_ofn.lpstrTitle = L"±£´æÎÄ¼þ";
	FileDlg.m_ofn.lpstrFilter = L"Certificate Files(*crt)\0\0";
	if (IDOK == FileDlg.DoModal())
	{
		m_countryname.GetWindowTextW(szCountry);
		m_province.GetWindowTextW(szProvince);
		m_city.GetWindowTextW(szCity);
		m_organization.GetWindowTextW(szOrganization);
		m_organizationunit.GetWindowTextW(szOrganizationUnit);
		m_commonname.GetWindowTextW(szCommonName);

		CRYPTO_malloc_init();
		ERR_load_crypto_strings();
		OpenSSL_add_all_algorithms();

		in = BIO_new(BIO_s_file());
		out = BIO_new(BIO_s_file());
		bio_err_str = BIO_new(BIO_s_mem());
		if ((in == NULL) || (out == NULL) || bio_err_str == NULL)
		{
			goto exit;
		}

		/*char *randfile = NULL;
		app_RAND_load_file(randfile, bio_err_str, 0);*/

		genctx = set_keygen_ctx(bio_err_str, NULL, &pkey_type, &newkey, &keyalgstr, NULL);
		if (!genctx)
		{
			goto exit;
		}

		EVP_PKEY_CTX_set_cb(genctx, genpkey_cb);
		EVP_PKEY_CTX_set_app_data(genctx, bio_err_str);

		if (EVP_PKEY_keygen(genctx, &pkey) <= 0)
		{
			BIO_puts(bio_err_str, "Error Generating Key\n");
			goto exit;
		}

		EVP_PKEY_CTX_free(genctx);
		genctx = NULL;

		//app_RAND_write_file(randfile, bio_err_str);

		if (BIO_write_filename(out, keyout) <= 0)
		{
			perror(keyout);
			goto exit;
		}

	loop:
		if (!PEM_write_bio_PrivateKey(out, pkey, cipher,
			NULL, 0, NULL, passout))
		{
			goto exit;
		}

		req = X509_REQ_new();
		if (req == NULL)
		{
			goto exit;
		}
		X509_REQ_set_version(req, 2);
		x509_name = X509_REQ_get_subject_name(req);

		if (L"" != szCountry)
		{
			ret = add_attribute_object(x509_name, NID_countryName, MBSTRING_UTF8, szCountry);
			if (1 != ret)
			{
				goto exit;
			}
		}

		if (L"" != szProvince)
		{
			ret = add_attribute_object(x509_name, NID_stateOrProvinceName, MBSTRING_UTF8, szProvince);
			if (1 != ret)
			{
				goto exit;
			}
		}

		if (L"" != szCity)
		{
			ret = add_attribute_object(x509_name, NID_localityName, MBSTRING_UTF8, szCity);
			if (1 != ret)
			{
				goto exit;
			}
		}

		if (L"" != szOrganization)
		{
			ret = add_attribute_object(x509_name, NID_organizationName, MBSTRING_UTF8, szOrganization);
			if (1 != ret)
			{
				goto exit;
			}
		}

		if (L"" != szOrganizationUnit)
		{
			ret = add_attribute_object(x509_name, NID_organizationalUnitName, MBSTRING_UTF8, szOrganizationUnit);
			if (1 != ret)
			{
				goto exit;
			}
		}

		if (L"" != szCommonName)
		{
			ret = add_attribute_object(x509_name, NID_organizationalUnitName, MBSTRING_UTF8, szCommonName);
			if (1 != ret)
			{
				goto exit;
			}
		}

		EVP_PKEY *tmppkey;
		X509V3_CTX ext_ctx;
		if ((x509ss = X509_new()) == NULL)
		{
			goto exit;
		}

		X509_set_version(x509ss, 2);

		BIGNUM *btmp = BN_new();
		if (!BN_pseudo_rand(btmp, 64, 0, 0))
		{
			goto exit;
		}
		if (!BN_to_ASN1_INTEGER(btmp, X509_get_serialNumber(x509ss)))
		{
			goto exit;
		}
		BN_free(btmp);
		if (!X509_set_issuer_name(x509ss, X509_REQ_get_subject_name(req))) goto exit;
		if (!X509_gmtime_adj(X509_get_notBefore(x509ss), 0)) goto exit;
		if (!X509_time_adj_ex(X509_get_notAfter(x509ss), days, 0, NULL)) goto exit;
		if (!X509_set_subject_name(x509ss, X509_REQ_get_subject_name(req))) goto exit;
		tmppkey = X509_REQ_get_pubkey(req);
		if (!tmppkey || !X509_set_pubkey(x509ss, tmppkey)) goto exit;
		EVP_PKEY_free(tmppkey);

		X509V3_set_ctx(&ext_ctx, x509ss, x509ss, NULL, NULL, 0);
		//X509V3_set_nconf(&ext_ctx, req_conf);
		//X509V3_EXT_REQ_add_nconf(req_conf,
		//	&ext_ctx, req_exts, req);

	exit:
		if (x509ss)
		{
			X509_free(x509ss);
		}

		if (req)
		{
			X509_REQ_free(req);
		}

		if (keyalgstr)
		{
			OPENSSL_free(keyalgstr);
		}
		EVP_PKEY_free(pkey);
		if (genctx)
		{
			EVP_PKEY_CTX_free(genctx);
			genctx = NULL;
		}

		if (in)
		{
			BIO_free(in);
		}

		if (out)
		{
			BIO_free(out);
		}
	}
}

static int add_attribute_object(X509_NAME *subject, int nid, unsigned long chtype, CString buf)
{
	int			nUtf8Length, ret = 0;
	char		*pUtf8;
	_bstr_t		tmp;

	if (MBSTRING_UTF8 == chtype)
	{
		nUtf8Length = WideCharToMultiByte(CP_UTF8,
			NULL,
			buf,
			wcslen(buf),
			NULL,
			0,
			NULL,
			NULL);
		
		pUtf8 = new char[nUtf8Length + 1];
		memset(pUtf8, 0, sizeof(char) * (nUtf8Length + 1));

		WideCharToMultiByte(CP_UTF8,
			0,
			buf,
			wcslen(buf),
			pUtf8,
			nUtf8Length,
			NULL,
			NULL);
		//pUtf8[nUtf8Length] = '\0';
	}
	else
	{
		tmp = buf;
		pUtf8 = (char *)tmp;
	}

	ret = X509_NAME_add_entry_by_NID(subject, nid, chtype, (unsigned char*)pUtf8, -1, -1, 0);
	
	return ret;
}

static EVP_PKEY_CTX *set_keygen_ctx(BIO *err, const char *gstr, int *pkey_type,
	long *pkeylen, char **palgnam,
	ENGINE *keygen_engine)
{
	EVP_PKEY_CTX *gctx = NULL;
	EVP_PKEY *param = NULL;
	long keylen = -1;
	BIO *pbio = NULL;
	const char *paramfile = NULL;

	if (gstr == NULL)
	{
		*pkey_type = EVP_PKEY_RSA;
		keylen = *pkeylen;
	}
	else if (gstr[0] >= '0' && gstr[0] <= '9')
	{
		*pkey_type = EVP_PKEY_RSA;
		keylen = atol(gstr);
		*pkeylen = keylen;
	}
	else if (!strncmp(gstr, "param:", 6))
		paramfile = gstr + 6;
	else
	{
		const char *p = strchr(gstr, ':');
		int len;
		ENGINE *tmpeng;
		const EVP_PKEY_ASN1_METHOD *ameth;

		if (p)
			len = p - gstr;
		else
			len = strlen(gstr);
		/* The lookup of a the string will cover all engines so
		* keep a note of the implementation.
		*/

		ameth = EVP_PKEY_asn1_find_str(&tmpeng, gstr, len);

		if (!ameth)
		{
			BIO_printf(err, "Unknown algorithm %.*s\n", len, gstr);
			return NULL;
		}

		EVP_PKEY_asn1_get0_info(NULL, pkey_type, NULL, NULL, NULL,
			ameth);

		if (*pkey_type == EVP_PKEY_RSA)
		{
			if (p)
			{
				keylen = atol(p + 1);
				*pkeylen = keylen;
			}
			else
				keylen = *pkeylen;
		}
		else if (p)
			paramfile = p + 1;
	}

	if (paramfile)
	{
		pbio = BIO_new_file(paramfile, "r");
		if (!pbio)
		{
			BIO_printf(err, "Can't open parameter file %s\n",
				paramfile);
			return NULL;
		}
		param = PEM_read_bio_Parameters(pbio, NULL);

		if (!param)
		{
			X509 *x;
			(void)BIO_reset(pbio);
			x = PEM_read_bio_X509(pbio, NULL, NULL, NULL);
			if (x)
			{
				param = X509_get_pubkey(x);
				X509_free(x);
			}
		}

		BIO_free(pbio);

		if (!param)
		{
			BIO_printf(err, "Error reading parameter file %s\n",
				paramfile);
			return NULL;
		}
		if (*pkey_type == -1)
			*pkey_type = EVP_PKEY_id(param);
		else if (*pkey_type != EVP_PKEY_base_id(param))
		{
			BIO_printf(err, "Key Type does not match parameters\n");
			EVP_PKEY_free(param);
			return NULL;
		}
	}

	if (palgnam)
	{
		const EVP_PKEY_ASN1_METHOD *ameth;
		ENGINE *tmpeng;
		const char *anam;
		ameth = EVP_PKEY_asn1_find(&tmpeng, *pkey_type);
		if (!ameth)
		{
			BIO_puts(err, "Internal error: can't find key algorithm\n");
			return NULL;
		}
		EVP_PKEY_asn1_get0_info(NULL, NULL, NULL, NULL, &anam, ameth);
		*palgnam = BUF_strdup(anam);
	}

	if (param)
	{
		gctx = EVP_PKEY_CTX_new(param, keygen_engine);
		*pkeylen = EVP_PKEY_bits(param);
		EVP_PKEY_free(param);
	}
	else
		gctx = EVP_PKEY_CTX_new_id(*pkey_type, keygen_engine);

	if (!gctx)
	{
		BIO_puts(err, "Error allocating keygen context\n");
		ERR_print_errors(err);
		return NULL;
	}

	if (EVP_PKEY_keygen_init(gctx) <= 0)
	{
		BIO_puts(err, "Error initializing keygen context\n");
		ERR_print_errors(err);
		return NULL;
	}
#ifndef OPENSSL_NO_RSA
	if ((*pkey_type == EVP_PKEY_RSA) && (keylen != -1))
	{
		if (EVP_PKEY_CTX_set_rsa_keygen_bits(gctx, keylen) <= 0)
		{
			BIO_puts(err, "Error setting RSA keysize\n");
			ERR_print_errors(err);
			EVP_PKEY_CTX_free(gctx);
			return NULL;
		}
	}
#endif

	return gctx;
}

static int genpkey_cb(EVP_PKEY_CTX *ctx)
{
	char c = '*';
	BIO *b = NULL;
	b = (BIO *)EVP_PKEY_CTX_get_app_data(ctx);
	int p;
	p = EVP_PKEY_CTX_get_keygen_info(ctx, 0);
	if (p == 0) c = '.';
	if (p == 1) c = '+';
	if (p == 2) c = '*';
	if (p == 3) c = '\n';
	BIO_write(b, &c, 1);
	(void)BIO_flush(b);
#ifdef LINT
	p = n;
#endif
	return 1;
}