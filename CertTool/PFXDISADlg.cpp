// PFXDISADlg.cpp : implementation file
//

#include "stdafx.h"
#include "CertTool.h"
#include "PFXDISADlg.h"
#include "afxdialogex.h"
#include <string>

# define PKCS12_F_OPENSSL_UNI2UTF8						127
# define NOKEYS											0x1
# define NOCERTS										0x2
# define INFO											0x4
# define CLCERTS										0x8
# define CACERTS										0x10

#define PASSWD_BUF_SIZE									2048

BIO *bio_err_1;

int dump_cert_text_1(BIO *out, X509 *x);
static int bmp_to_utf8(char *str, unsigned char *utf16, int len);
char *OPENSSL_uni2utf8(unsigned char *uni, int unilen);
int dump_certs_keys_p12(BIO *out, PKCS12 *p12, const char *pass,
	int passlen, int options, char *pempass,
	const EVP_CIPHER *enc);
int dump_certs_pkeys_bags(BIO *out, const STACK_OF(PKCS12_SAFEBAG) *bags,
	const char *pass, int passlen, int options,
	char *pempass, const EVP_CIPHER *enc);
int dump_certs_pkeys_bag(BIO *out, PKCS12_SAFEBAG *bag, const char *pass,
	int passlen, int options, char *pempass, const EVP_CIPHER *enc);
void ASN1_String2UTF_8(wchar_t** out, int &nOutLen, const char *src, int srclen);
void char2wchar_t(char *in, wchar_t** out);
// PFXDISADlg dialog

IMPLEMENT_DYNAMIC(PFXDISADlg, CDialogEx)

PFXDISADlg::PFXDISADlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_DIALOG2, pParent)
{

}

PFXDISADlg::~PFXDISADlg()
{
}

void PFXDISADlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_IMP_PIN_EDIT, m_certpin);
	DDX_Control(pDX, IDC_PRIV_PIN_EDIT, m_keypin);
	DDX_Control(pDX, IDC_PFX_FILE_EDIT, m_pfxfile);
}


BEGIN_MESSAGE_MAP(PFXDISADlg, CDialogEx)
	ON_BN_CLICKED(IDC_EXP_BUTTON, &PFXDISADlg::OnBnClickedExpButton)
	ON_BN_CLICKED(IDC_PFX_FILE_BUTTON, &PFXDISADlg::OnBnClickedPfxFileButton)
END_MESSAGE_MAP()


// PFXDISADlg message handlers


void PFXDISADlg::OnBnClickedExpButton()
{
	// TODO: Add your control notification handler code here
	_bstr_t					filetmp, passtmp;
	char					buf[8192] = { 0 };
	char					pass[50] = { 0 }, macpass[50] = { 0 };
	char					*cpass = NULL, *mpass = NULL, *badpass = NULL;
	BIO						*infile = NULL, *outfile = NULL;
	BIO						*bio_err_str = NULL;
	PKCS12					*p12 = NULL;
	FILE					*fp = NULL;
	int						fd = -1, rc = 0;
	const EVP_CIPHER		*enc;

	CString					PFXFILE = L"", IMPIN = L"", KeyPIN = L"";
	CString					Outfile = L"";
	CFileDialog				FileDlg(FALSE, L"pem");

	UpdateData(TRUE);

	FileDlg.m_ofn.lpstrTitle = L"保存文件";
	FileDlg.m_ofn.lpstrFilter = L"PEM Files(*pem)\0\0";
	if (IDOK == FileDlg.DoModal())
	{
		Outfile = FileDlg.GetPathName();

		m_pfxfile.GetWindowTextW(PFXFILE);
		m_certpin.GetWindowTextW(IMPIN);
		m_keypin.GetWindowTextW(KeyPIN);

		if (IMPIN == L"")
		{
			AfxMessageBox(_T("请输入证书保护PIN码!"));
			return;
		}

		do_pipe_sig();
		CRYPTO_malloc_init();
		ERR_load_crypto_strings();
		OpenSSL_add_all_algorithms();

		enc = EVP_des_ede3_cbc();
		if (KeyPIN == L"")
		{
			enc = NULL;
		}

		bio_err_str = BIO_new(BIO_s_mem());

		cpass = pass;
		mpass = macpass;

		ERR_load_crypto_strings();
		filetmp = PFXFILE;
		infile = BIO_new_file(filetmp, "rb");
		if (infile == NULL)
		{
			goto exit;
		}

		filetmp = Outfile;
		outfile = BIO_new_file(filetmp, "wb");
		if (outfile == NULL)
		{
			goto exit;
		}

		p12 = d2i_PKCS12_bio(infile, NULL);
		if (p12 == NULL)
		{
			ERR_print_errors(bio_err_str);
			BIO_read(bio_err_str, buf, 8191);
			goto exit;
		}

		passtmp = IMPIN;
		memcpy(pass, (char *)passtmp, wcslen(passtmp));
		memcpy(macpass, pass, sizeof macpass);
		

		//verify MAC
		if (!mpass[0] && PKCS12_verify_mac(p12, NULL, 0))
		{
			cpass = NULL;
		}
		else if (!PKCS12_verify_mac(p12, mpass, -1))
		{
			unsigned char *utmp;
			int utmplen;
			utmp = OPENSSL_asc2uni(mpass, -1, NULL, &utmplen);
			if (utmp == NULL)
				goto exit;
			badpass = OPENSSL_uni2utf8(utmp, utmplen);
			OPENSSL_free(utmp);
			if (!PKCS12_verify_mac(p12, badpass, -1)) {
				BIO_printf(bio_err_str, "Mac verify error: invalid password?\n");
				ERR_print_errors(bio_err_str);
				goto exit;
			}
			else {
				BIO_printf(bio_err_str, "Warning: using broken algorithm\n");
				cpass = badpass;
			}
			BIO_printf(bio_err_str, "Mac verify error: invalid password?\n");
			//ERR_print_errors(bio_err_1);
			goto exit;
		}

		BIO_printf(bio_err_str, "MAC verified OK\n");
		passtmp = KeyPIN;
		if (!dump_certs_keys_p12(outfile, p12, cpass, -1, 0, passtmp, enc)) {
			BIO_printf(bio_err_str, "Error outputting keys and certificates\n");
			ERR_print_errors(bio_err_str);
			goto exit;
		}

		rc = 1;
	exit:
		if (infile)
		{
			BIO_free(infile);
		}

		if (fp)
		{
			fclose(fp);
		}
		else if (fd >= 0)
		{
			closesocket(fd);
		}

		if (outfile)
		{
			BIO_free(outfile);
		}

		if (p12)
		{
			PKCS12_free(p12);
		}

		if (rc == 1)
		{
			AfxMessageBox(_T("PFX-->PEM, 转换成功!"));
		}
		else
		{
			AfxMessageBox(_T("PFX-->PEM, 转换失败!"));
		}
	}
}


void PFXDISADlg::OnBnClickedPfxFileButton()
{
	// TODO: Add your control notification handler code here
	BOOL isOpen = TRUE;		//是否打开(否则为保存)
	CString defaultDir = L"C:\\";	//默认打开的文件路径
	CString fileName = L"";			//默认打开的文件名
	CString filter = L"文件 (*.pfx; *.p12)|*.pfx; *.p12||";	//文件过虑的类型
	CFileDialog openFileDlg(isOpen, defaultDir, fileName, OFN_HIDEREADONLY | OFN_READONLY, filter, NULL);
	INT_PTR result = openFileDlg.DoModal();
	CString filePath = L"";

	if (result == IDOK) {
		filePath = openFileDlg.GetPathName();
		m_pfxfile.SetWindowTextW(filePath);
	}
}

static int bmp_to_utf8(char *str, unsigned char *utf16, int len)
{
	unsigned long utf32chr;

	if (len == 0) return 0;

	if (len < 2) return -1;

	/* pull UTF-16 character in big-endian order */
	utf32chr = (utf16[0] << 8) | utf16[1];

	if (utf32chr >= 0xD800 && utf32chr < 0xE000) {   /* two chars */
		unsigned int lo;

		if (len < 4) return -1;

		utf32chr -= 0xD800;
		utf32chr <<= 10;
		lo = (utf16[2] << 8) | utf16[3];
		if (lo < 0xDC00 || lo >= 0xE000) return -1;
		utf32chr |= lo - 0xDC00;
		utf32chr += 0x10000;
	}

	return UTF8_putc((unsigned char *)str, len > 4 ? 4 : len, utf32chr);
}

char *OPENSSL_uni2utf8(unsigned char *uni, int unilen)
{
	int asclen, i, j;
	char *asctmp;

	/* string must contain an even number of bytes */
	if (unilen & 1)
		return NULL;

	for (asclen = 0, i = 0; i < unilen; ) {
		j = bmp_to_utf8(NULL, uni + i, unilen - i);
		/*
		* falling back to OPENSSL_uni2asc makes lesser sense [than
		* falling back to OPENSSL_asc2uni in OPENSSL_utf82uni above],
		* it's done rather to maintain symmetry...
		*/
		if (j < 0) return OPENSSL_uni2asc(uni, unilen);
		if (j == 4) i += 4;
		else        i += 2;
		asclen += j;
	}

	/* If no terminating zero allow for one */
	if (!unilen || (uni[unilen - 2] || uni[unilen - 1]))
		asclen++;

	if ((asctmp = (char *)OPENSSL_malloc(asclen)) == NULL) {
		PKCS12err(PKCS12_F_OPENSSL_UNI2UTF8, ERR_R_MALLOC_FAILURE);
		return NULL;
	}

	/* re-run the loop emitting UTF-8 string */
	for (asclen = 0, i = 0; i < unilen; ) {
		j = bmp_to_utf8(asctmp + asclen, uni + i, unilen - i);
		if (j == 4) i += 4;
		else        i += 2;
		asclen += j;
	}

	/* If no terminating zero write one */
	if (!unilen || (uni[unilen - 2] || uni[unilen - 1]))
		asctmp[asclen] = '\0';

	return asctmp;
}

int dump_certs_keys_p12(BIO *out, PKCS12 *p12, const char *pass,
	int passlen, int options, char *pempass,
	const EVP_CIPHER *enc)
{
	STACK_OF(PKCS7) *asafes = NULL;
	STACK_OF(PKCS12_SAFEBAG) *bags;
	int i, bagnid;
	int ret = 0;
	PKCS7 *p7;

	if (!(asafes = PKCS12_unpack_authsafes(p12)))
	{
		return 0;
	}

	for (i = 0; i < sk_PKCS7_num(asafes); i++)
	{
		p7 = sk_PKCS7_value(asafes, i);
		bagnid = OBJ_obj2nid(p7->type);
		if (bagnid == NID_pkcs7_data)
		{
			bags = PKCS12_unpack_p7data(p7);
			if (options & INFO)
			{
				BIO_printf(bio_err_1, "PKCS7 Data\n");
			}
		}
		else if (bagnid == NID_pkcs7_encrypted)
		{
			if (options & INFO)
			{
				BIO_printf(bio_err_1, "PKCS7 Encrypted data: ");
				//alg_print(p7->d.encrypted->enc_data->algorithm);
			}
			bags = PKCS12_unpack_p7encdata(p7, pass, passlen);
		}
		else
		{
			continue;
		}

		if (!bags)
		{
			goto err;
		}

		if (!dump_certs_pkeys_bags(out, bags, pass, passlen, options, pempass, enc))
		{
			sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
			goto err;
		}
		sk_PKCS12_SAFEBAG_pop_free(bags, PKCS12_SAFEBAG_free);
		bags = NULL;
	}
	ret = 1;

err:
	sk_PKCS7_pop_free(asafes, PKCS7_free);
	return ret;
}

int dump_certs_pkeys_bags(BIO *out, const STACK_OF(PKCS12_SAFEBAG) *bags,
	const char *pass, int passlen, int options,
	char *pempass, const EVP_CIPHER *enc)
{
	int i;
	for (i = 0; i < sk_PKCS12_SAFEBAG_num(bags); i++)
	{
		if (!dump_certs_pkeys_bag(out, sk_PKCS12_SAFEBAG_value(bags, i), pass, passlen, options, pempass, enc))
		{
			return 0;
		}
	}

	return 1;
}

int dump_certs_pkeys_bag(BIO *out, PKCS12_SAFEBAG *bag, const char *pass,
	int passlen, int options, char *pempass, const EVP_CIPHER *enc)
{
	EVP_PKEY *pkey;
	PKCS8_PRIV_KEY_INFO *p8;
	X509 *x509;

	switch (M_PKCS12_bag_type(bag))
	{
	case NID_keyBag:
		if (options & INFO) BIO_printf(bio_err_1, "Key bag\n");
		if (options & NOKEYS) return 1;
		//print_attribs(out, bag->attrib, "Bag Attributes");
		p8 = bag->value.keybag;
		if (!(pkey = EVP_PKCS82PKEY(p8))) return 0;
		//print_attribs(out, p8->attributes, "Key Attributes");
		PEM_write_bio_PrivateKey(out, pkey, enc, NULL, 0, NULL, pempass);
		EVP_PKEY_free(pkey);
		break;

	case NID_pkcs8ShroudedKeyBag:
		if (options & INFO) {
			BIO_printf(bio_err_1, "Shrouded Keybag: ");
			//alg_print(bio_err_1, bag->value.shkeybag->algor);
		}
		if (options & NOKEYS) return 1;
		//print_attribs(out, bag->attrib, "Bag Attributes");
		if (!(p8 = PKCS12_decrypt_skey(bag, pass, passlen)))
			return 0;
		if (!(pkey = EVP_PKCS82PKEY(p8))) {
			PKCS8_PRIV_KEY_INFO_free(p8);
			return 0;
		}
		//print_attribs(out, p8->attributes, "Key Attributes");
		PKCS8_PRIV_KEY_INFO_free(p8);
		PEM_write_bio_PrivateKey(out, pkey, enc, NULL, 0, NULL, pempass);
		EVP_PKEY_free(pkey);
		break;

	case NID_certBag:
		if (options & INFO) BIO_printf(bio_err_1, "Certificate bag\n");
		if (options & NOCERTS) return 1;
		if (PKCS12_get_attr(bag, NID_localKeyID)) {
			if (options & CACERTS) return 1;
		}
		else if (options & CLCERTS) return 1;
		//print_attribs(out, bag->attrib, "Bag Attributes");
		if (M_PKCS12_cert_bag_type(bag) != NID_x509Certificate)
			return 1;
		if (!(x509 = PKCS12_certbag2x509(bag))) return 0;
		dump_cert_text_1(out, x509);
		PEM_write_bio_X509(out, x509);
		X509_free(x509);
		break;

	case NID_safeContentsBag:
		if (options & INFO) BIO_printf(bio_err_1, "Safe Contents bag\n");
		//print_attribs(out, bag->attrib, "Bag Attributes");
		return dump_certs_pkeys_bags(out, bag->value.safes, pass,
			passlen, options, pempass, enc);

	default:
		BIO_printf(bio_err_1, "Warning unsupported bag type: ");
		i2a_ASN1_OBJECT(bio_err_1, bag->type);
		BIO_printf(bio_err_1, "\n");
		return 1;
		break;
	}
	return 1;
}

int dump_cert_text_1(BIO *out, X509 *x)
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