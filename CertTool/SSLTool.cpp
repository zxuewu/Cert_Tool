#include "stdafx.h"
#include "SSLTool.h"

bool gen_X509Req(CString *str)
{
	int				ret = 0;
	RSA				*r;
	BIGNUM			*BN;

	int				nVersion = 2;
	int				bits = 2048;
	unsigned long	e = RSA_F4;

	X509_REQ		*x509_req = NULL;
	X509_NAME		*x509_name = NULL;
	EVP_PKEY		*pKey = NULL;
	RSA				*tmp = NULL;
	BIO				*out = NULL, *bio_err = NULL;
	BIO				*pReqBIO = NULL;

	const char		*szCountry = "CN";
	const char		*szProvince = "Some-State";
	const char		*szCity = "济南";
	const char		*szOrganization = "server1";
	const char		*szOrganizationUnit = "Dynamsoft";
	const char		*szCommon = "济南市";
	wchar_t*		tmp1 = L"济南市";
	const char		*szPath = "x509Req.csr";

	char			*pP10File = NULL;

	int nUtf8Length = WideCharToMultiByte(CP_UTF8,
		NULL,
		tmp1,
		wcslen(tmp1),
		NULL,
		0,
		NULL,
		NULL);

	char* pUtf8 = new char[nUtf8Length + 1];
	memset((void*)pUtf8, 0, sizeof(char) * (nUtf8Length + 1));

	WideCharToMultiByte(CP_UTF8,
		0,
		tmp1,
		wcslen(tmp1),
		pUtf8,
		nUtf8Length,
		NULL,
		NULL);
	pUtf8[nUtf8Length] = '\0';
	BN = BN_new();
	ret = BN_set_word(BN, e);
	if (ret != 1)
	{
		//TODO: failed op
	}

	r = RSA_new();
	ret = RSA_generate_key_ex(r, bits, BN, NULL);
	if (ret != 1)
	{
		//TODO: failed op
	}

	x509_req = X509_REQ_new();
	ret = X509_REQ_set_version(x509_req, nVersion);
	if (ret != 1)
	{
		//TODO: failed op
	}

	x509_name = X509_REQ_get_subject_name(x509_req);
	ret = X509_NAME_add_entry_by_NID(x509_name, NID_countryName, MBSTRING_UTF8, (unsigned char*)szCountry, -1, -1, 0); 
	if (ret != 1)
	{
		//TODO: failed op
	}

	ret = X509_NAME_add_entry_by_NID(x509_name, NID_stateOrProvinceName, MBSTRING_UTF8, (unsigned char*)szProvince, -1, -1, 0);
	if (ret != 1)
	{
		//TODO: failed op
	}

	ret = X509_NAME_add_entry_by_NID(x509_name, NID_localityName, MBSTRING_UTF8, (unsigned char*)szCity, -1, -1, 0);
	if (ret != 1)
	{
		//TODO: failed op
	}

	ret = X509_NAME_add_entry_by_NID(x509_name, NID_organizationName, MBSTRING_UTF8, (unsigned char*)szOrganization, -1, -1, 0);
	if (ret != 1)
	{
		//TODO: failed op
	}

	ret = X509_NAME_add_entry_by_NID(x509_name, NID_organizationalUnitName, MBSTRING_UTF8, (unsigned char*)szOrganizationUnit, -1, -1, 0);
	if (ret != 1)
	{
		//TODO: failed op
	}

	ret = X509_NAME_add_entry_by_NID(x509_name, NID_commonName, MBSTRING_UTF8, (unsigned char*)pUtf8, -1, -1, 0);
	if (ret != 1)
	{
		//TODO: failed op
	}

	pKey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pKey, r);
	r = NULL;

	ret = X509_REQ_set_pubkey(x509_req, pKey);
	if (ret != 1) {
		//TODO: failed op
	}

	ret = X509_REQ_sign(x509_req, pKey, EVP_sha1());    // return x509_req->signature->length
	if (ret <= 0) {
		//TODO: failed op
	}

	out = BIO_new_file(szPath, "w");
	ret = PEM_write_bio_X509_REQ(out, x509_req);
	/*out = BIO_new_mem_buf(pP10File, 4096);
	ret = PEM_write_bio_X509_REQ(out, x509_req);
	ret = BIO_get_mem_data(out, pP10File);
	*str = pP10File;*/
	pReqBIO = BIO_new(BIO_s_mem());
	if (pReqBIO)
	{
		ret = PEM_write_bio_X509_REQ(pReqBIO, x509_req);

		char *pTmp = NULL;
		ret = BIO_get_mem_data(pReqBIO, &pTmp);

		if (ret > 0 && pTmp)
		{
			*(&pP10File) = (char *)malloc(ret + 1);
			memcpy(pP10File, pTmp, ret);
			(pP10File)[ret] = 0;
		}
	}

	*str = pP10File;

	BIO_free(pReqBIO);
	BIO_free(out);

exit:

	if (x509_req)
	{
		X509_REQ_free(x509_req);
	}

	if (pKey)
	{
		EVP_PKEY_free(pKey);
	}

	if (BN)
	{
		BN_free(BN);
	}

	return (ret == 1);
}