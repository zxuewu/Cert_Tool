#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <string.h>
#include "afxwin.h"
#include "stdafx.h"

bool gen_X509Req(CString *str);