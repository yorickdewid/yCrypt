// yCrypt.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "yCrypt.h"

#include <sodium.h>

#define MAX_LOADSTRING			100
#define MAX_PASSWORD			128
#define MAX_SIGNATURE			16
#define YC_SCRYPT_SALSA_POLY	0x8
#define YC_SCRYPT_AES_GCM		0x10
#define YC_ARGON2_AES_GCM		0x12

static LPCWCHAR pszSignature = L"YCRYPT V100$";

// Global Variables:
HANDLE hFile;										// File handler
WCHAR szFile[MAX_PATH];								// Original file name

// Forward declarations of functions included in this code module:
INT_PTR CALLBACK	EncryptProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);

typedef struct tagYENCFILE
{
	BYTE		cbSignature[MAX_SIGNATURE];				// yCrypt signature
	BYTE		cbNonce[crypto_secretbox_NONCEBYTES];	// Cipher nonce
	UINT        rawSize;								// Original filesize in bytes
	UINT        algorithm;								// Algorithms used in this encryption
} YENCFILE;

LPCWCHAR fileNameExt(LPCWCHAR filename)
{
	LPCWCHAR dot = wcsrchr(filename, '.');
	if (!dot || dot == filename) {
		return L"";
	}
	
	return dot + 1;
}

int APIENTRY wWinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPWSTR    lpCmdLine,
                     int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

	int nArgs;

	LPWSTR *szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
	if (!szArglist)
	{
		MessageBox(NULL, L"Cannot read arguments", L"File error", MB_ICONERROR);
		return FALSE;
	}
		
	if (nArgs < 2)
	{
		MessageBox(NULL, L"Encryptor takes file als first argument", L"File error", MB_ICONERROR);
		return FALSE;
	}

	wcscpy_s(szFile, MAX_PATH, szArglist[1]);
	LocalFree(szArglist);

	// Check if file exist and is accessable
	hFile = CreateFile(szFile,	// name of the write
		GENERIC_READ,			// open for reading
		0,						// share for reading
		NULL,					// default security
		OPEN_EXISTING,			// existing file only
		FILE_ATTRIBUTE_NORMAL,	// normal file
		NULL);					// no attr. template

	if (hFile == INVALID_HANDLE_VALUE)
	{
		MessageBox(NULL, L"Unable to open file", L"File error", MB_ICONERROR);
		return FALSE;
	}

	LPCWSTR szExt = fileNameExt(szFile);
	if (szExt == L"yc") {
		// Decryption process
		MessageBox(NULL, L"We should decrypt", L"Action", 0);
	} else {
		// Encryption process
		DialogBox(hInstance, MAKEINTRESOURCE(IDD_ENCRYPT), NULL, EncryptProc);
	}

    MSG msg;

    // Main message loop:
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        TranslateMessage(&msg);
		DispatchMessage(&msg);
    }

    return (int) msg.wParam;
}


BOOL SodiumEncryptFile(LPTSTR password)
{
	ULONG numread;
	BOOL bErrorFlag;
	int nFilesz;

	// Retrieve file size
	if ((nFilesz = GetFileSize(hFile, 0)) == 0)
	{
		MessageBox(NULL, L"Cannot get filesize", L"Encryption error", MB_ICONERROR);

		bErrorFlag = FALSE;
		goto exit_on_failure;
	}

	HLOCAL hFileBuffer = LocalAlloc(LPTR, nFilesz * sizeof(BYTE));
	if (!hFileBuffer)
	{
		MessageBox(NULL, L"Cannot allocate memory", L"Encryption error", MB_ICONERROR);

		bErrorFlag = FALSE;
		goto exit_on_failure;
	}

	// Read entire file into memory
	if (!ReadFile(hFile, hFileBuffer, nFilesz, &numread, NULL))
	{
		MessageBox(NULL, L"Cannot read file into memory", L"Encryption error", MB_ICONERROR);

		bErrorFlag = FALSE;
		goto exit_on_failure;
	}

	// For now read byes must equal filesize
	assert(nFilesz == numread);

	CloseHandle(hFile);

	// Wide password to multibyte password
	size_t nConvChars;
	char c_szPassword[100]; // This might not be enough
	wcstombs_s(&nConvChars, c_szPassword, password, wcslen(password) + 1);

	// DERIVE KEY
	BYTE salt[crypto_pwhash_scryptsalsa208sha256_SALTBYTES];
	BYTE key[crypto_secretbox_KEYBYTES];

	randombytes_buf(salt, crypto_pwhash_scryptsalsa208sha256_SALTBYTES);

	if (crypto_pwhash_scryptsalsa208sha256(key, crypto_secretbox_KEYBYTES, c_szPassword, strlen(c_szPassword), salt,
		crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
		crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) != 0) {
		
		MessageBox(NULL, L"Operation takes too much system resources", L"Encryption error", MB_ICONERROR);

		bErrorFlag = FALSE;
		goto exit_on_failure;
	}

	// ENC
	int nCiphersz = crypto_secretbox_MACBYTES + nFilesz;
	HLOCAL hCipherBuffer = LocalAlloc(LPTR, nCiphersz * sizeof(BYTE));

	BYTE nonce[crypto_secretbox_NONCEBYTES];

	randombytes_buf(nonce, sizeof(nonce));
	crypto_secretbox_easy((LPBYTE)hCipherBuffer, (LPBYTE)hFileBuffer, nFilesz, nonce, key);
	
	YENCFILE encFileStrct;
	memcpy(encFileStrct.cbSignature, pszSignature, MAX_SIGNATURE);
	memcpy(encFileStrct.cbNonce, nonce, crypto_secretbox_NONCEBYTES);
	encFileStrct.rawSize = nFilesz;
	encFileStrct.algorithm = YC_SCRYPT_SALSA_POLY;

	wcscat_s(szFile, MAX_PATH, L".yc");

	// WRITE
	HANDLE hFileEncrypt = CreateFile(
		szFile,					// name of the write
		GENERIC_WRITE,			// open for writing
		0,						// do not share
		NULL,					// default security
		CREATE_NEW,				// create new file only
		FILE_ATTRIBUTE_NORMAL,	// normal file
		NULL);					// no attr. template

	if (hFileEncrypt == INVALID_HANDLE_VALUE)
	{
		MessageBox(NULL, L"Cannot open file", L"Encryption error", MB_ICONERROR);
		bErrorFlag = FALSE;
		goto exit_on_failure;
	}

	bErrorFlag = WriteFile(
		hFileEncrypt,			// open file handle
		&encFileStrct,			// start of data to write
		sizeof(YENCFILE),		// number of bytes to write
		&numread,				// number of bytes that were written
		NULL);					// no overlapped structure'

	if (!bErrorFlag)
	{
		MessageBox(NULL, L"Cannot write to file", L"Encryption error", MB_ICONERROR);
		goto exit_on_failure;
	}

	bErrorFlag = WriteFile(
		hFileEncrypt,			// open file handle
		hCipherBuffer,			// start of data to write
		nCiphersz,				// number of bytes to write
		&numread,				// number of bytes that were written
		NULL);					// no overlapped structure

	if (!bErrorFlag)
	{
		MessageBox(NULL, L"Cannot write to file", L"Encryption error", MB_ICONERROR);
		goto exit_on_failure;
	}

	CloseHandle(hFileEncrypt);

exit_on_failure:
	// Override sensitive in memory
	sodium_memzero(password, wcslen(password) * sizeof(TCHAR));
	sodium_memzero(c_szPassword, strlen(c_szPassword) * sizeof(BYTE));
	sodium_memzero(key, sizeof(key));

	LocalFree(hFileBuffer);
	LocalFree(hCipherBuffer);

	return bErrorFlag;
	/*
	unsigned char *szDecBuffer = (unsigned char *)calloc(nFilesz + 1, sizeof(char));
	if (!szDecBuffer) {
		return FALSE;
	}

	if (crypto_secretbox_open_easy(szDecBuffer, szCipherBuffer, nCiphersz, nonce, key) != 0) {
		// Ouch
	}*/
}


// Message handler for about box.
INT_PTR CALLBACK EncryptProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);

	switch (message) {
	case WM_INITDIALOG:
		// Get the owner window and dialog box rectangles. 
		HWND hwndOwner;
		RECT rc, rcDlg, rcOwner;

		if ((hwndOwner = GetParent(hDlg)) == NULL) {
			hwndOwner = GetDesktopWindow();
		}

		GetWindowRect(hwndOwner, &rcOwner);
		GetWindowRect(hDlg, &rcDlg);
		CopyRect(&rc, &rcOwner);

		// Offset the owner and dialog box rectangles so that right and bottom 
		// values represent the width and height, and then offset the owner again 
		// to discard space taken up by the dialog box. 

		OffsetRect(&rcDlg, -rcDlg.left, -rcDlg.top);
		OffsetRect(&rc, -rc.left, -rc.top);
		OffsetRect(&rc, -rcDlg.right, -rcDlg.bottom);

		// The new position is the sum of half the remaining space and the owner's 
		// original position. 

		SetWindowPos(hDlg,
			HWND_TOP,
			rcOwner.left + (rc.right / 2),
			rcOwner.top + (rc.bottom / 2),
			0, 0,          // Ignores size arguments. 
			SWP_NOSIZE);

		SetWindowText(hDlg, szFile);
		return (INT_PTR)TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK) {
			TCHAR pwd1[MAX_PASSWORD];
			TCHAR pwd2[MAX_PASSWORD];

			GetDlgItemText(hDlg, IDC_PWD, pwd1, MAX_PASSWORD);
			GetDlgItemText(hDlg, IDC_PWD2, pwd2, MAX_PASSWORD);

			if (!wcslen(pwd1)) {
				MessageBox(hDlg, L"Password cannot be empty", L"Password error", MB_ICONERROR);
				break;
			}

			if (wcscmp(pwd1, pwd2)) {
				MessageBox(hDlg, L"Passwords do not match", L"Password error", MB_ICONERROR);
				break;
			}

			EndDialog(hDlg, LOWORD(wParam));

			if (!SodiumEncryptFile(pwd1))
			{
				PostQuitMessage(1);
			}
			
			PostQuitMessage(0);
			return (INT_PTR)TRUE;

		} else if (LOWORD(wParam) == IDCANCEL) {
			EndDialog(hDlg, LOWORD(wParam));
			PostQuitMessage(0);
			return (INT_PTR)TRUE;

		}
		break;
	}
	
	return (INT_PTR)FALSE;
}
