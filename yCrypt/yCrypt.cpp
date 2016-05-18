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
INT_PTR CALLBACK	DecryptProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);

typedef struct tagYENCFILE
{
	BYTE		cbSignature[MAX_SIGNATURE];										// yCrypt signature
	BYTE		cbNonce[crypto_secretbox_NONCEBYTES];							// Cipher nonce
	BYTE		cbPasswordSalt[crypto_pwhash_scryptsalsa208sha256_SALTBYTES];	// Password salt
	UINT        rawSize;														// Original filesize in bytes
	UINT        algorithm;														// Algorithms used in this encryption
	DWORD		dwOps;															// CPU operations for password hashing
	DWORD		dwMemory;														// Memory limit for password hashing
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
	if (!wcscmp(szExt, L"yc")) {
		// Decryption process
		DialogBox(hInstance, MAKEINTRESOURCE(IDD_DECRYPT), NULL, DecryptProc);
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
	// handle NULL

	BYTE nonce[crypto_secretbox_NONCEBYTES];

	randombytes_buf(nonce, sizeof(nonce));
	crypto_secretbox_easy((LPBYTE)hCipherBuffer, (LPBYTE)hFileBuffer, nFilesz, nonce, key);
	
	YENCFILE encFileStrct;
	memcpy(encFileStrct.cbSignature, pszSignature, MAX_SIGNATURE);
	memcpy(encFileStrct.cbNonce, nonce, crypto_secretbox_NONCEBYTES);
	memcpy(encFileStrct.cbPasswordSalt, salt, crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
	encFileStrct.rawSize = nFilesz;
	encFileStrct.algorithm = YC_SCRYPT_SALSA_POLY;
	encFileStrct.dwOps = crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE;
	encFileStrct.dwMemory = crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE;

	wcscat_s(szFile, MAX_PATH, L".yc");

	// WRITE
	HANDLE hFileEncrypt = CreateFile(
		szFile,					// Name of the write
		GENERIC_WRITE,			// Open for writing
		0,						// Do not share
		NULL,					// Default security
		CREATE_NEW,				// Create new file only
		FILE_ATTRIBUTE_NORMAL,	// Normal file
		NULL);					// No attr. template

	if (hFileEncrypt == INVALID_HANDLE_VALUE)
	{
		MessageBox(NULL, L"Cannot open file", L"Encryption error", MB_ICONERROR);
		bErrorFlag = FALSE;
		goto exit_on_failure;
	}

	bErrorFlag = WriteFile(
		hFileEncrypt,			// Open file handle
		&encFileStrct,			// Start of data to write
		sizeof(YENCFILE),		// Number of bytes to write
		&numread,				// Number of bytes that were written
		NULL);					// No overlapped structure'

	if (!bErrorFlag)
	{
		MessageBox(NULL, L"Cannot write to file", L"Encryption error", MB_ICONERROR);
		goto exit_on_failure;
	}

	bErrorFlag = WriteFile(
		hFileEncrypt,			// Open file handle
		hCipherBuffer,			// Start of data to write
		nCiphersz,				// Number of bytes to write
		&numread,				// Number of bytes that were written
		NULL);					// No overlapped structure

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
	sodium_memzero(key, crypto_secretbox_KEYBYTES);

	LocalFree(hFileBuffer);
	LocalFree(hCipherBuffer);

	return bErrorFlag;
}


BOOL SodiumDecryptFile(LPTSTR password)
{
	ULONG numread;
	BOOL bErrorFlag;
	YENCFILE encFileStrct;
	int nFilesz;

	if (!ReadFile(hFile, &encFileStrct, sizeof(YENCFILE), &numread, NULL)) {
		MessageBox(NULL, L"Cannot read file into memory", L"Decryption error", MB_ICONERROR);

		bErrorFlag = FALSE;
		// goto exit_on_failure;
	}

	if (sodium_memcmp(encFileStrct.cbSignature, pszSignature, MAX_SIGNATURE))
	{
		MessageBox(NULL, L"This is not an encrypted file", L"Decryption error", MB_ICONERROR);
		bErrorFlag = FALSE;
	}

	HLOCAL hCipherBuffer = LocalAlloc(LPTR, (encFileStrct.rawSize + crypto_secretbox_MACBYTES) * sizeof(BYTE));
	if (!hCipherBuffer) {
		MessageBox(NULL, L"Cannot allocate memory", L"Decryption error", MB_ICONERROR);

		bErrorFlag = FALSE;
		// goto exit_on_failure;
	}

	if (!ReadFile(hFile, hCipherBuffer, encFileStrct.rawSize + crypto_secretbox_MACBYTES, &numread, NULL)) {
		MessageBox(NULL, L"Cannot read file into memory", L"Decryption error", MB_ICONERROR);

		bErrorFlag = FALSE;
		// goto exit_on_failure;
	}

	// For now read byes must equal filesize
	assert((encFileStrct.rawSize + crypto_secretbox_MACBYTES) == numread);

	CloseHandle(hFile);

	// Wide password to multibyte password
	size_t nConvChars;
	char c_szPassword[100]; // This might not be enough
	wcstombs_s(&nConvChars, c_szPassword, password, wcslen(password) + 1);

	// DERIVE KEY
	BYTE key[crypto_secretbox_KEYBYTES];

	if (crypto_pwhash_scryptsalsa208sha256(key, crypto_secretbox_KEYBYTES, c_szPassword, strlen(c_szPassword), encFileStrct.cbPasswordSalt,
		encFileStrct.dwOps,
		encFileStrct.dwMemory) != 0) {

		MessageBox(NULL, L"Operation takes too much system resources", L"Decryption error", MB_ICONERROR);

		bErrorFlag = FALSE;
		// goto exit_on_failure;
	}

	HLOCAL hDecBuffer = LocalAlloc(LPTR, encFileStrct.rawSize * sizeof(char));
	if (!hDecBuffer) {
		return FALSE;
	}

	if (crypto_secretbox_open_easy((LPBYTE)hDecBuffer, (LPBYTE)hCipherBuffer, encFileStrct.rawSize + crypto_secretbox_MACBYTES, encFileStrct.cbNonce, key) != 0) {
		MessageBox(NULL, L"Decryption failed, please try again", L"Decryption error", MB_ICONERROR);
		return FALSE;
	}

	// WRITE
	HANDLE hFileEncrypt = CreateFile(
		L"kaas.txt",			// name of the write
		GENERIC_WRITE,			// open for writing
		0,						// do not share
		NULL,					// default security
		CREATE_NEW,				// create new file only
		FILE_ATTRIBUTE_NORMAL,	// normal file
		NULL);					// no attr. template

	if (hFileEncrypt == INVALID_HANDLE_VALUE) {
		MessageBox(NULL, L"Cannot open file", L"Decryption error", MB_ICONERROR);
		bErrorFlag = FALSE;
		// goto exit_on_failure;
	}

	bErrorFlag = WriteFile(
		hFileEncrypt,			// open file handle
		hDecBuffer,			// start of data to write
		encFileStrct.rawSize,	// number of bytes to write
		&numread,				// number of bytes that were written
		NULL);					// no overlapped structure'

	CloseHandle(hFileEncrypt);

	return TRUE;
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

			if (!SodiumEncryptFile(pwd1))
			{
				sodium_memzero(pwd1, MAX_PASSWORD);
				sodium_memzero(pwd2, MAX_PASSWORD);
				
				break;
			}
			
			sodium_memzero(pwd1, MAX_PASSWORD);
			sodium_memzero(pwd2, MAX_PASSWORD);

			EndDialog(hDlg, LOWORD(wParam));
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


// Message handler for about box.
INT_PTR CALLBACK DecryptProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
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
			TCHAR pwd[MAX_PASSWORD];

			GetDlgItemText(hDlg, IDC_PWD, pwd, MAX_PASSWORD);

			if (!wcslen(pwd)) {
				MessageBox(hDlg, L"Password cannot be empty", L"Password error", MB_ICONERROR);
				break;
			}

			if (!SodiumDecryptFile(pwd)) {
				sodium_memzero(pwd, MAX_PASSWORD);
				break;
			}

			sodium_memzero(pwd, MAX_PASSWORD);

			EndDialog(hDlg, LOWORD(wParam));
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
