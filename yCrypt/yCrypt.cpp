// yCrypt.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "yCrypt.h"

#include <sodium.h>

#define MAX_LOADSTRING	100
#define MAX_PASSWORD	128
#define YCALG1			0x10

// Global Variables:
HANDLE hFile;										// File handler
WCHAR szFile[MAX_PATH];								// Original file name

// Forward declarations of functions included in this code module:
INT_PTR CALLBACK	EncryptProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);

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

	// Run encryption dialog
	DialogBox(hInstance, MAKEINTRESOURCE(IDD_ENCRYPT), NULL, EncryptProc);

    MSG msg;

    // Main message loop:
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        TranslateMessage(&msg);
		DispatchMessage(&msg);
    }

    return (int) msg.wParam;
}


typedef struct tagYENCFILE
{
	BYTE		cbSignature[16];
	BYTE		cbNonce[crypto_secretbox_NONCEBYTES];
	UINT        rawSize;
	int         algorithm;
} YENCFILE;


BOOL SodiumEncryptFile(LPTSTR password)
{
	ULONG numread;
	BOOL bErrorFlag;
	int nFilesz;

	// Retrieve file size
	if ((nFilesz = GetFileSize(hFile, 0)) == 0)
	{
		return FALSE;
	}

	unsigned char *szFileBuffer = (unsigned char *) malloc(nFilesz * sizeof(char)); //TODO LocalAlloc
	if (!szFileBuffer)
	{
		return FALSE;
	}

	// Read entire file into memory
	if (!ReadFile(hFile, szFileBuffer, nFilesz, &numread, NULL))
	{
		DWORD x = GetLastError();
		printf("xx ->  %ld\n", x);//TODO
	}

	assert(nFilesz == numread);

	CloseHandle(hFile);

	// Wide password to multibyte password
	size_t nConvChars;
	char c_szPassword[100]; // This might not be enough
	wcstombs_s(&nConvChars, c_szPassword, password, wcslen(password) + 1);

	// DERIVE KEY
	BYTE salt[crypto_pwhash_scryptsalsa208sha256_SALTBYTES];
	BYTE key[crypto_secretbox_KEYBYTES];

	randombytes_buf(salt, sizeof(salt));

	if (crypto_pwhash_scryptsalsa208sha256(key, sizeof(key), c_szPassword, strlen(c_szPassword), salt,
		crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
		crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) != 0) {
		/* out of memory */ //TODO
	}

	// ENC
	int nCiphersz = crypto_secretbox_MACBYTES + nFilesz;
	LPBYTE szCipherBuffer = (LPBYTE) malloc(nCiphersz * sizeof(char));

	BYTE nonce[crypto_secretbox_NONCEBYTES];

	randombytes_buf(nonce, sizeof(nonce));
	crypto_secretbox_easy(szCipherBuffer, szFileBuffer, nFilesz, nonce, key);
	
	// Override sensitive in memory
	sodium_memzero(password, wcslen(password) * sizeof(TCHAR));
	sodium_memzero(c_szPassword, strlen(c_szPassword) * sizeof(BYTE));
	sodium_memzero(key, sizeof(key));

	YENCFILE encFileStrct;
	memcpy(encFileStrct.cbSignature, "YCRYPT V100$", 16);
	memcpy(encFileStrct.cbNonce, nonce, crypto_secretbox_NONCEBYTES);
	encFileStrct.rawSize = nFilesz;
	encFileStrct.algorithm = YCALG1;

	wcscat_s(szFile, MAX_PATH, L".yc");

	// WRITE
	HANDLE hFileEncrypt = CreateFile(szFile,                // name of the write
		GENERIC_WRITE,          // open for writing
		0,                      // do not share
		NULL,                   // default security
		CREATE_NEW,             // create new file only
		FILE_ATTRIBUTE_NORMAL,  // normal file
		NULL);                  // no attr. template

	if (hFileEncrypt == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	bErrorFlag = WriteFile(
		hFileEncrypt,			// open file handle
		&encFileStrct,			// start of data to write
		sizeof(YENCFILE),		// number of bytes to write
		&numread,				// number of bytes that were written
		NULL);					// no overlapped structure'

	if (!bErrorFlag)
	{
		return FALSE;
	}

	bErrorFlag = WriteFile(
		hFileEncrypt,			// open file handle
		szCipherBuffer,			// start of data to write
		nCiphersz,				// number of bytes to write
		&numread,				// number of bytes that were written
		NULL);					// no overlapped structure

	if (!bErrorFlag)
	{
		return FALSE;
	}

	CloseHandle(hFileEncrypt);
	/*
	unsigned char *szDecBuffer = (unsigned char *)calloc(nFilesz + 1, sizeof(char));
	if (!szDecBuffer) {
		return FALSE;
	}

	if (crypto_secretbox_open_easy(szDecBuffer, szCipherBuffer, nCiphersz, nonce, key) != 0) {
		// Ouch
	}*/

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
