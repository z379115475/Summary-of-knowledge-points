#pragma once
#include <atltime.h>
#include <WinBase.h>
#include <vector>
#include <Shlobj.h>
#include <Shellapi.h>
#include <wininet.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <atlimage.h>
#include "ResTool.h"

using namespace std;
#pragma comment(lib, "Wininet.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Version.lib")

typedef struct tagLVITEM64
{
	UINT mask;
	int iItem;
	int iSubItem;
	UINT state;
	UINT stateMask;
	_int64 pszText;
	int cchTextMax;
	int iImage;
	_int64 lParam;
#if (_WIN32_IE >= 0x0300)  
	int iIndent;
#endif  
#if (_WIN32_WINNT >= 0x0501)  
	int iGroupId;
	UINT cColumns; // tile view columns  
	_int64 puColumns;
#endif  
#if _WIN32_WINNT >= 0x0600  
	_int64 piColFmt;
	int iGroup; // readonly. only valid for owner data.  
#endif  
} LVITEM64;

#define BUFFER_SIZE_1K		1024		//1K缓冲区大小
#define BUFFER_SIZE_4K		4096		//4K缓冲区大小

#define _S_OK(a) if (!a) return FALSE
#define FIND_KEY(str,strKey) (str.Find(strKey) >= 0)
#define DEBUG_LOG(msg, p) {\
	CString log; \
	log = msg + p; \
	PrintLog(0, log.GetBuffer()); \
}
#define _S_FAIL_LOG(a, log) if (!a) {\
	log; \
	return FALSE; \
}

int key[8] = { 2, 0, 1, 5, 0, 6, 2, 3 };

class CUtility
{
	CUtility(){}
public:

	static CUtility& GetInstance()
	{
		static CUtility obj;

		return obj;
	}

	~CUtility(){}

	BOOL RemoveFolder(LPCTSTR pstrFolder)
	{
		if ((NULL == pstrFolder)) {
			return FALSE;
		}

		int iPathLen = _tcslen(pstrFolder);
		if (iPathLen >= MAX_PATH) {
			return FALSE;
		}

		/*确保目录的路径以2个\0结尾*/
		TCHAR tczFolder[MAX_PATH + 1];
		ZeroMemory(tczFolder, (MAX_PATH + 1)*sizeof(TCHAR));
		_tcscpy_s(tczFolder, pstrFolder);
		tczFolder[iPathLen] = _T('\0');
		tczFolder[iPathLen + 1] = _T('\0');

		SHFILEOPSTRUCT FileOp;
		ZeroMemory(&FileOp, sizeof(SHFILEOPSTRUCT));
		FileOp.fFlags |= FOF_SILENT;        /*不显示进度*/
		FileOp.fFlags |= FOF_NOERRORUI;        /*不报告错误信息*/
		FileOp.fFlags |= FOF_NOCONFIRMATION;/*直接删除，不进行确认*/
		FileOp.hNameMappings = NULL;
		FileOp.hwnd = NULL;
		FileOp.lpszProgressTitle = NULL;
		FileOp.wFunc = FO_DELETE;
		FileOp.pFrom = tczFolder;            /*要删除的目录，必须以2个\0结尾*/
		FileOp.pTo = NULL;
		FileOp.fFlags &= ~FOF_ALLOWUNDO; /*直接删除，不放入回收站*/

		/*删除目录*/
		return SHFileOperation(&FileOp) == 0;
	}

	BOOL CreateFolder(LPCTSTR pstrFolder)
	{
		if (PathFileExists(pstrFolder)) {
			return TRUE;
		}

		return CreateDirectory(pstrFolder, NULL);
	}

	BOOL CopyFolder(LPCTSTR lpszFromPath, LPCTSTR lpszToPath)
	{
		SHFILEOPSTRUCT fileOp = { 0 };
		fileOp.wFunc = FO_COPY;
		TCHAR newFrom[MAX_PATH];
		_tcscpy_s(newFrom, lpszFromPath);
		newFrom[_tcsclen(lpszFromPath) + 1] = NULL;
		fileOp.pFrom = newFrom;
		TCHAR newTo[MAX_PATH];
		_tcscpy_s(newTo, lpszToPath);
		newTo[_tcsclen(lpszToPath) + 1] = NULL;
		fileOp.pTo = newTo;
		fileOp.fFlags = FOF_SILENT | FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_NOCONFIRMMKDIR;

		return SHFileOperation(&fileOp) == 0;
	}

	BOOL ModifyFileName(CString OldFile, CString NewFile)
	{
		return MoveFile(OldFile, NewFile);
	}

	void FindFile(CString strFolderPath)
	{
		WIN32_FIND_DATA FindFileData;
		HANDLE hFind = ::FindFirstFile(strFolderPath, &FindFileData);

		if (INVALID_HANDLE_VALUE == hFind) return;
		while (TRUE)
		{
			if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				if (FindFileData.cFileName[0] != TEXT('.'))
				{
					CString strFolderName = FindFileData.cFileName;	//文件夹
				}
			}
			else
			{
				CString strFileName = FindFileData.cFileName; //文件
			}

			if (!FindNextFile(hFind, &FindFileData)) break;
		}
		FindClose(hFind);
	}

	BOOL ExtractResource(HMODULE hModule, DWORD dwResID, LPCTSTR lpResType, CString &strFileName)
	{
		HRSRC	hSysRes;
		DWORD	dwSize;
		HGLOBAL gl;
		LPVOID  lp;
		HANDLE  fp;
		DWORD   fileSize;

		hSysRes = FindResource(hModule, MAKEINTRESOURCE(dwResID), lpResType);

		if (NULL == hSysRes) {
			return FALSE;
		}

		dwSize = SizeofResource(hModule, hSysRes);
		if (0 == dwSize) {
			return FALSE;
		}

		gl = LoadResource(hModule, hSysRes);
		if (NULL == gl) {
			return FALSE;
		}

		lp = LockResource(gl);
		if (NULL == lp) {
			FreeResource(gl);
			return FALSE;
		}

		fp = CreateFile(strFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_FLAG_BACKUP_SEMANTICS, NULL);
		if (!WriteFile(fp, lp, dwSize, &fileSize, NULL)) {
			CloseHandle(fp);
			FreeResource(gl);
			return FALSE;
		}

		CloseHandle(fp);
		FreeResource(gl);

		return TRUE;
	}

	BOOL ExtractResource2Memory(HMODULE hModule, DWORD dwResID, LPCTSTR lpResType, CHAR** pMem, DWORD& dwSize)
	{
		HRSRC	hSysRes;
		HGLOBAL gl;
		LPVOID  lp;

		hSysRes = FindResource(hModule, MAKEINTRESOURCE(dwResID), lpResType);
		if (NULL == hSysRes) {
			return FALSE;
		}

		dwSize = SizeofResource(hModule, hSysRes);
		if (0 == dwSize) {
			return FALSE;
		}

		gl = LoadResource(hModule, hSysRes);
		if (NULL == gl) {
			return FALSE;
		}

		lp = LockResource(gl);
		if (NULL == lp) {
			goto EXIT;
		}

		*pMem = new CHAR[dwSize];
		if ((*pMem) == NULL) {
			goto EXIT;
		}

		CopyMemory(*pMem, lp, dwSize);		

	EXIT:
		FreeResource(gl);

		return TRUE;
	}

	CString LongPathToShortPath(CString& strPath)
	{
		TCHAR bufShortPath[MAX_PATH] = { 0 };
		GetShortPathName(strPath, bufShortPath, MAX_PATH);

		CString strShort = bufShortPath;
		if (strShort.IsEmpty()) {
			return strPath;
		}
		
		return bufShortPath;
	}
	
	BOOL GetSubString(CString &strOring, LPCTSTR lpLeftTag, LPCTSTR lpRightTag, CString &strSub)
	{
		INT leftPos = strOring.Find(lpLeftTag);
		if (leftPos == -1) {
			return FALSE;
		}

		leftPos += _tcslen(lpLeftTag);

		INT rightPos = strOring.Find(lpRightTag, leftPos);
		if (rightPos == -1) {
			strSub = strOring.Mid(leftPos);
		}
		else {
			strSub = strOring.Mid(leftPos, rightPos - leftPos);
		}

		return (strSub.IsEmpty() ? FALSE : TRUE);
	}

	BOOL GetKeyFormString(CString& lpContent, LPCTSTR lpKey, LPCTSTR lpTag, CString &strValue)
	{
		CString strKey = lpKey;
		strKey += TEXT("=");
		return GetSubString(lpContent, strKey, lpTag, strValue);
	}

	DWORD GetKeyValue(LPCTSTR szFileName, LPCTSTR szSection, LPCTSTR szKeyName, CString &strValue, DWORD dwMaxSize = MAX_PATH)
	{
		DWORD dwRet = GetPrivateProfileString(szSection, szKeyName, NULL, strValue.GetBuffer(dwMaxSize), dwMaxSize, szFileName);
		strValue.ReleaseBuffer();

		return dwRet;
	}

	BOOL SetKeyValue(LPCTSTR szFileName, LPCTSTR szSection, LPCTSTR szKeyName, LPCTSTR strValue)
	{
		return WritePrivateProfileString(szSection, szKeyName, strValue, szFileName);
	}

	BOOL SplitString(CString& strSrc, LPCTSTR lpszTag, vector<CString> &strArray)
	{
		INT nPis = 0;
		CString strElement;

		do {
			strElement = strSrc.Tokenize(lpszTag, nPis);
		} while (!strElement.IsEmpty() && (strArray.push_back(strElement),TRUE));
		
		return !strArray.empty();
	}

	CString GetCurrentPath(HMODULE hModu = NULL)
	{
		TCHAR szFilePath[MAX_PATH + 1] = { 0 };

		GetModuleFileName(hModu, szFilePath, MAX_PATH);
		PathRemoveFileSpec(szFilePath);

		long length = 0;
		length = GetShortPathName(szFilePath, NULL, 0);
		wchar_t bufShortPath[256] = { 0 };
		GetShortPathName(szFilePath, bufShortPath, length);

		if (bufShortPath == L"") {
			return szFilePath;
		}

		return bufShortPath;
	}

	CString GetPathLastName(CString strPath)
	{
		strPath = strPath.Right(strPath.GetLength() - strPath.ReverseFind('\\') - 1);
		strPath.MakeLower();
		return strPath;
	}

	INT GetRadomNum(DWORD dwMax)
	{
		static BOOL bIsInit = FALSE;

		if (!bIsInit) {
			srand((UINT)time(NULL));
			bIsInit = TRUE;
		}

		return (rand() % dwMax);
	}

	CString GetRadomString(DWORD dwLength)
	{
		CString str;
		str.GetBuffer(dwLength + 1);
		while (dwLength--){
			str.AppendChar('a' + GetRadomNum(26));
		}

		return str;
	}

	BOOL Is64BitOS()
	{
		BOOL bRet = FALSE;
		SYSTEM_INFO si;

		typedef VOID(WINAPI *LPFN_GetNativeSystemInfo)(LPSYSTEM_INFO lpSystemInfo);

		LPFN_GetNativeSystemInfo nsInfo = (LPFN_GetNativeSystemInfo)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "GetNativeSystemInfo");
		if (NULL != nsInfo) {
			nsInfo(&si);
		} else {
			GetSystemInfo(&si);
		}

		if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
			si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64) {
			bRet = TRUE;
		}

		return bRet;
	}

	BOOL SetPrivilege(HANDLE hProcess, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
	{
		HANDLE hToken;
		if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken)) {
			return FALSE;
		}
		LUID luid;
		if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
			return FALSE;
		}
		TOKEN_PRIVILEGES tkp;
		tkp.PrivilegeCount = 1;
		tkp.Privileges[0].Luid = luid;
		tkp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : FALSE;

		if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
			return FALSE;
		}
		return TRUE;
	}

	BOOL PromoteProcessPrivileges()
	{
		HANDLE hToken = NULL;
		BOOL bFlag = FALSE;

		if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
			TOKEN_PRIVILEGES tp;
			tp.PrivilegeCount = 1;
			if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
				CloseHandle(hToken);
				return FALSE;
			}

			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
				CloseHandle(hToken);
				return FALSE;
			}
		}

		CloseHandle(hToken);

		return TRUE;
	}

	CString GetEnvVar(LPCTSTR lpVar)
	{
		CString strValue;
		::GetEnvironmentVariable(lpVar, strValue.GetBuffer(MAX_PATH), MAX_PATH);
		strValue.ReleaseBuffer();

		return strValue;
	}

	CString GetPathFormEnvVar(LPCTSTR pVar)
	{
		TCHAR szPath[MAX_PATH] = { 0 };
		GetEnvironmentVariable(pVar, szPath, MAX_PATH);

		CString strPath = szPath;

		return strPath;
	}

	BOOL DeleteUrlCache()
	{
		BOOL bRet = FALSE;
		HANDLE hEntry;
		LPINTERNET_CACHE_ENTRY_INFO lpCacheEntry = NULL;
		DWORD dwEntrySize = BUFFER_SIZE_1K;

		lpCacheEntry = (LPINTERNET_CACHE_ENTRY_INFO) new char[dwEntrySize];
		hEntry = FindFirstUrlCacheEntry(NULL, lpCacheEntry, &dwEntrySize);
		if (!hEntry) {
			return FALSE;
		}

		do {
			DeleteUrlCacheEntry(lpCacheEntry->lpszSourceUrlName);
			dwEntrySize = BUFFER_SIZE_1K;
		} while (FindNextUrlCacheEntry(hEntry, lpCacheEntry, &dwEntrySize));

		if (lpCacheEntry) {
			delete[] lpCacheEntry;
		}

		return TRUE;
	}

	CHAR IntToHexChar(INT x)
	{
		static const CHAR HEX[16] = {
			('0'), ('1'), ('2'), ('3'),
			('4'), ('5'), ('6'), ('7'),
			('8'), ('9'), ('A'), ('B'),
			('C'), ('D'), ('E'), ('F'),
		};

		return HEX[x];
	}

	INT HexCharToInt(CHAR hex)
	{
		hex = toupper(hex);
		if (isdigit(hex))
			return (hex - '0');
		if (isalpha(hex))
			return (hex - 'A' + 10);

		return 0;
	}

	BOOL Encrypt(CString lpOrgStr, CString& lpOutStr)
	{
		LPSTR lpOut = new CHAR[(_tcslen(lpOrgStr) + 1) * 2];
		CObjRelease<CHAR> resout(lpOut);
		CT2A ansi(lpOrgStr);
		INT i = 0;
		LPSTR lpOrg = ansi;

		while (lpOrg[i]) {
			CHAR c = lpOrgStr[i] ^ key[i % 8];
			lpOut[i * 2] = IntToHexChar(c >> 4);
			lpOut[i * 2 + 1] = IntToHexChar(c & 0xF);
			i++;
		}

		lpOut[i * 2] = '\0';
		lpOutStr = CA2T(lpOut);

		return TRUE;
	}

	BOOL Decryption(CString lpOrgStr, CString& lpOutStr)
	{
		LPSTR lpOut = new CHAR[_tcslen(lpOrgStr) + 1];
		CObjRelease<CHAR> resout(lpOut);
		CT2A ansi(lpOrgStr);
		INT i = 0;
		INT index = 0;
		LPSTR lpOrg = ansi;

		while (lpOrg[i]) {
			CHAR c = (HexCharToInt(lpOrg[i]) << 4) | HexCharToInt(lpOrg[i + 1]);
			lpOut[index] = c^ key[index % 8];
			i += 2;
			index++;
		}

		*(lpOut + index) = '\0';
		lpOutStr = CA2T(lpOut);

		return TRUE;
	}

	BOOL File2Memory(CString strFilePath, CString& strMemory)
	{
		HANDLE hFile = CreateFile(strFilePath,
			GENERIC_READ,
			FILE_SHARE_READ,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL
			);
		if (hFile == INVALID_HANDLE_VALUE) {
			return FALSE;
		}

		DWORD dwFileSize = GetFileSize(hFile, NULL);

		HANDLE lhShareMemory = CreateFileMapping(
			hFile,
			NULL,
			PAGE_READONLY,
			0,
			dwFileSize,
			NULL
			);
		if (!lhShareMemory) {
			return FALSE;
		}

		CHAR* lpBuffer = (CHAR*)MapViewOfFile(lhShareMemory, FILE_MAP_READ, 0, 0, dwFileSize);
		if (!lpBuffer) {
			return FALSE;
		}

		strMemory = CA2T(lpBuffer, CP_UTF8);

		UnmapViewOfFile(lpBuffer);
		CloseHandle(lhShareMemory);
		CloseHandle(hFile);

		DeleteFile(strFilePath);

		return TRUE;
	}

	BOOL Memory2File(CString strMemory, CString strFilePath)
	{
		CT2A ansi(strMemory, CP_UTF8);
		int nLen = strlen(ansi);
		DWORD fileSize = 0;
		HANDLE hFile = CreateFile(strFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_FLAG_BACKUP_SEMANTICS, NULL);
		WriteFile(hFile, ansi, nLen, &fileSize, NULL);

		CloseHandle(hFile);
		return TRUE;
	}

	BOOL MemoryToFile(LPCTSTR wszReleasePath, PVOID wszBuffer, ULONG length)
	{
		HANDLE hFile = CreateFile(wszReleasePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_FLAG_BACKUP_SEMANTICS, NULL);
		if (hFile == INVALID_HANDLE_VALUE){
			return FALSE;
		}

		DWORD dwLength;
		BOOL bRet = WriteFile(hFile, wszBuffer, length, &dwLength, NULL);
		CloseHandle(hFile);

		return bRet;
	}

	BOOL IsAllNumber(CString strBuf)
	{
		if (strBuf.SpanIncluding(L"0123456789") == strBuf) {
			return TRUE;
		}

		return FALSE;
	}

	BOOL IncludeChinese(char *str)
	{
		char c;
		while (1)
		{
			c = *str++;
			if (c == 0) break;  //如果到字符串尾则说明该字符串没有中文字符
			if (c & 0x80)        //如果字符高位为1且下一字符高位也是1则有中文字符
			{
				if (*str & 0x80) return TRUE;
			}

		}
		return FALSE;
	}

	char Encode_GetChar(BYTE num)
	{
		return
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz"
			"0123456789"
			"+/="[num];
	}

	size_t Base64_Encode(char *pDest, const char *pSrc, size_t srclen)
	{
		BYTE input[3], output[4];
		size_t i, index_src = 0, index_dest = 0;
		for (i = 0; i < srclen; i += 3)
		{
			//char [0]
			input[0] = pSrc[index_src++];
			output[0] = (BYTE)(input[0] >> 2);
			pDest[index_dest++] = Encode_GetChar(output[0]);

			//char [1]
			if (index_src < srclen)
			{
				input[1] = pSrc[index_src++];
				output[1] = (BYTE)(((input[0] & 0x03) << 4) + (input[1] >> 4));
				pDest[index_dest++] = Encode_GetChar(output[1]);
			}
			else
			{
				output[1] = (BYTE)((input[0] & 0x03) << 4);
				pDest[index_dest++] = Encode_GetChar(output[1]);
				pDest[index_dest++] = '=';
				pDest[index_dest++] = '=';
				break;
			}

			//char [2]
			if (index_src < srclen)
			{
				input[2] = pSrc[index_src++];
				output[2] = (BYTE)(((input[1] & 0x0f) << 2) + (input[2] >> 6));
				pDest[index_dest++] = Encode_GetChar(output[2]);
			}
			else
			{
				output[2] = (BYTE)((input[1] & 0x0f) << 2);
				pDest[index_dest++] = Encode_GetChar(output[2]);
				pDest[index_dest++] = '=';
				break;
			}

			//char [3]
			output[3] = (BYTE)(input[2] & 0x3f);
			pDest[index_dest++] = Encode_GetChar(output[3]);
		}
		//null-terminator
		pDest[index_dest] = 0;
		return index_dest;
	}

	BYTE Decode_GetByte(char c)
	{
		if (c == '+')
			return 62;
		else if (c == '/')
			return 63;
		else if (c <= '9')
			return (BYTE)(c - '0' + 52);
		else if (c == '=')
			return 64;
		else if (c <= 'Z')
			return (BYTE)(c - 'A');
		else if (c <= 'z')
			return (BYTE)(c - 'a' + 26);
		return 64;
	}

	void Base64_Decode(char *buffer, const char *text, int textlen)
	{
		BYTE input[4];
		int i, index = 0;
		for (i = 0; i < textlen; i += 4)
		{
			//byte[0]
			input[0] = Decode_GetByte(text[i]);
			input[1] = Decode_GetByte(text[i + 1]);
			buffer[index++] = (input[0] << 2) + (input[1] >> 4);

			//byte[1]
			if (text[i + 2] != '=')
			{
				input[2] = Decode_GetByte(text[i + 2]);
				buffer[index++] = ((input[1] & 0x0F) << 4) + (input[2] >> 2);
			}


			//byte[2]
			if (text[i + 3] != '=')
			{
				input[3] = Decode_GetByte(text[i + 3]);
				buffer[index++] = ((input[2] & 0x03) << 6) + (input[3]);
			}
		}


		//null-terminator
		buffer[index] = 0;
	}

	BOOL GetExplorerProcessId(DWORD& dwPid)
	{
		HWND hWnd = ::FindWindow(TEXT("Progman"), TEXT("Program Manager"));
		hWnd = ::FindWindowEx(hWnd, 0, TEXT("SHELLDLL_DefView"), NULL);
		hWnd = ::FindWindowEx(hWnd, 0, TEXT("SysListView32"), NULL);

		if (hWnd == NULL) {
			return FALSE;
		}

		GetWindowThreadProcessId(hWnd, &dwPid);

		return TRUE;
	}

	DWORD GetProcessIdByName(CString strFilename)
	{
		HANDLE procSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (procSnap == INVALID_HANDLE_VALUE) {
			return FALSE;
		}

		BOOL bIsFound = FALSE;
		PROCESSENTRY32 procEntry = { 0 };

		procEntry.dwSize = sizeof(PROCESSENTRY32);

		BOOL bRet = Process32First(procSnap, &procEntry);
		CString strExeName;
		while (bRet) {
			// 进程查看器搜索
			strExeName = procEntry.szExeFile;
			strExeName.MakeLower();
			if (strExeName == strFilename)
			{
				//id->句柄
				HANDLE _hProcessHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, procEntry.th32ProcessID);
				//句柄->全路径
				TCHAR szFilePath[MAX_PATH + 1] = { 0 };
				GetModuleFileNameEx(_hProcessHandle, NULL, szFilePath, MAX_PATH);
				//全路径->文件大小
				WIN32_FIND_DATA fileInfo;
				DWORD fileSize = 0;
				HANDLE hFind = FindFirstFile(szFilePath, &fileInfo);
				fileSize = fileInfo.nFileSizeLow;
				FindClose(hFind);

				return procEntry.th32ProcessID;
			}

			bRet = Process32Next(procSnap, &procEntry);
		}

		CloseHandle(procSnap);

		return -1;
	}

	BOOL MyCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE pThreadProc, LPVOID pRemoteBuf)
	{
		HANDLE      hThread = NULL;
		FARPROC     pFunc = NULL;

		hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);
		if (hThread == NULL) {
			return FALSE;
		}

		if (WAIT_FAILED == WaitForSingleObject(hThread, INFINITE)) {
			return FALSE;
		}

		return TRUE;
	}

	BOOL InjectThread(DWORD dwPid, LPCTSTR lpDllName)
	{
		CHAR *pFunName;
		BOOL bRet = TRUE;
		HANDLE hThread = NULL;
		LPVOID pDllAddr = NULL;
		LPTHREAD_START_ROUTINE pFunAddr = NULL;
#ifdef UNICODE
		pFunName = "LoadLibraryW";
#else
		pFunName = "LoadLibraryA";
#endif
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
		if (NULL == hProcess) {
			bRet = FALSE;
			goto _ERROR;
		}

		size_t nDllLen = lstrlen(lpDllName) + 1;
		nDllLen *= sizeof(TCHAR);
		pDllAddr = VirtualAllocEx(hProcess, NULL, nDllLen, MEM_COMMIT, PAGE_READWRITE);
		if (NULL == pDllAddr) {
			bRet = FALSE;
			goto _ERROR;
		}

		// 在刚申请的内存地址中写入dll的完整路径
		DWORD dwNum = 0;
		if (!WriteProcessMemory(hProcess, pDllAddr, lpDllName, nDllLen, NULL)) {
			bRet = FALSE;
			goto _ERROR;
		}

		pFunAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), pFunName);

		if (!MyCreateRemoteThread(hProcess, pFunAddr, pDllAddr)) {
			bRet = FALSE;
			goto _ERROR;
		}

	_ERROR:
		if (pDllAddr)
			VirtualFreeEx(hProcess, pDllAddr, 0, MEM_RELEASE);

		if (hThread)
			CloseHandle(hThread);

		if (hProcess)
			CloseHandle(hProcess);

		return bRet;
	}

	BOOL WriteSharedMemory(CString strMsg)
	{
		TCHAR szName[] = TEXT("XtSharedMemory");    // 指向同一块共享内存的名字

		HANDLE hMapFile = CreateFileMapping(
			INVALID_HANDLE_VALUE,    // use paging file
			NULL,                    // default security
			PAGE_READWRITE,          // read/write access
			0,                       // maximum object size (high-order DWORD)
			BUFFER_SIZE_1K,          // maximum object size (low-order DWORD)
			szName);                 // name of mapping object

		if (hMapFile == NULL) {
			return FALSE;
		}

		LPTSTR pBuf = (LPTSTR)MapViewOfFile(hMapFile,   // handle to map object
			FILE_MAP_ALL_ACCESS,						 // read/write permission
			0,
			0,
			BUFFER_SIZE_1K);

		if (pBuf == NULL) {
			CloseHandle(hMapFile);
			return FALSE;
		}

		CopyMemory(pBuf, strMsg.GetBuffer(), (strMsg.GetLength() + 1)* sizeof(TCHAR));

		return TRUE;
	}

	BOOL ReadSharedMemory(CString& strMsg)
	{
		// 进程间通信
		HANDLE hShareMemory = CreateFileMapping(
			INVALID_HANDLE_VALUE,
			NULL,
			PAGE_READWRITE,
			0,
			BUFFER_SIZE_1K,
			TEXT("XtSharedMemory")
			);

		if (hShareMemory == NULL) {
			return FALSE;
		}

		LPTSTR pBuf = (LPTSTR)MapViewOfFile(hShareMemory, FILE_MAP_WRITE | FILE_MAP_READ, 0, 0, BUFFER_SIZE_1K);

		if (pBuf == NULL) {
			CloseHandle(hShareMemory);
			return FALSE;
		}

		strMsg = pBuf;

		UnmapViewOfFile(pBuf);
		CloseHandle(hShareMemory);
	}

	void Createlnk(CString strLnkName, CString strSrcFile)
	{
		TCHAR path[255];
		SHGetSpecialFolderPath(0, path, CSIDL_DESKTOPDIRECTORY, 0);
		CString strDesktop = path;
		strDesktop += strLnkName;

		HRESULT hr = CoInitialize(NULL);
		if (SUCCEEDED(hr))
		{
			IShellLink *pisl;
			hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (void**)&pisl);
			if (SUCCEEDED(hr))
			{
				IPersistFile* pIPF;
				//这里是我们要创建快捷方式的原始文件地址
				pisl->SetPath(strSrcFile);
				hr = pisl->QueryInterface(IID_IPersistFile, (void**)&pIPF);
				if (SUCCEEDED(hr)) {
					//这里是我们要创建快捷方式的目标地址
					pIPF->Save(strDesktop, FALSE);
					pIPF->Release();
				}
				pisl->Release();
			}
			CoUninitialize();
		}
	}

	BOOL GetGUID(CString& strName)
	{
		GUID guid;
		CoCreateGuid(&guid);
		TCHAR szFolderName[MAX_PATH] = { 0 };

		_sntprintf_s(szFolderName, MAX_PATH, _TRUNCATE, TEXT("{%08lX-%04X-%04x-%02X%02X-%02X%02X%02X%02X%02X%02X}"),
			guid.Data1,
			guid.Data2,
			guid.Data3,
			guid.Data4[0],
			guid.Data4[1],
			guid.Data4[2],
			guid.Data4[3],
			guid.Data4[4],
			guid.Data4[5],
			guid.Data4[6],
			guid.Data4[7]);

		strName = szFolderName;

		return TRUE;
	}

	bool GetProcessFilePath(IN HANDLE hProcess, OUT std::wstring& szFilePath)
	{
		szFilePath = _T("");
		TCHAR tsFileDosPath[MAX_PATH + 1];
		ZeroMemory(tsFileDosPath, sizeof(TCHAR)*(MAX_PATH + 1));
		if (0 == GetProcessImageFileName(hProcess, tsFileDosPath, MAX_PATH + 1))
		{
			return false;
		}

		// 获取Logic Drive String长度  
		UINT uiLen = GetLogicalDriveStrings(0, NULL);
		if (0 == uiLen)
		{
			return false;
		}

		PTSTR pLogicDriveString = new TCHAR[uiLen + 1];
		ZeroMemory(pLogicDriveString, uiLen + 1);
		uiLen = GetLogicalDriveStrings(uiLen, pLogicDriveString);
		if (0 == uiLen)
		{
			delete[]pLogicDriveString;
			return false;
		}

		TCHAR szDrive[3] = TEXT(" :");
		PTSTR pDosDriveName = new TCHAR[MAX_PATH];
		PTSTR pLogicIndex = pLogicDriveString;

		do
		{
			szDrive[0] = *pLogicIndex;
			uiLen = QueryDosDevice(szDrive, pDosDriveName, MAX_PATH);
			if (0 == uiLen)
			{
				if (ERROR_INSUFFICIENT_BUFFER != GetLastError())
				{
					break;
				}

				delete[]pDosDriveName;
				pDosDriveName = new TCHAR[uiLen + 1];
				uiLen = QueryDosDevice(szDrive, pDosDriveName, uiLen + 1);
				if (0 == uiLen)
				{
					break;
				}
			}

			uiLen = _tcslen(pDosDriveName);
			if (0 == _tcsnicmp(tsFileDosPath, pDosDriveName, uiLen))
			{
				wchar_t buf[1024];
				swprintf_s(buf, 1024, L"%s%s", szDrive, tsFileDosPath + uiLen);
				wchar_t *pstr = buf;
				szFilePath = std::wstring(pstr);

				break;
			}

			while (*pLogicIndex++);
		} while (*pLogicIndex);

		delete[]pLogicDriveString;
		delete[]pDosDriveName;

		return true;
	}

	BOOL EnableDebugPrivilege(BOOL fEnable)
	{
		BOOL fOk = FALSE;
		HANDLE hToken;
		// 得到进程的访问令牌
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
		{
			TOKEN_PRIVILEGES tp;
			tp.PrivilegeCount = 1;
			// 查看系统特权值并返回一个LUID结构体 
			LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
			tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
			// 启用/关闭 特权
			AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
			fOk = (GetLastError() == ERROR_SUCCESS);
			CloseHandle(hToken);
		}
		else
		{
			return 0;
		}
		return(fOk);
	}

	BOOL GetProcessDll(int nProID, std::vector<CString>& vDLLNames)
	{		
		MODULEENTRY32 me32;
		EnableDebugPrivilege(1);

		HANDLE hProcessDll = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, nProID);
		me32.dwSize = sizeof(MODULEENTRY32);
		if (!Module32First(hProcessDll, &me32)) {
			return FALSE;
		}

		do {
			vDLLNames.push_back(me32.szExePath);
		} while (Module32Next(hProcessDll, &me32));

		EnableDebugPrivilege(0);

		return TRUE;
	}

	CString GetDeskPath(int nParam)
	{
		TCHAR path[255];
		SHGetSpecialFolderPath(0, path, nParam, 0);
		CString strDeskPath = path;
		strDeskPath = LongPathToShortPath(strDeskPath);
		return strDeskPath;
	}

	BOOL GetDeskPath(CString& strUserDesk, CString& strCommonDesk)
	{
		strUserDesk = GetDeskPath(CSIDL_DESKTOPDIRECTORY);
		strCommonDesk = GetDeskPath(CSIDL_COMMON_DESKTOPDIRECTORY);
		return TRUE;
	}

	CString ExpandShortcut(CString inFile)
	{
		CString   outFile = _T("");

		IShellLink*   psl;
		HRESULT   hres;
		LPTSTR   lpsz = inFile.GetBuffer(MAX_PATH);

		HRESULT hr = ::CoInitialize(NULL);
		if (FAILED(hr))	return L"";

		hres = ::CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
			IID_IShellLink, (LPVOID*)&psl);

		if (SUCCEEDED(hres)) {
			IPersistFile*   ppf;
			hres = psl->QueryInterface(IID_IPersistFile, (LPVOID*)&ppf);

			if (SUCCEEDED(hres)) {
				hres = ppf->Load(lpsz, STGM_READ);

				if (SUCCEEDED(hres))   {
					WIN32_FIND_DATA   wfd;
					HRESULT   hres = psl->GetPath(outFile.GetBuffer(MAX_PATH),
						MAX_PATH,
						&wfd,
						SLGP_UNCPRIORITY);

					outFile.ReleaseBuffer();
				}
				ppf->Release();
			}
			psl->Release();
		}

		return outFile;
	}

	void GetDeskIcon(vector<CString>& vIcoNames)
	{
		HWND hDestTop = NULL;
		while (!hDestTop) {
			hDestTop = ::FindWindow(L"progman", TEXT("Program Manager"));
			hDestTop = ::FindWindowEx(hDestTop, 0, L"SHELLDLL_DefView", NULL);
			hDestTop = ::FindWindowEx(hDestTop, 0, L"SysListView32", NULL);
		}

		int count = (int)::SendMessage(hDestTop, LVM_GETITEMCOUNT, 0, 0);

		LVITEM64 lvi, *_lvi;
		wchar_t item[512], subitem[512];
		wchar_t *_item, *_subitem;
		unsigned long pid;
		HANDLE process;

		GetWindowThreadProcessId(hDestTop, &pid);
		process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, FALSE, pid);

		_lvi = (LVITEM64*)VirtualAllocEx(process, NULL, sizeof(LVITEM64), MEM_COMMIT, PAGE_READWRITE);
		_item = (wchar_t*)VirtualAllocEx(process, NULL, 512 * sizeof(wchar_t), MEM_COMMIT, PAGE_READWRITE);
		_subitem = (wchar_t*)VirtualAllocEx(process, NULL, 512 * sizeof(wchar_t), MEM_COMMIT, PAGE_READWRITE);

		RECT  rc;
		rc.left = LVIR_ICON;  //这个一定要设定 可以去看MSDN关于LVM_GETITEMRECT的说明  
		RECT* _rc = (RECT*)VirtualAllocEx(process, NULL, sizeof(RECT), MEM_COMMIT, PAGE_READWRITE);

		lvi.cchTextMax = 512;

		for (int i = 0; i< count; i++) {
			lvi.iSubItem = 0;
			lvi.pszText = (_int64)_item;
			WriteProcessMemory(process, _lvi, &lvi, sizeof(LVITEM64), NULL);
			::SendMessage(hDestTop, LVM_GETITEMTEXT, (WPARAM)i, (LPARAM)_lvi);

			lvi.iSubItem = 1;
			lvi.pszText = (_int64)_subitem;
			WriteProcessMemory(process, _lvi, &lvi, sizeof(LVITEM64), NULL);
			::SendMessage(hDestTop, LVM_GETITEMTEXT, (WPARAM)i, (LPARAM)_lvi);

			::WriteProcessMemory(process, _rc, &rc, sizeof(rc), NULL);
			::SendMessage(hDestTop, LVM_GETITEMRECT, (WPARAM)i, (LPARAM)_rc);

			ReadProcessMemory(process, _item, item, 512 * sizeof(wchar_t), NULL);
			ReadProcessMemory(process, _subitem, subitem, 512 * sizeof(wchar_t), NULL);

			ReadProcessMemory(process, _rc, &rc, sizeof(rc), NULL);
			vIcoNames.push_back(item);
		}

		VirtualFreeEx(process, _lvi, 0, MEM_RELEASE);
		VirtualFreeEx(process, _item, 0, MEM_RELEASE);
		VirtualFreeEx(process, _subitem, 0, MEM_RELEASE);
		VirtualFreeEx(process, _rc, 0, MEM_RELEASE);

		CloseHandle(process);
	}

	void GetScreenShot(CString strSavePath)
	{
		HDC hdcSrc = GetDC(NULL);
		int nBitPerPixel = GetDeviceCaps(hdcSrc, BITSPIXEL);
		int nWidth = GetDeviceCaps(hdcSrc, HORZRES);
		int nHeight = GetDeviceCaps(hdcSrc, VERTRES);
		CImage image;
		image.Create(nWidth, nHeight, nBitPerPixel);
		BitBlt(image.GetDC(), 0, 0, nWidth, nHeight, hdcSrc, 0, 0, SRCCOPY);
		ReleaseDC(NULL, hdcSrc);
		image.ReleaseDC();
		image.Save(strSavePath, Gdiplus::ImageFormatPNG);//ImageFormatJPEG
	}

	bool ChangeLinkIcon(const CString &strLnkName, const CString &strIconPath)
	{
		if (strLnkName.IsEmpty() || strIconPath.IsEmpty())
		{
			return false;
		}

		HRESULT hres;
		IShellLink *psl = NULL;
		IPersistFile *pPf = NULL;
		int id;
		LPITEMIDLIST pidl;
		bool bRet = false;

		do
		{
			hres = CoInitialize(NULL);
			if (FAILED(hres))
			{
				break;
			}

			hres = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (LPVOID*)&psl);
			if (FAILED(hres))
			{
				break;
			}

			hres = psl->QueryInterface(IID_IPersistFile, (LPVOID*)&pPf);
			if (FAILED(hres))
			{
				break;
			}

			hres = pPf->Load(strLnkName, STGM_READWRITE);
			if (FAILED(hres))
			{
				break;
			}

			hres = psl->SetIconLocation(strIconPath, 0);
			if (FAILED(hres))
			{
				break;
			}

			pPf->Save(strLnkName, TRUE);
			if (FAILED(hres))
			{
				break;
			}

			bRet = true;

		} while (0);

		if (pPf != NULL)
		{
			pPf->Release();
		}

		if (psl != NULL)
		{
			psl->Release();
		}

		CoUninitialize();

		return bRet;
	}

	BOOL Is64BitPorcess(DWORD dwProcessID)
	{
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessID);
		if (hProcess) {
			typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
			LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandleW(L"kernel32"), "IsWow64Process");
			if (NULL != fnIsWow64Process) {
				BOOL bIsWow64 = FALSE;
				fnIsWow64Process(hProcess, &bIsWow64);
				CloseHandle(hProcess);
				if (bIsWow64) {
					return FALSE;
				}
				else {
					return TRUE;
				}
			}
		}

		return FALSE;
	}
};

