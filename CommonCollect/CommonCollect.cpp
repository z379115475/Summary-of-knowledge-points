// CommonCollect.cpp : ����Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include "CommonCollect.h"
#include <iostream>
#include "Utility.h"
#include "json/json.h"
#include "dummyxml.h"
#include "HardInfo.h"
#include "HideProc.h"
#include "HttpHelp.h"
#include "CPUInfo.h"
#include "GPUInfo.h"
#include "md5.h"
#include "Zlib.h"
#include "CxLog.h"
#include "CPUusage.h"
#include "MemLoadDLL.h"
#include "MemStartExe.h"
#include "PebGetCmdLine.h"

#define ADD(x,y) x+y

class mutex
{
	CRITICAL_SECTION cs;
public:
	void lock()     { EnterCriticalSection(&cs); }
	void unlock()   { LeaveCriticalSection(&cs); }
	mutex()         { InitializeCriticalSection(&cs); }
	~mutex()        { DeleteCriticalSection(&cs); }
};

BOOL UtilityExample()
{
	//��������
	//::SetEnvironmentVariable(L"abcdfs", L"aaaaaaa");
	//CString strEnv = CUtility::GetInstance().GetEnvVar(L"abcdfs");	//strEnv:aaaaaaa

	//ɾ���ļ���
	//CUtility::GetInstance().RemoveFolder(L"D:\\test");

	//�����ļ���
	//CUtility::GetInstance().CreateFolder(L"D:\\test");

	//�����ļ���,�����ļ������ļ�
	//CUtility::GetInstance().CopyFolder(L"D:\\test", L"C:\\test1");

	//�����ļ�(��)
	//CUtility::GetInstance().ModifyFileName(L"D:\\test.txt", L"D:\\test\\test1.txt");
	
	//�����ļ���
	//CUtility::GetInstance().FindFile(L"D:\\test\\*.*");

	//�ļ�->�ڴ棬�ڴ�->�ļ�
	/*CString strFile = L"D:\\test.txt";
	CString strMemory;
	CUtility::GetInstance().File2Memory(strFile, strMemory);
	CUtility::GetInstance().Memory2File(strMemory, strFile);*/

	//�ͷ���Դ(�����dll����һ���������봫��HMODULE)
	//CString strFileName = TEXT("D:\\lander.ini");
	//CUtility::GetInstance().ExtractResource(NULL, IDR_INI, TEXT("BIN"), strFileName);

	//�ͷ���Դ���ڴ�
	/*CHAR *pMemDll = NULL;
	DWORD dwSize;
	CUtility::GetInstance().ExtractResource2Memory(NULL, IDR_DLL_32, TEXT("BIN"), &pMemDll, dwSize);
	if (pMemDll) {
		delete 	pMemDll;
		pMemDll = NULL;
	}*/	

	//��·��ת��·��
	//CString strLongPath = L"C:\\Program Files (x86)\\Microsoft ASP.NET\\ASP.NET MVC 4\\eula.rtf";
	//CString strShortPath = CUtility::GetInstance().LongPathToShortPath(strLongPath);

	//�ַ�������
	//CString strFind = L"aaa=bbb ccc=ddd eee=fff";
	//CString strRet;
	//CUtility::GetInstance().GetKeyFormString(strFind, TEXT("ccc"), TEXT(" "), strRet);
	//CUtility::GetInstance().GetSubString(strFind, TEXT("ccc="), TEXT(" "), strRet);	//�ҵ���xxx��xxx֮����ַ���

	//�ָ��ַ���
	/*CString strSplit = L"aaa bbb ccc ddd eee fff";
	vector<CString> vec;
	CUtility::GetInstance().SplitString(strSplit, L" ", vec);*/

	//ini�ļ�����
	/*CString strContent;
	CUtility::GetInstance().SetKeyValue(L"D:\\test.ini", L"head", L"body", L"I`m content");	
	CUtility::GetInstance().GetKeyValue(L"D:\\test.ini", L"head", L"body", strContent);*/

	//��ȡ��ǰģ��·��
	//CString strPath = CUtility::GetInstance().GetCurrentPath(NULL);

	//��ȡ·���������
	//CString strPath = L"C:\\Program Files (x86)\\Common Files\\Intel\\OpenCL\\version.ini";
	//CString strName = CUtility::GetInstance().GetPathLastName(strPath);

	//������֡��ַ���
	//int nNum = CUtility::GetInstance().GetRadomNum(20);
	//CString strRandom = CUtility::GetInstance().GetRadomString(5);

	//�ж�ϵͳλ��
	//BOOL b64 = CUtility::GetInstance().Is64BitOS();

	//�жϽ���λ��
	//BOOL b64 = CUtility::GetInstance().Is64BitPorcess(8888);

	//����Ȩ��
	//CUtility::GetInstance().PromoteProcessPrivileges();	//������ǰ����Ȩ��

	//��ȡtemp��appdataĿ¼
	//CString strTemp =  CUtility::GetInstance().GetPathFormEnvVar(L"temp");
	//CString strAppData = CUtility::GetInstance().GetPathFormEnvVar(L"appdata");

	//���IE����
	//CUtility::GetInstance().DeleteUrlCache();

	//���ܡ�����
	/*CString strOrg = L"mima";
	CString strOut;
	CUtility::GetInstance().Encrypt(strOrg, strOut);
	CUtility::GetInstance().Decryption(strOut, strOrg);*/

	//�ж�Ϊ������
	/*CString strBuf = L"767546546";
	BOOL b = CUtility::GetInstance().IsAllNumber(strBuf);*/

	//�ж��Ƿ��������
	/*CString strBuf = L"7675����46546";
	BOOL b = CUtility::GetInstance().IncludeChinese(CT2A(strBuf.GetBuffer()));*/

	//Base64 ���롢����
	/*CString strBuf = L"Base64����";
	char dest[256] = { 0 };
	CStringA strUtf8 = CT2A(strBuf, CP_UTF8);
	CUtility::GetInstance().Base64_Encode(dest, strUtf8, strUtf8.GetLength());

	char src[256] = { 0 };
	CUtility::GetInstance().Base64_Decode(src, dest, strlen(dest));
	strBuf = CA2T(src, CP_UTF8);*/

	//Զ���߳�ע��dll��������̣���Ҫ��<64λexe>��<64λdll>ע�뵽<64λ������>��
	/*DWORD dwExplorerPid;
	if (!CUtility::GetInstance().GetExplorerProcessId(dwExplorerPid)) {
		return FALSE;
	}
	CString strDllPath = L"D:\\Notes\\�������\\CommonCollect\\hideDll\\x64\\msvcr32.dll";
	BOOL b = CUtility::GetInstance().InjectThread(dwExplorerPid, strDllPath);*/

	//����д�����ڴ棨���̼�ͨ�ţ�
	/*CString strMsg = L"this is communication information";
	CUtility::GetInstance().WriteSharedMemory(strMsg);
	strMsg.Empty();
	CUtility::GetInstance().ReadSharedMemory(strMsg);*/

	//���������ݷ�ʽ
	//CUtility::GetInstance().Createlnk(L"\\proCheck.lnk",L"D:\\software\\pro111.exe");

	//���ݽ�������(Сд)��ȡ����ID,(ID -> ���)��(��� -> ȫ·��)��(ȫ·�� -> �����ļ���С)
	//DWORD strProID = CUtility::GetInstance().GetProcessIdByName(L"everything.exe");

	//��ȡGUID
	//CString strName;
	//CUtility::GetInstance().GetGUID(strName);

	return TRUE;
}

BOOL StringExample()
{
	//�������д������
	//_cwprintf(L"%s\n", str);

	//INTתʮ������
	/*int nOrg = 4096;
	char ch[16];
	_itoa_s(nOrg, ch, 16);*/

	//ʮ�������ַ���תINT
	/*char chSixteen[16] = "1000";	
	int nInt = strtol(chSixteen, NULL, 16);*/

	//�ַ�������
	//char buf[32] = "abcdefg";
	//CHAR* ret = strstr(buf, "de");	//ret = "defg"

	//wchar_t w_buf[32] = L"abcdefg";
	//wchar_t* w_ret = _tcsstr(w_buf, L"de");	//w_ret = L"defg"����һ�γ��ֵ�λ��

	//TCHAR* buffer = L"abc def gh";
	//const TCHAR* pszPos = _tcsrchr(buffer, TEXT(' '));	//pszPos = L"gh"�����һ�γ��ֵ�λ��

	//�ַ���ƴ��
	//wchar_t w_buf[32] = L"abcdefg";
	//wcscat_s(w_buf, L"higkefj");	// w_buf = L"abcdefghigkefj"

	//�ַ�����ֵ
	/*TCHAR szOrg[1024] = { 0 };
	CString strTemp = L"abc";
	_sntprintf_s(szOrg, 1024, _TRUNCATE, TEXT("123%s_%s"), strTemp, strTemp);*/

	//�ַ�������
	/*TCHAR szOrg[32] = { 0 };
	TCHAR szSrc[16] = L"abcdefghigkefj";
	_tcscpy_s(szOrg, 32, szSrc);*/

	//INTתTCHAR
	/*int nValue = 16;
	TCHAR buffer[32] = { 0 };
	_itot_s(nValue, buffer, 3, 10);*/

	//����
	/*TCHAR* buffer = L"abc";
	int nLen = _tcslen(buffer);*/

	//�Ƚ�
	//TCHAR* buffer1 = L"abc";
	//TCHAR* buffer2 = L"abc";
	//int nRet = _tcsicmp(buffer1, buffer2);	//0��ͬ >0ǰ��� <0�����

	return TRUE;
}

std::string JsonToString(Json::Value jvSrc)
{
	Json::StyledWriter fw;
	std::string strRet = fw.write(jvSrc);

	return strRet;
}

Json::Value StringToJson(std::string strSrc)
{
	Json::Value root;
	Json::Reader reader;
	reader.parse(strSrc, root);

	return root;
}

BOOL JsonExample()
{
	//��������json�ṹ��
	/*{
		"���ڵ�1" : 1,
		"���ڵ�2" : "�ַ���",
		"���ڵ�3-����" : [
			{
				"����ڵ�1" : "�ַ���1",
				"����ڵ�2" : "�ַ���2"
			},
			{
				"����ڵ�1" : "�ַ���3",
				"����ڵ�2" : "�ַ���4"
			}
		]
	}*/

	//Json::Value jvRoot;
	//jvRoot["���ڵ�1"] = 1;
	//jvRoot["���ڵ�2"] = "�ַ���";

	//Json::Value item1;
	//item1["����ڵ�1"] = "�ַ���1";
	//item1["����ڵ�2"] = "�ַ���2";
	//Json::Value item2;
	//item2["����ڵ�1"] = "�ַ���3";
	//item2["����ڵ�2"] = "�ַ���4";

	//Json::Value list;
	//list.append(item1);
	//list.append(item2);

	//jvRoot["���ڵ�3-����"] = list;

	////����json
	//int nNum = jvRoot["���ڵ�1"].asInt();
	//CString str = CA2T(jvRoot["���ڵ�2"].asString().c_str());
	//for (int i = 0; i < jvRoot["���ڵ�3-����"].size(); i++)
	//{
	//	CString strTemp1 = CA2T(jvRoot["���ڵ�3-����"][i]["����ڵ�1"].asString().c_str());
	//	CString strTemp2 = CA2T(jvRoot["���ڵ�3-����"][i]["����ڵ�2"].asString().c_str());
	//}

	return TRUE;
}

BOOL XmlExample()
{
	/*
	<?xml version="1.0" encoding="UTF-8"?>
	<root>
		<user>
			<id>1058</id>
			<name>z379115475</name>
			<type>0</type>
		</user>
		<config>
			<run>yes</run>
			<delayed>0</delayed>
			<delproj list="111"/>
		</config>
		<projlist>
			<item>
				<name>kjt</name>
				<id>17</id>
				<key>400387</key>
			</item>
			<item>
				<name>qt</name>
				<id>23</id>
				<key>400626</key>
			</item>
		</projlist>
		<datetime>2016-10-08 17:08:45</datetime>
	</root>
	*/
	//CString strXml = L"..\\res\\test.xml";

	//CDummyXml pXMLDoc;
	//_S_OK(pXMLDoc.LoadFile(strXml));

	//CXmlNode* pRootNode = pXMLDoc.Parse();
	//_S_OK(pRootNode);
	//
	////����config�ڵ�
	//CXmlNode* pConfigNode = pRootNode->GetSubNode(TEXT("config"));
	//_S_OK(pConfigNode);

	//CString strRun, strList;
	//pConfigNode->GetSubNode(TEXT("run"))->GetText(strRun);
	//pConfigNode->GetSubNode(TEXT("delproj"))->GetProperty(TEXT("list"), strList);

	////����projlist�ڵ�
	//CXmlNode* pProjNode = pRootNode->GetSubNode(TEXT("projlist"));
	//_S_OK(pProjNode);

	//for (size_t i = 0; i < pProjNode->GetSubNodeCount(); i++) {
	//	CString strName;
	//	CXmlNode* pSub = pProjNode->GetSubNode(i);
	//	pSub->GetSubNode(TEXT("name"))->GetText(strName);
	//}

	return TRUE;
}

BOOL HardInfoExample()
{
	//CString strMac = CHardInfo::GetInstance().GetMac();
	//CString strSys = CHardInfo::GetInstance().GetSysInfo();	//win7_64

	//CCPUInfo cpuinfo;
	//CString strCpuName = cpuinfo.GetCPUName();
	//int strCpuNum = cpuinfo.GetCPUNumbers();
	//int strCpuThreads = cpuinfo.GetCPUThreads();

	//DWORD strCpuUseRate;
	////cpuinfo.Initialize();	 ���ֻ��ȡһ�Σ�����Ҫ��ʼ��һ�£�ѭ����ȡ���ó�ʼ��
	//while (true) {		
	//	strCpuUseRate = cpuinfo.GetCPUUseRate();
	//	Sleep(500);
	//}

	/*��ȡ������Ϣ
	DWORD dwNum;
	CString strName;
	CNvGPUInfo::GetInstance().GetIntegratedGraphicsInfo(dwNum, strName);*/

	return TRUE;
}

BOOL RegeditExample()
{
	//CRegKey rk;
	//if (rk.Open(HKEY_CURRENT_USER, _T("Software\\360Chrome\\Chrome")) != ERROR_SUCCESS) {	//����
	//	//rk.Create(HKEY_CURRENT_USER, _T("Software\\360Chrome\\Chrome"));	//�½���
	//	//rk.DeleteSubKey(_T("111"));	//ɾ��ĳ�������111
	//	//rk.EnumKey(i, keyName, &dLen);	//����ĳ�����������
	//	return FALSE;
	//}
	//
	//DWORD dValue;
	//rk.QueryValue(dValue, L"LastPages");	//��ȡ��������ĳ����ֵ(REG_DWORD)

	//TCHAR szPath[MAX_PATH];
	//DWORD dLen = MAX_PATH;
	//rk.QueryValue(szPath, L"gpulv", &dLen);	//��ȡ��������ĳ����ֵ(REG_SZ)

	//rk.SetValue(100, L"new_dword");	//���(�޸�)ĳ��ֵ(REG_DWORD)
	//rk.SetValue(L"new", L"new_sz");	//���(�޸�)ĳ��ֵ(REG_SZ)

	//rk.DeleteValue(L"new_dword");	//ɾ��ĳ��
	//rk.DeleteValue(L"new_sz");

	////����ĳ���������м�ֵ
	//int i = 0;
	//TCHAR keyName[MAX_PATH], val[MAX_PATH];
	//DWORD nKeyNameLen, nValLen;
	//while (true)
	//{
	//	nKeyNameLen = nValLen = sizeof(keyName) / sizeof(char);
	//	if (RegEnumValue(rk, i, keyName, &nKeyNameLen, NULL, NULL, (PUCHAR)val, &nValLen) != ERROR_SUCCESS) {
	//		break;
	//	}
	//	i++;
	//}

	//rk.Close();

	return TRUE;
}

BOOL Md5Example()
{
	/*TCHAR szMd5[33] = { 0 };
	CMd5::GetFileMd5(L"D:\\test.txt", szMd5);

	CString strMd5 = CMd5::GetStringMd5(L"1234567890abc");

	BOOL b = CMd5::CheckFileMd5(L"D:\\test.txt", szMd5);*/

	return TRUE;
}

BOOL UnzipExample()
{
	/*if (!CZlib::GetInstance().Zip_UnPackFiles(L"D:\\test.zip", L"D:\\")) {
		return FALSE;
	}*/

	return TRUE;
}

BOOL HideExample()
{
	//***(64λϵͳ):������(64λexe)����(64λdll)��������64/32λ���̣�32λͬ��***

	// ��װ����ģ��
	//CString strDllPath = L"D:\\Notes\\�������\\CommonCollect\\hideDll\\x64";
	//if (!CHideProcServer::GetInstance().LoadHideModule(strDllPath)) {
	//	return FALSE;
	//}

	//// ���ؽ���
	//PID_TOKE pt;
	//pt.pid = 1152;
	//pt.toke = TEXT("CommonCollect");
	//if (!CHideProcServer::GetInstance().HideProcess(pt)) {
	//	return FALSE;
	//}

	//// ���������ļ���
	//if (!CHideProcServer::GetInstance().HideFolder(L"D:\\apks")) {
	//	return FALSE;
	//}

	return TRUE;
}

BOOL HttpExample()
{
	//�����ļ�
	//CString strUrl = L"http://domain.52wblm.com/XtTow/Client/BackEnd.ini";
	//CString szRand;
	//szRand.Format(_T("?skq=%d"), GetTickCount());
	//strUrl += szRand;	//���߻���
	//CHttpHelp::GetInstance().FromUrlToFile(strUrl, L"D:\\BackEnd.ini");

	//��������״̬
	/*if (!CHttpHelp::GetInstance().TestNetStatus()) {
		return FALSE;
	}*/

	//��ȡ����ip
	/*CString strIp;
	CHttpHelp::GetInstance().GetWANIP(strIp);*/

	//Http Get ����(Ҳ������������URL�ļ�)
	/*CString strHost = TONGJI_URL;
	CString strUrl = TEXT("/eda/cpuConfig?u=shanshan");
	CString strOutUrl;
	CHttpHelp::GetInstance().GetReq(strHost, strUrl, strOutUrl);*/
	
	//Https Post ����Ҳ������Http Post�����ǲ���Https��ȫ��
	/*CString strHost = TONGJI_URL;
	CString strUrl = TEXT("/eda/address");
	CString body;
	body.Format(TEXT("type=cpu&version=cpu1.0&user=shanshan&son=shanshan&pw=%s&osbit=64&client=1.0"), CMd5::GetSignature(TEXT("getEdaAddress.awangba.com")));
	CString strOutUrl;
	CHttpHelp::GetInstance().PostReq(strUrl, body, strOutUrl, strHost);*/

	return TRUE;
}

BOOL LogExample()
{
	//�ڵ�ǰ��������Ŀ¼������־�ļ�
	//LOG1(TEXT("��ӡ��־_%s"), L"NORMAL");
	//LOG_T1(CxLog::EnumType::CX_LOG_MESSAGE, TEXT("��ӡ��־_%s"), L"T");
	//LOG_WARN1(TEXT("��ӡ��־_%s"), L"WARN");
	//LOG_EXCEPTION1(TEXT("��ӡ��־_%s"), L"EXCEPTION");
	//LOG_ERR1(TEXT("��ӡ��־_%s"), L"ERR");
	//LOG_LAST_ERROR();	//��ӡ"�����ɹ����"

	return TRUE;
}

BOOL CALLBACK EnumChildProc(HWND hWnd, LPARAM lParam)
{
	CString strBuf;
	::GetWindowText(hWnd, strBuf.GetBuffer(256), 255);
	strBuf.ReleaseBuffer();
	OutputDebugString(strBuf);
	if (strBuf.Find(_T("��(&Y)")) != -1) {	//�����ť"��"
		//������button
		::PostMessage(hWnd, WM_LBUTTONDOWN, 0, 0);
		Sleep(10);
		::PostMessage(hWnd, WM_LBUTTONUP, 0, 0);

		return FALSE;
	}

	return TRUE;
}

UINT WINAPI WorkTreadex(LPVOID lpParameter)
{
	int pos = 0;
	while (true)
	{
		Sleep(200);

		HWND hWnd = FindWindow(_T("#32770"), _T("ɾ���ļ�"));	//������������������
		if (hWnd) {
			::EnumChildWindows(hWnd, EnumChildProc, NULL);
			break;
		}

		pos++;
		if (pos == 300) { 	//1����
			break;
		}
	}

	return 0;
}

BOOL FindKey(CString strBuf, CString strKey)
{
	int nPos = strBuf.Find(strKey);

	return nPos >= 0 ? TRUE : FALSE;
}

BOOL CALLBACK EnumChildProc1(HWND hWnd, LPARAM lParam)
{
	CString strBuf;
	::GetWindowText(hWnd, strBuf.GetBuffer(256), 255);
	strBuf.ReleaseBuffer();

	if (FindKey(strBuf, L"���ؽ���") && FindKey(strBuf, L"Ӧ�ò㲻�ɷ��ʽ���")) {
		return TRUE;
	}

	return TRUE;
}

BOOL CALLBACK EnumWindowsProc(HWND hwnd/*��ǰ�ҵ��Ĵ��ھ��*/, LPARAM lParam/*�Զ������*/)
{
	TCHAR tcClass[256];
	::GetClassName(hwnd, tcClass, 255);

	CString strClassName = tcClass;
	if (strClassName == L"#32770") {	//����ǶԻ��򣬼��������Ӵ��ڣ��ж��Ƿ�pcHunter
		::EnumChildWindows(hwnd, EnumChildProc1, NULL);
	}

	if (strClassName == L"PROCEXPL") {	//procexp
		return TRUE;
	}

	return TRUE;
}

BOOL FindWindowExample()
{
	//��ʾ��Ϊģ����ɾ�������ļ��������е�"��"��ť
	//_beginthreadex(NULL, NULL, WorkTreadex, NULL, 0, NULL);

	//�������д���
	//::EnumWindows((WNDENUMPROC)EnumWindowsProc, NULL);

	return TRUE;
}

BOOL WinHexExample()
{
	//����winHex�����test.xmlת��Ϊ16��������
	//�����鱣����testXml.cpp��
	//Ȼ�󽫴���������д�뵽�������ɻ�ԭ�ļ�
	//CUtility::GetInstance().MemoryToFile(L"D:\\test.xml", testXml, 455);

	return TRUE;
}

BOOL ProExample()
{
	struct LANGANDCODEPAGE {
		WORD wLanguage;
		WORD wCodePage;
	} *lpTranslate;

	HANDLE procSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (procSnap == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	PROCESSENTRY32 procEntry = { 0 };

	procEntry.dwSize = sizeof(PROCESSENTRY32);
	BOOL bRet = Process32First(procSnap, &procEntry);

	while (bRet) {
		// �������������ʱ
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, procEntry.th32ProcessID);
		if (hProcess) {
			std::wstring strFile;
			CUtility::GetInstance().GetProcessFilePath(hProcess, strFile);	//���ݽ���ID��ȡ����Ŀ���ļ�·��
			CString strFilePath = strFile.c_str();

			DWORD dwSize = 0;
			UINT uSize = GetFileVersionInfoSize(strFilePath, &dwSize);
			if (uSize == 0)	return 0;

			PTSTR pBuffer = new TCHAR[uSize];
			if (!pBuffer)	return 0;

			memset((void*)pBuffer, 0, uSize);
			if (!GetFileVersionInfo(strFilePath, 0, uSize, (PVOID)pBuffer))	return 0;

			if (!VerQueryValue(pBuffer, L"\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &uSize))	return 0;

			CString strTemp;
			strTemp.Format(L"\\StringFileInfo\\%04x%04x\\CompanyName", lpTranslate[0].wLanguage, lpTranslate[0].wCodePage);
			/*CompanyName���������Ϳ��Ի�ȡ�������ԣ��磺
			FileVersion��Comments��InternalName��ProductName��LegalCopyright��ProductVersion��FileDescription��
			LegalTrademarks��PrivateBuild��OriginalFileName��SpecialBuild*/

			LPWSTR pCompany = NULL;
			if (!VerQueryValueW(pBuffer, strTemp.GetBuffer(), (LPVOID*)&pCompany, &uSize))	return 0;

			CString strCompany = pCompany;
			delete[]pBuffer;

			int nPos = strCompany.Find(L"һ����Ϊ");
		}
		bRet = Process32Next(procSnap, &procEntry);
	}
	CloseHandle(procSnap);

	return TRUE;
}

void ProUsage()
{
	//��ȡ����CPUʹ����
	/*int nProId = 8888;
	CString strCpuUsage;

	CPUusage usg(nProId);
	while (true)
	{
		float cpu = usg.get_cpu_usage();
		int nUsage = (int)cpu;

		if (nUsage != -2) {
			strCpuUsage.Format(L"%.2f%%", cpu);
			break;
		}
		Sleep(500);
	}*/

	//��ȡ���̱�ע���DLL
	/*std::vector<CString> vDLLNames;
	CUtility::GetInstance().GetProcessDll(8888, vDLLNames);*/
}

typedef BOOL(__stdcall* fSandBox)(LPTSTR lpCmd);
void MemLoadDll()
{
	/*CHAR *pMemDll = NULL;
	DWORD dwSize;
	CUtility::GetInstance().ExtractResource2Memory(NULL, IDR_DLL_32, TEXT("BIN"), &pMemDll, dwSize);   //�ڴ����32λdll
	//CUtility::GetInstance().ExtractResource2Memory(NULL, IDR_DLL_64, TEXT("BIN"), &pMemDll, dwSize); //�ڴ����64λdll

	LOAD_DLL_INFO* p = new LOAD_DLL_INFO;
	DWORD res = LoadDLLFromMemory(pMemDll, dwSize, 0, p);
	if (res != ELoadDLLResult_OK) {
		delete p;
		delete pMemDll;
		return ;
	}

	fSandBox func = (fSandBox)myGetProcAddress_LoadDLLInfo(p, "SandBox");
	if (!func) {
		return;
	}

	func(L"123456");

	Sleep(60 * 1000);*/
}

void MemStartExe()
{
	//FILE *  fp;
	//fp = fopen("..\\res\\test32.exe", " rb ");

	//if (!fp) return;

	//fseek(fp, 0l, SEEK_END);
	//int  file_size = ftell(fp); /* ��ȡ�ļ����� */
	//fseek(fp, 0l, SEEK_SET); /* �ص��ļ�ͷ�� */


	//CHAR* pBuf = new  CHAR[file_size];
	//memset(pBuf, 0, file_size);

	//fread(pBuf, file_size, 1, fp);

	//unsigned  long  ulProcessId = 0;
	//char *cmdLine = " 111 222 333";
	//HANDLE handle = MemExecu(pBuf, file_size, cmdLine, &ulProcessId);
	//MemStop(handle);

	//delete[] pBuf;
}

void GetCmdLine()
{
	//�Ե�ǰ���̺�Ŀ�����λ����Ҫ��32��64������
	//CString strCmdLine;
	//GetPebCommandLine(10060, strCmdLine);

	return;
}

void ExplorerExample()
{
	//��ȡ�����ͼPNG
	//CUtility::GetInstance().GetScreenShot(L"D:\\screen.png");

	//��ȡ��ǰ�û�����Ŀ¼�͹���Ŀ¼
	//CString strUserDesk, strCommonDesk;
	//CUtility::GetInstance().GetDeskPath(strUserDesk, strCommonDesk);

	//��ȡ��ݷ�ʽ��Ŀ��·��
	//CString strTargetPath = CUtility::GetInstance().ExpandShortcut(L"C:\\Users\\Administrator\\Desktop\\Postman.lnk");

	//��ȡ��������ͼ������ּ�λ�õ���Ϣ����ȡ����Ҳ�����÷���GetDeskPath��ʵ�֣�
	//vector<CString> vIcoNames;
	//CUtility::GetInstance().GetDeskIcon(vIcoNames);

	//������ݷ�ʽͼ��
	//CUtility::GetInstance().ChangeLinkIcon(L"C:\\Users\\Administrator\\Desktop\\test32.exe.lnk", L"D:\\favicon.ico");

	return;
}

int APIENTRY _tWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPTSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
	//Utility.h
	UtilityExample();

	//�ַ������,C�ӿ�
	StringExample();

	//json��ز���
	JsonExample();

	//xml����
	XmlExample();

	//��ȡpc��Ϣ
	HardInfoExample();

	//ע������
	RegeditExample();

	//md5��ز���
	Md5Example();

	//��ѹ��ز���
	UnzipExample();

	//���ؽ��̡������ļ�
	HideExample();

	//HTTP��HTTPS����
	HttpExample();

	//��־ģ��
	LogExample();

	//��ش���,����ָ�����ڲ�������а�ť
	FindWindowExample();

	//�ͷ�ʮ�������ļ�
	WinHexExample();

	//���̱�����ز���
	ProExample();

	//�ڴ����DLL��32��64��
	MemLoadDll();

	//�ڴ�����EXE��32��
	MemStartExe();

	//����PEB������ȡ������������
	GetCmdLine();

	//��ȡ���漰����ͼ�ꡢ�����ݷ�ʽ�����Ϣ
	ExplorerExample();

	return 0;
}