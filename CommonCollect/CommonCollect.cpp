// CommonCollect.cpp : 定义应用程序的入口点。
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
	//环境变量
	//::SetEnvironmentVariable(L"abcdfs", L"aaaaaaa");
	//CString strEnv = CUtility::GetInstance().GetEnvVar(L"abcdfs");	//strEnv:aaaaaaa

	//删除文件夹
	//CUtility::GetInstance().RemoveFolder(L"D:\\test");

	//创建文件夹
	//CUtility::GetInstance().CreateFolder(L"D:\\test");

	//拷贝文件夹,包括文件夹内文件
	//CUtility::GetInstance().CopyFolder(L"D:\\test", L"C:\\test1");

	//改名文件(夹)
	//CUtility::GetInstance().ModifyFileName(L"D:\\test.txt", L"D:\\test\\test1.txt");
	
	//遍历文件夹
	//CUtility::GetInstance().FindFile(L"D:\\test\\*.*");

	//文件->内存，内存->文件
	/*CString strFile = L"D:\\test.txt";
	CString strMemory;
	CUtility::GetInstance().File2Memory(strFile, strMemory);
	CUtility::GetInstance().Memory2File(strMemory, strFile);*/

	//释放资源(如果是dll，第一个参数必须传入HMODULE)
	//CString strFileName = TEXT("D:\\lander.ini");
	//CUtility::GetInstance().ExtractResource(NULL, IDR_INI, TEXT("BIN"), strFileName);

	//释放资源到内存
	/*CHAR *pMemDll = NULL;
	DWORD dwSize;
	CUtility::GetInstance().ExtractResource2Memory(NULL, IDR_DLL_32, TEXT("BIN"), &pMemDll, dwSize);
	if (pMemDll) {
		delete 	pMemDll;
		pMemDll = NULL;
	}*/	

	//长路径转短路径
	//CString strLongPath = L"C:\\Program Files (x86)\\Microsoft ASP.NET\\ASP.NET MVC 4\\eula.rtf";
	//CString strShortPath = CUtility::GetInstance().LongPathToShortPath(strLongPath);

	//字符串查找
	//CString strFind = L"aaa=bbb ccc=ddd eee=fff";
	//CString strRet;
	//CUtility::GetInstance().GetKeyFormString(strFind, TEXT("ccc"), TEXT(" "), strRet);
	//CUtility::GetInstance().GetSubString(strFind, TEXT("ccc="), TEXT(" "), strRet);	//找到从xxx到xxx之间的字符串

	//分割字符串
	/*CString strSplit = L"aaa bbb ccc ddd eee fff";
	vector<CString> vec;
	CUtility::GetInstance().SplitString(strSplit, L" ", vec);*/

	//ini文件操作
	/*CString strContent;
	CUtility::GetInstance().SetKeyValue(L"D:\\test.ini", L"head", L"body", L"I`m content");	
	CUtility::GetInstance().GetKeyValue(L"D:\\test.ini", L"head", L"body", strContent);*/

	//获取当前模块路径
	//CString strPath = CUtility::GetInstance().GetCurrentPath(NULL);

	//获取路径最后名字
	//CString strPath = L"C:\\Program Files (x86)\\Common Files\\Intel\\OpenCL\\version.ini";
	//CString strName = CUtility::GetInstance().GetPathLastName(strPath);

	//随机数字、字符串
	//int nNum = CUtility::GetInstance().GetRadomNum(20);
	//CString strRandom = CUtility::GetInstance().GetRadomString(5);

	//判断系统位数
	//BOOL b64 = CUtility::GetInstance().Is64BitOS();

	//判断进程位数
	//BOOL b64 = CUtility::GetInstance().Is64BitPorcess(8888);

	//进程权限
	//CUtility::GetInstance().PromoteProcessPrivileges();	//提升当前进程权限

	//获取temp、appdata目录
	//CString strTemp =  CUtility::GetInstance().GetPathFormEnvVar(L"temp");
	//CString strAppData = CUtility::GetInstance().GetPathFormEnvVar(L"appdata");

	//清楚IE缓存
	//CUtility::GetInstance().DeleteUrlCache();

	//加密、解密
	/*CString strOrg = L"mima";
	CString strOut;
	CUtility::GetInstance().Encrypt(strOrg, strOut);
	CUtility::GetInstance().Decryption(strOut, strOrg);*/

	//判断为纯数字
	/*CString strBuf = L"767546546";
	BOOL b = CUtility::GetInstance().IsAllNumber(strBuf);*/

	//判断是否包含中文
	/*CString strBuf = L"7675中文46546";
	BOOL b = CUtility::GetInstance().IncludeChinese(CT2A(strBuf.GetBuffer()));*/

	//Base64 编码、解码
	/*CString strBuf = L"Base64编码";
	char dest[256] = { 0 };
	CStringA strUtf8 = CT2A(strBuf, CP_UTF8);
	CUtility::GetInstance().Base64_Encode(dest, strUtf8, strUtf8.GetLength());

	char src[256] = { 0 };
	CUtility::GetInstance().Base64_Decode(src, dest, strlen(dest));
	strBuf = CA2T(src, CP_UTF8);*/

	//远程线程注入dll到桌面进程（需要用<64位exe>将<64位dll>注入到<64位进程中>）
	/*DWORD dwExplorerPid;
	if (!CUtility::GetInstance().GetExplorerProcessId(dwExplorerPid)) {
		return FALSE;
	}
	CString strDllPath = L"D:\\Notes\\工程相关\\CommonCollect\\hideDll\\x64\\msvcr32.dll";
	BOOL b = CUtility::GetInstance().InjectThread(dwExplorerPid, strDllPath);*/

	//读、写共享内存（进程间通信）
	/*CString strMsg = L"this is communication information";
	CUtility::GetInstance().WriteSharedMemory(strMsg);
	strMsg.Empty();
	CUtility::GetInstance().ReadSharedMemory(strMsg);*/

	//创建桌面快捷方式
	//CUtility::GetInstance().Createlnk(L"\\proCheck.lnk",L"D:\\software\\pro111.exe");

	//根据进程名字(小写)获取进程ID,(ID -> 句柄)，(句柄 -> 全路径)，(全路径 -> 进程文件大小)
	//DWORD strProID = CUtility::GetInstance().GetProcessIdByName(L"everything.exe");

	//获取GUID
	//CString strName;
	//CUtility::GetInstance().GetGUID(strName);

	return TRUE;
}

BOOL StringExample()
{
	//在命令行窗口输出
	//_cwprintf(L"%s\n", str);

	//INT转十六进制
	/*int nOrg = 4096;
	char ch[16];
	_itoa_s(nOrg, ch, 16);*/

	//十六进制字符串转INT
	/*char chSixteen[16] = "1000";	
	int nInt = strtol(chSixteen, NULL, 16);*/

	//字符串查找
	//char buf[32] = "abcdefg";
	//CHAR* ret = strstr(buf, "de");	//ret = "defg"

	//wchar_t w_buf[32] = L"abcdefg";
	//wchar_t* w_ret = _tcsstr(w_buf, L"de");	//w_ret = L"defg"，第一次出现的位置

	//TCHAR* buffer = L"abc def gh";
	//const TCHAR* pszPos = _tcsrchr(buffer, TEXT(' '));	//pszPos = L"gh"，最后一次出现的位置

	//字符串拼接
	//wchar_t w_buf[32] = L"abcdefg";
	//wcscat_s(w_buf, L"higkefj");	// w_buf = L"abcdefghigkefj"

	//字符串赋值
	/*TCHAR szOrg[1024] = { 0 };
	CString strTemp = L"abc";
	_sntprintf_s(szOrg, 1024, _TRUNCATE, TEXT("123%s_%s"), strTemp, strTemp);*/

	//字符串拷贝
	/*TCHAR szOrg[32] = { 0 };
	TCHAR szSrc[16] = L"abcdefghigkefj";
	_tcscpy_s(szOrg, 32, szSrc);*/

	//INT转TCHAR
	/*int nValue = 16;
	TCHAR buffer[32] = { 0 };
	_itot_s(nValue, buffer, 3, 10);*/

	//长度
	/*TCHAR* buffer = L"abc";
	int nLen = _tcslen(buffer);*/

	//比较
	//TCHAR* buffer1 = L"abc";
	//TCHAR* buffer2 = L"abc";
	//int nRet = _tcsicmp(buffer1, buffer2);	//0相同 >0前面大 <0后面大

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
	//构建如下json结构：
	/*{
		"根节点1" : 1,
		"根节点2" : "字符串",
		"根节点3-数组" : [
			{
				"数组节点1" : "字符串1",
				"数组节点2" : "字符串2"
			},
			{
				"数组节点1" : "字符串3",
				"数组节点2" : "字符串4"
			}
		]
	}*/

	//Json::Value jvRoot;
	//jvRoot["根节点1"] = 1;
	//jvRoot["根节点2"] = "字符串";

	//Json::Value item1;
	//item1["数组节点1"] = "字符串1";
	//item1["数组节点2"] = "字符串2";
	//Json::Value item2;
	//item2["数组节点1"] = "字符串3";
	//item2["数组节点2"] = "字符串4";

	//Json::Value list;
	//list.append(item1);
	//list.append(item2);

	//jvRoot["根节点3-数组"] = list;

	////解析json
	//int nNum = jvRoot["根节点1"].asInt();
	//CString str = CA2T(jvRoot["根节点2"].asString().c_str());
	//for (int i = 0; i < jvRoot["根节点3-数组"].size(); i++)
	//{
	//	CString strTemp1 = CA2T(jvRoot["根节点3-数组"][i]["数组节点1"].asString().c_str());
	//	CString strTemp2 = CA2T(jvRoot["根节点3-数组"][i]["数组节点2"].asString().c_str());
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
	////解析config节点
	//CXmlNode* pConfigNode = pRootNode->GetSubNode(TEXT("config"));
	//_S_OK(pConfigNode);

	//CString strRun, strList;
	//pConfigNode->GetSubNode(TEXT("run"))->GetText(strRun);
	//pConfigNode->GetSubNode(TEXT("delproj"))->GetProperty(TEXT("list"), strList);

	////解析projlist节点
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
	////cpuinfo.Initialize();	 如果只获取一次，则需要初始化一下，循环获取则不用初始化
	//while (true) {		
	//	strCpuUseRate = cpuinfo.GetCPUUseRate();
	//	Sleep(500);
	//}

	/*获取集显信息
	DWORD dwNum;
	CString strName;
	CNvGPUInfo::GetInstance().GetIntegratedGraphicsInfo(dwNum, strName);*/

	return TRUE;
}

BOOL RegeditExample()
{
	//CRegKey rk;
	//if (rk.Open(HKEY_CURRENT_USER, _T("Software\\360Chrome\\Chrome")) != ERROR_SUCCESS) {	//打开项
	//	//rk.Create(HKEY_CURRENT_USER, _T("Software\\360Chrome\\Chrome"));	//新建项
	//	//rk.DeleteSubKey(_T("111"));	//删除某项的子项111
	//	//rk.EnumKey(i, keyName, &dLen);	//遍历某项的所有子项
	//	return FALSE;
	//}
	//
	//DWORD dValue;
	//rk.QueryValue(dValue, L"LastPages");	//获取该项下面某个键值(REG_DWORD)

	//TCHAR szPath[MAX_PATH];
	//DWORD dLen = MAX_PATH;
	//rk.QueryValue(szPath, L"gpulv", &dLen);	//获取该项下面某个键值(REG_SZ)

	//rk.SetValue(100, L"new_dword");	//添加(修改)某键值(REG_DWORD)
	//rk.SetValue(L"new", L"new_sz");	//添加(修改)某键值(REG_SZ)

	//rk.DeleteValue(L"new_dword");	//删除某键
	//rk.DeleteValue(L"new_sz");

	////遍历某项下面所有键值
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
	//***(64位系统):必须用(64位exe)加载(64位dll)才能隐藏64/32位进程，32位同理***

	// 安装隐藏模块
	//CString strDllPath = L"D:\\Notes\\工程相关\\CommonCollect\\hideDll\\x64";
	//if (!CHideProcServer::GetInstance().LoadHideModule(strDllPath)) {
	//	return FALSE;
	//}

	//// 隐藏进程
	//PID_TOKE pt;
	//pt.pid = 1152;
	//pt.toke = TEXT("CommonCollect");
	//if (!CHideProcServer::GetInstance().HideProcess(pt)) {
	//	return FALSE;
	//}

	//// 隐藏下载文件夹
	//if (!CHideProcServer::GetInstance().HideFolder(L"D:\\apks")) {
	//	return FALSE;
	//}

	return TRUE;
}

BOOL HttpExample()
{
	//下载文件
	//CString strUrl = L"http://domain.52wblm.com/XtTow/Client/BackEnd.ini";
	//CString szRand;
	//szRand.Format(_T("?skq=%d"), GetTickCount());
	//strUrl += szRand;	//不走缓存
	//CHttpHelp::GetInstance().FromUrlToFile(strUrl, L"D:\\BackEnd.ini");

	//测试网络状态
	/*if (!CHttpHelp::GetInstance().TestNetStatus()) {
		return FALSE;
	}*/

	//获取外网ip
	/*CString strIp;
	CHttpHelp::GetInstance().GetWANIP(strIp);*/

	//Http Get 请求(也可以用来下载URL文件)
	/*CString strHost = TONGJI_URL;
	CString strUrl = TEXT("/eda/cpuConfig?u=shanshan");
	CString strOutUrl;
	CHttpHelp::GetInstance().GetReq(strHost, strUrl, strOutUrl);*/
	
	//Https Post 请求（也可以用Http Post，但是不如Https安全）
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
	//在当前进程所在目录生成日志文件
	//LOG1(TEXT("打印日志_%s"), L"NORMAL");
	//LOG_T1(CxLog::EnumType::CX_LOG_MESSAGE, TEXT("打印日志_%s"), L"T");
	//LOG_WARN1(TEXT("打印日志_%s"), L"WARN");
	//LOG_EXCEPTION1(TEXT("打印日志_%s"), L"EXCEPTION");
	//LOG_ERR1(TEXT("打印日志_%s"), L"ERR");
	//LOG_LAST_ERROR();	//打印"操作成功完成"

	return TRUE;
}

BOOL CALLBACK EnumChildProc(HWND hWnd, LPARAM lParam)
{
	CString strBuf;
	::GetWindowText(hWnd, strBuf.GetBuffer(256), 255);
	strBuf.ReleaseBuffer();
	OutputDebugString(strBuf);
	if (strBuf.Find(_T("是(&Y)")) != -1) {	//点击按钮"是"
		//点击这个button
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

		HWND hWnd = FindWindow(_T("#32770"), _T("删除文件"));	//参数：类名、窗口名
		if (hWnd) {
			::EnumChildWindows(hWnd, EnumChildProc, NULL);
			break;
		}

		pos++;
		if (pos == 300) { 	//1分钟
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

	if (FindKey(strBuf, L"隐藏进程") && FindKey(strBuf, L"应用层不可访问进程")) {
		return TRUE;
	}

	return TRUE;
}

BOOL CALLBACK EnumWindowsProc(HWND hwnd/*当前找到的窗口句柄*/, LPARAM lParam/*自定义参数*/)
{
	TCHAR tcClass[256];
	::GetClassName(hwnd, tcClass, 255);

	CString strClassName = tcClass;
	if (strClassName == L"#32770") {	//如果是对话框，继续检索子窗口，判断是否pcHunter
		::EnumChildWindows(hwnd, EnumChildProc1, NULL);
	}

	if (strClassName == L"PROCEXPL") {	//procexp
		return TRUE;
	}

	return TRUE;
}

BOOL FindWindowExample()
{
	//此示例为模拟点击删除桌面文件弹出框中的"是"按钮
	//_beginthreadex(NULL, NULL, WorkTreadex, NULL, 0, NULL);

	//遍历所有窗口
	//::EnumWindows((WNDENUMPROC)EnumWindowsProc, NULL);

	return TRUE;
}

BOOL WinHexExample()
{
	//先用winHex软件将test.xml转换为16进制数组
	//将数组保存在testXml.cpp中
	//然后将此数组数据写入到本地生成回原文件
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
		// 任务管理器启动时
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, procEntry.th32ProcessID);
		if (hProcess) {
			std::wstring strFile;
			CUtility::GetInstance().GetProcessFilePath(hProcess, strFile);	//根据进程ID获取进程目标文件路径
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
			/*CompanyName换成其他就可以获取其他属性，如：
			FileVersion、Comments、InternalName、ProductName、LegalCopyright、ProductVersion、FileDescription、
			LegalTrademarks、PrivateBuild、OriginalFileName、SpecialBuild*/

			LPWSTR pCompany = NULL;
			if (!VerQueryValueW(pBuffer, strTemp.GetBuffer(), (LPVOID*)&pCompany, &uSize))	return 0;

			CString strCompany = pCompany;
			delete[]pBuffer;

			int nPos = strCompany.Find(L"一普明为");
		}
		bRet = Process32Next(procSnap, &procEntry);
	}
	CloseHandle(procSnap);

	return TRUE;
}

void ProUsage()
{
	//获取进程CPU使用率
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

	//获取进程被注入的DLL
	/*std::vector<CString> vDLLNames;
	CUtility::GetInstance().GetProcessDll(8888, vDLLNames);*/
}

typedef BOOL(__stdcall* fSandBox)(LPTSTR lpCmd);
void MemLoadDll()
{
	/*CHAR *pMemDll = NULL;
	DWORD dwSize;
	CUtility::GetInstance().ExtractResource2Memory(NULL, IDR_DLL_32, TEXT("BIN"), &pMemDll, dwSize);   //内存加载32位dll
	//CUtility::GetInstance().ExtractResource2Memory(NULL, IDR_DLL_64, TEXT("BIN"), &pMemDll, dwSize); //内存加载64位dll

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
	//int  file_size = ftell(fp); /* 获取文件长度 */
	//fseek(fp, 0l, SEEK_SET); /* 回到文件头部 */


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
	//对当前进程和目标进程位数无要求，32和64都可以
	//CString strCmdLine;
	//GetPebCommandLine(10060, strCmdLine);

	return;
}

void ExplorerExample()
{
	//获取桌面截图PNG
	//CUtility::GetInstance().GetScreenShot(L"D:\\screen.png");

	//获取当前用户桌面目录和公共目录
	//CString strUserDesk, strCommonDesk;
	//CUtility::GetInstance().GetDeskPath(strUserDesk, strCommonDesk);

	//获取快捷方式的目标路径
	//CString strTargetPath = CUtility::GetInstance().ExpandShortcut(L"C:\\Users\\Administrator\\Desktop\\Postman.lnk");

	//获取桌面所有图标的名字及位置等信息（获取名字也可以用方法GetDeskPath来实现）
	//vector<CString> vIcoNames;
	//CUtility::GetInstance().GetDeskIcon(vIcoNames);

	//更换快捷方式图标
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

	//字符串相关,C接口
	StringExample();

	//json相关操作
	JsonExample();

	//xml解析
	XmlExample();

	//获取pc信息
	HardInfoExample();

	//注册表操作
	RegeditExample();

	//md5相关操作
	Md5Example();

	//解压相关操作
	UnzipExample();

	//隐藏进程、隐藏文件
	HideExample();

	//HTTP、HTTPS请求
	HttpExample();

	//日志模块
	LogExample();

	//监控窗口,捕获指定窗口并点击其中按钮
	FindWindowExample();

	//释放十六进制文件
	WinHexExample();

	//进程遍历相关操作
	ProExample();

	//内存加载DLL（32、64）
	MemLoadDll();

	//内存启动EXE（32）
	MemStartExe();

	//利用PEB分区获取进程启动参数
	GetCmdLine();

	//获取桌面及桌面图标、桌面快捷方式相关信息
	ExplorerExample();

	return 0;
}