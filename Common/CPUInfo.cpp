/*
 * @��  ��  ����CPUManager.cpp
 * @˵      ����CCloudHelperʵ��
 * @��      �ڣ�Created on: 2014/03/03
 * @��      Ȩ��Copyright 2014
 * @��      �ߣ�MCA
 */

#include "StdAfx.h"
#include "CPUInfo.h"
#include <wbemidl.h>
#pragma comment(lib,"wbemuuid.lib")

/**
 * \brief  ��ȡCPUʹ���ʳ�ʼ��
 * \return ��ʼ�����
 */
BOOL CCPUInfo::Initialize()
{
	FILETIME ftIdle, ftKernel, ftUser;
	BOOL flag = FALSE;

	if (flag = GetSystemTimes(&ftIdle, &ftKernel, &ftUser)) {
		m_fOldCPUIdleTime = FileTimeToDouble(ftIdle);
		m_fOldCPUKernelTime = FileTimeToDouble(ftKernel);
		m_fOldCPUUserTime = FileTimeToDouble(ftUser);
	}

	return flag;
}


/**
 * \brief  ��ȡCPUʹ����
 * \return CPUʹ����
 */
DWORD CCPUInfo::GetCPUUseRate()
{
	DWORD nCPUUseRate = -1;
	FILETIME ftIdle, ftKernel, ftUser;

	if (GetSystemTimes(&ftIdle, &ftKernel, &ftUser)) {
		double fCPUIdleTime = FileTimeToDouble(ftIdle);
		double fCPUKernelTime = FileTimeToDouble(ftKernel);
		double fCPUUserTime = FileTimeToDouble(ftUser);
		nCPUUseRate= (DWORD)(100.0 - (fCPUIdleTime - m_fOldCPUIdleTime) 
			/ (fCPUKernelTime - m_fOldCPUKernelTime + fCPUUserTime - m_fOldCPUUserTime) 
			*100.0);
		m_fOldCPUIdleTime = fCPUIdleTime;
		m_fOldCPUKernelTime = fCPUKernelTime;
		m_fOldCPUUserTime = fCPUUserTime;
	}
	return nCPUUseRate;
}

double CCPUInfo::FileTimeToDouble(FILETIME &filetime)
{
	return (double)(filetime.dwHighDateTime * 4.294967296E9) + (double)filetime.dwLowDateTime;
}

/**
 * \brief  ��ȡCPU������
 * \return CPU������
 */
DWORD CCPUInfo::GetCPUNumbers()
{
	SYSTEM_INFO sysInfo;
	::GetSystemInfo(&sysInfo);
	DWORD dwNumCpu = sysInfo.dwNumberOfProcessors;
	return dwNumCpu;
}

/**
 * \brief  ��ȡCPU�߳���
 * \return CPU�߳���
 */
SHORT CCPUInfo::GetCPUThreads()
{
	IWbemLocator *locator = NULL;
	IWbemServices *services = NULL;
	IEnumWbemClassObject *results = NULL;
	
	// COM��ʼ��
	CoInitializeEx(0, COINIT_MULTITHREADED);
	CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);

	VARIANT varNumberOfLogic;
	VariantInit(&varNumberOfLogic);

	// ����WMI
	CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *) &locator);
	locator->ConnectServer(L"ROOT\\CIMV2", NULL, NULL, NULL, 0, NULL, NULL, &services);

	// ִ��WMI��ѯ
	services->ExecQuery(L"WQL", L"SELECT NumberOfLogicalProcessors FROM Win32_Processor", WBEM_FLAG_BIDIRECTIONAL, NULL, &results);

	// ���������
	if (results != NULL) {
		IWbemClassObject *result = NULL;
		ULONG count = 0;

		while(results->Next(WBEM_INFINITE, 1, &result, &count) == S_OK) {
			result->Get(L"NumberOfLogicalProcessors", 0, &varNumberOfLogic, 0, 0);
			result->Release();
		}
	}

	services->Release();
	locator->Release();
	CoUninitialize();

	if (varNumberOfLogic.iVal <= 0) {
		return 2;
	}

	return varNumberOfLogic.iVal;
}

CString CCPUInfo::GetCPUName()
{
	CString strCPUName;

	HKEY hKey;
	TCHAR szCPUInfo[MAX_PATH] = { 0 };
	DWORD szCPUFre = 0;
	DWORD dwBufLen = MAX_PATH;
	LONG lRet;

	lRet = RegOpenKeyEx( HKEY_LOCAL_MACHINE,
		TEXT("HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"),
		0, KEY_QUERY_VALUE, &hKey );
	
	if (lRet != ERROR_SUCCESS) {
		strCPUName = TEXT("δ֪CPU����");
	} else {
		lRet = RegQueryValueEx( hKey, TEXT("ProcessorNameString"), NULL, NULL,
			(LPBYTE) szCPUInfo, &dwBufLen);
		if ((lRet != ERROR_SUCCESS) || (dwBufLen > MAX_PATH)) {
			strCPUName = TEXT("δ֪CPU����");
		} else {
			strCPUName = szCPUInfo;
		}
	}
	RegCloseKey(hKey);

	return strCPUName; 
}