#pragma once
#include "nvapi.h"
#include "adl_sdk.h"
#include <d3d9.h>
#pragma comment(lib,"../Nvapi/amd64/nvapi64.lib")
#pragma comment(lib, "d3d9.lib")

/*======================================== NVIDIA ===========================================*/
NvAPI_Status ret = NVAPI_OK;
NvPhysicalGpuHandle physicalGPUs[NVAPI_MAX_PHYSICAL_GPUS];

class CNvGPUInfo
{
	CNvGPUInfo(){ }
public:
	static CNvGPUInfo& GetInstance()
	{
		static CNvGPUInfo obj;

		return obj;
	}

	~CNvGPUInfo(){}

	BOOL NvInit()
	{
		ret = NvAPI_Initialize();

		if (ret != NVAPI_OK){
			return FALSE;
		}
		return TRUE;
	}

	int NvGetNum()
	{
		NvU32 cnt;
		ret = NvAPI_EnumPhysicalGPUs(physicalGPUs, &cnt);
		if (ret != NVAPI_OK){			
			return -1;
		}

		return cnt;
	}

	CString NvGetName(int i)
	{
		NvAPI_ShortString name;
		ret = NvAPI_GPU_GetFullName(physicalGPUs[i], name);
		if (ret != NVAPI_OK){
			return L"";
		}

		CString strName;
		strName.Format(L"NVIDIA %s", CA2T(name).m_psz);
		return strName;
	}

	CString NvGetType(int i)
	{
		NV_GPU_TYPE type;
		ret = NvAPI_GPU_GetGPUType(physicalGPUs[i], &type);
		if (ret == NVAPI_OK) {
			if (type == 1) {
				return L"integrated";	//集显
			}
			else if (type == 2) {
				return L"discrete";	//独显
			}
			else {
				return L"unknown";	//未知
			}
		}
		return L"unknown";
	}

	CString NvGetSysType(int i)
	{
		NV_SYSTEM_TYPE sysType;
		ret = NvAPI_GPU_GetSystemType(physicalGPUs[i], &sysType);
		if (ret == NVAPI_OK) {
			if (sysType == 1) {
				return L"notebook";	//笔记本
			}
			else if (sysType == 2) {
				return L"desktop";	//台式机
			}
			else {
				return L"unknown";	//未知
			}
		}
		return L"unknown";
	}

	int NvGetFanSpeed(int i)
	{
		NvU32 Value = 0;
		ret = NvAPI_GPU_GetTachReading(physicalGPUs[i], &Value);

		if (ret == NVAPI_OK) {
			return Value;
		}
		return 0;
	}

	int NvGetUseRate(int i)
	{
		NV_GPU_DYNAMIC_PSTATES_INFO_EX infoEx = { 0 };;
		infoEx.version = NV_GPU_DYNAMIC_PSTATES_INFO_EX_VER;

		ret = NvAPI_GPU_GetDynamicPstatesInfoEx(physicalGPUs[i], &infoEx);
		if (ret == NVAPI_ERROR){
			return 0;
		}

		return infoEx.utilization[0].percentage;
	}

	int NvGetTemperature(int i)
	{
		NV_GPU_THERMAL_SETTINGS ThermalSettings = { 0 };
		Init_Thermal_Setting(ThermalSettings, NV_GPU_THERMAL_SETTINGS_VER);

		ret = NvAPI_GPU_GetThermalSettings(physicalGPUs[i], 0, &ThermalSettings);
		if (ret == NVAPI_ERROR){
			return 0;
		}

		if (NVAPI_INCOMPATIBLE_STRUCT_VERSION == ret) {
			Init_Thermal_Setting(ThermalSettings, NV_GPU_THERMAL_SETTINGS_VER_1);
			ret = NvAPI_GPU_GetThermalSettings(physicalGPUs[i], 0, &ThermalSettings);
		}

		if (ret == NVAPI_ERROR){
			return 0;
		}

		return ThermalSettings.sensor[0].currentTemp;
	}

	void Init_Thermal_Setting(NV_GPU_THERMAL_SETTINGS& ThermalSettings, NvU32 Version)
	{
		ZeroMemory(&ThermalSettings, sizeof(NV_GPU_THERMAL_SETTINGS));
		ThermalSettings.version = Version;
		ThermalSettings.count = NVAPI_MAX_THERMAL_SENSORS_PER_GPU;
	}

	void GetDisplayCardInfo(DWORD &dwNum, CString chCardName[])
	{
		HKEY keyServ;
		HKEY keyEnum;
		HKEY key;
		HKEY key2;
		LONG lResult;//LONG型变量－保存函数返回值  

		//查询"SYSTEM\\CurrentControlSet\\Services"下的所有子键保存到keyServ  
		lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Services"), 0, KEY_READ, &keyServ);
		if (ERROR_SUCCESS != lResult)
			return;


		//查询"SYSTEM\\CurrentControlSet\\Enum"下的所有子键保存到keyEnum  
		lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Enum"), 0, KEY_READ, &keyEnum);
		if (ERROR_SUCCESS != lResult)
			return;

		int i = 0, count = 0;
		DWORD size = 0, type = 0;
		for (;; ++i)
		{
			Sleep(5);
			size = 512;
			TCHAR name[512] = { 0 };//保存keyServ下各子项的字段名称  

			//逐个枚举keyServ下的各子项字段保存到name中  
			lResult = RegEnumKeyEx(keyServ, i, name, &size, NULL, NULL, NULL, NULL);

			//要读取的子项不存在，即keyServ的子项全部遍历完时跳出循环  
			if (lResult == ERROR_NO_MORE_ITEMS)
				break;

			//打开keyServ的子项字段为name所标识的字段的值保存到key  
			lResult = RegOpenKeyEx(keyServ, name, 0, KEY_READ, &key);
			if (lResult != ERROR_SUCCESS)
			{
				RegCloseKey(keyServ);
				return;
			}


			size = 512;
			//查询key下的字段为Group的子键字段名保存到name  
			TCHAR val[512] = { 0 };
			lResult = RegQueryValueEx(key, TEXT("Group"), 0, &type, (LPBYTE)val, &size);
			if (lResult == ERROR_FILE_NOT_FOUND)
			{
				//?键不存在  
				RegCloseKey(key);
				continue;
			};



			//如果查询到的name不是Video则说明该键不是显卡驱动项  
			if (_tcscmp(TEXT("Video"), val) != 0)
			{
				RegCloseKey(key);
				continue;     //返回for循环  
			};

			//如果程序继续往下执行的话说明已经查到了有关显卡的信息，所以在下面的代码执行完之后要break第一个for循环，函数返回  
			lResult = RegOpenKeyEx(key, TEXT("Enum"), 0, KEY_READ, &key2);
			RegCloseKey(key);
			key = key2;
			size = sizeof(count);
			lResult = RegQueryValueEx(key, TEXT("Count"), 0, &type, (LPBYTE)&count, &size);//查询Count字段（显卡数目）  

			dwNum = count;//保存显卡数目  
			for (int j = 0; j <count; ++j)
			{
				TCHAR sz[512] = { 0 };
				TCHAR name[64] = { 0 };
				wsprintf(name, TEXT("%d"), j);
				size = sizeof(sz);
				lResult = RegQueryValueEx(key, name, 0, &type, (LPBYTE)sz, &size);


				lResult = RegOpenKeyEx(keyEnum, sz, 0, KEY_READ, &key2);
				if (ERROR_SUCCESS)
				{
					RegCloseKey(keyEnum);
					return;
				}


				size = sizeof(sz);
				lResult = RegQueryValueEx(key2, TEXT("FriendlyName"), 0, &type, (LPBYTE)sz, &size);
				if (lResult == ERROR_FILE_NOT_FOUND)
				{
					size = sizeof(sz);
					lResult = RegQueryValueEx(key2, TEXT("DeviceDesc"), 0, &type, (LPBYTE)sz, &size);
					chCardName[j] = sz;//保存显卡名称  
				};
				RegCloseKey(key2);
				key2 = NULL;
			};
			RegCloseKey(key);
			key = NULL;
			break;
		}
	}

	//获取集成显卡信息
	void GetIntegratedGraphicsInfo(DWORD &dwNum, CString &strName)
	{
		CString chCardName[16];
		GetDisplayCardInfo(dwNum, chCardName);

		for (int i = 0; i < dwNum; i++) {
			CString strCardName = chCardName[i];
			int nPos = strCardName.Find(L";");
			if (nPos >= 0) {
				strCardName = strCardName.Right(strCardName.GetLength() - nPos - 1);
			}

			if (strName.IsEmpty()) {
				strName = strCardName;
			}
			else {
				strName = strName + L"|" + strCardName;
			}
		}
	}
};

/*======================================== AMD ===========================================*/

//amd显卡相关
typedef int(*ADL_MAIN_CONTROL_CREATE)(ADL_MAIN_MALLOC_CALLBACK callback, int iEnumConnectedAdapters);
typedef int(*ADL_MAIN_CONTROL_REFRESH)();
typedef int(*ADL_OVERDRIVE5_TEMPERATURE_GET)(int iAdapterIndex, int iThermalControllerIndex, ADLTemperature *lpTemperature);
typedef int(*ADL_OVERDRIVE5_CURRENTACTIVITY_GET)(int iAdapterIndex, ADLPMActivity *lpActivity);
typedef int(*ADL_ADAPTER_ADAPTERINFO_GET)(LPAdapterInfo lpAdapterInfo, int num);
typedef int(*ADL_ADAPTER_NUMBEROFADAPTERS_GET)(int* num);

ADL_MAIN_CONTROL_CREATE				ADL_Main_Control_Create;
ADL_OVERDRIVE5_TEMPERATURE_GET		ADL_Overdrive5_Temperature_Get;
ADL_OVERDRIVE5_CURRENTACTIVITY_GET	ADL_Overdrive5_CurrentActivity_Get;
ADL_MAIN_CONTROL_REFRESH			ADL_Main_Control_Refresh;
ADL_ADAPTER_ADAPTERINFO_GET			ADL_Adapter_AdapterInfo_Get;
ADL_ADAPTER_NUMBEROFADAPTERS_GET    ADL_Adapter_NumberOfAdapters_Get;

class gpu_interface
{
public:
	virtual int get_gpu_usage()
	{
		return -1;
	}
	virtual int get_gpu_temp()
	{
		return -1;
	}
};

void* __stdcall ADL_Main_Memory_Alloc(int size)
{
	void *buf = malloc(size);

	return buf;
}

void __stdcall ADL_Main_Memory_Free(void **lpbuf)
{
	if (*lpbuf) {
		free(*lpbuf);
		*lpbuf = NULL;
	}
}

class CAmdGpuInfo
{
	CAmdGpuInfo(){ }
public:
	static CAmdGpuInfo& GetInstance()
	{
		static CAmdGpuInfo obj;

		return obj;
	}

	~CAmdGpuInfo(){}

	BOOL AmdInit()
	{
		HMODULE hDLL = LoadLibraryA("atiadlxx.dll");
		if (!hDLL) {
			// A 32 bit calling application on 64 bit OS will fail to LoadLIbrary.
			// Try to load the 32 bit library (atiadlxy.dll) instead
			hDLL = LoadLibraryA("atiadlxy.dll");
		}

		if (!hDLL) {
			return FALSE;
		}

		ADL_Main_Control_Create = (ADL_MAIN_CONTROL_CREATE)GetProcAddress(hDLL, "ADL_Main_Control_Create");
		ADL_Overdrive5_Temperature_Get = (ADL_OVERDRIVE5_TEMPERATURE_GET)GetProcAddress(hDLL, "ADL_Overdrive5_Temperature_Get");
		ADL_Overdrive5_CurrentActivity_Get = (ADL_OVERDRIVE5_CURRENTACTIVITY_GET)GetProcAddress(hDLL, "ADL_Overdrive5_CurrentActivity_Get");
		ADL_Main_Control_Refresh = (ADL_MAIN_CONTROL_REFRESH)GetProcAddress(hDLL, "ADL_Main_Control_Refresh");
		ADL_Adapter_AdapterInfo_Get = (ADL_ADAPTER_ADAPTERINFO_GET)GetProcAddress(hDLL, "ADL_Adapter_AdapterInfo_Get");
		ADL_Adapter_NumberOfAdapters_Get = (ADL_ADAPTER_NUMBEROFADAPTERS_GET)GetProcAddress(hDLL, "ADL_Adapter_NumberOfAdapters_Get");

		if (!ADL_Main_Control_Create || !ADL_Overdrive5_Temperature_Get ||
			!ADL_Overdrive5_CurrentActivity_Get || !ADL_Main_Control_Refresh || !ADL_Adapter_AdapterInfo_Get) {
			return FALSE;
		}

		if (ADL_Main_Control_Create(ADL_Main_Memory_Alloc, 1) != ADL_OK) {
			return FALSE;
		}

		if (ADL_Main_Control_Refresh() != ADL_OK) {
			return FALSE;
		}

		return TRUE;
	}

	int GetUsage()
	{
		static int percent = -1;
		ADLPMActivity activity;
		if (ADL_Overdrive5_CurrentActivity_Get(0, &activity) != ADL_OK) {
			return percent == -1 ? -1 : percent;
		}
		percent = activity.iActivityPercent;
		return percent;
	}

	int GetTemp()
	{
		ADLTemperature temp_struct;
		if (ADL_Overdrive5_Temperature_Get(0, 0, &temp_struct) != ADL_OK) {
			return -1;
		}
		return temp_struct.iTemperature / 1000;
	}

	CString GetName()
	{
		int count = 0;

		if (ADL_OK != ADL_Adapter_NumberOfAdapters_Get(&count) && count < 1)	return L"";

		LPAdapterInfo lpAdapterInfo = NULL;
		lpAdapterInfo = (LPAdapterInfo)malloc(sizeof(AdapterInfo)* count);
		if (!lpAdapterInfo)		return L"";

		if (ADL_OK != ADL_Adapter_AdapterInfo_Get(lpAdapterInfo, sizeof(AdapterInfo)* count))	return L"";

		AdapterInfo info = lpAdapterInfo[0];
		CString strName = CA2T(info.strAdapterName);
		if (lpAdapterInfo) free(lpAdapterInfo);

		return strName;
	}
};

/*======================================== GET GPU INFOS ===========================================*/

class CGetGpuInfo
{
	CGetGpuInfo(){ }
public:
	static CGetGpuInfo& GetInstance()
	{
		static CGetGpuInfo obj;

		return obj;
	}

	~CGetGpuInfo(){}

	void changetolower(std::string& str)
	{
		auto iter = str.begin();
		while (iter != str.end()) {
			if (*iter <= 'Z' && *iter >= 'A') {
				*iter += 32;
			}
			iter++;
		}
	}

	CString GetGpuInfos()
	{
		CString strGpus;
		LPDIRECT3D9 pD3D = NULL;
		pD3D = Direct3DCreate9(D3D_SDK_VERSION);//创建Direct 3D对象
		if (!pD3D) {
			return L"";
		}
		DWORD dwDisplayCount = pD3D->GetAdapterCount();//获得显卡数量

		D3DADAPTER_IDENTIFIER9 adapterID;
		for (DWORD i = 0; i < dwDisplayCount; i++)
		{
			if (pD3D->GetAdapterIdentifier(i, 0, &adapterID) != D3D_OK) {
				continue;
			}

			std::string graphics_info = adapterID.Description;
			changetolower(graphics_info);
			cout << graphics_info.c_str() << endl;

			if (graphics_info.find("amd") != -1 || graphics_info.find("ati") != -1) {
				strGpus.Append(L"AMD|");
			}
			else if (graphics_info.find("nvidia") != -1) {
				strGpus.Append(L"NVIDIA|");
			}
			else {
				strGpus.Append(L"INTER|");
			}
		}

		pD3D->Release();
		return strGpus;
	}
};