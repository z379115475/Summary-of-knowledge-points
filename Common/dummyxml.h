#pragma once

/*����ֻʵ��xml�ļ��Ľ���������дxml�ļ�����������Ƿǳ����صģ������ַ�������\0Ϊ��β������ԣ�
  ���еĽڵ���Ϣ������ָ��ԭʼxml�ļ���bufָ�빹�ɣ������Ĺ��̾��ǽ�����λ�õ��ַ��޸ĳ�\0,���������xml
  ������Ľ�����£�
  ԭʼxml
  <?xml version="1.0" encoding="UTF-8"?>
  <root>
		<user id="23" name="lhkyzh" type="com"/>
		<config>
			<run>yes</run>
			<p2p cudp="19034" sudp="19033" stcp="19042"/>
			<rename/>
			<exp/>
		</config>
		<projlist>
			<item id="id1" name="eda" uid="1234">1234</item>
			<item id="id2" name="mainpage" uid="mpid"/>
		</projlist>
  </root>
*/
/* �ڵ����� */
struct _tProperty
{
	LPCSTR key;
	LPCSTR value;
};

/* xml�ڵ��� */
class CXmlNode
{
private:
	
	LPSTR  m_Pos;
	LPCSTR m_name;
	LPCSTR m_text;
	vector<_tProperty> m_PropertyList;
	vector<CXmlNode*> m_SubList;

public:
	CXmlNode() { m_name = NULL; m_text = NULL; m_Pos = NULL;  }
	CXmlNode(LPSTR lpPos) { m_Pos = lpPos; }
	~CXmlNode()
	{
		for (size_t i = 0; i < m_SubList.size(); i++) {
			delete m_SubList[i];
		}
	}

	BOOL Parse()
	{
		return Parse(m_Pos);
	}

	CXmlNode* GetSubNode(INT index)
	{
		if (index < m_SubList.size()) {
			return m_SubList[index];
		}

		return NULL;
	}

	CXmlNode* GetSubNode(LPCTSTR lpNodeName)
	{
		CT2A name(lpNodeName);

		for (size_t i = 0; i < m_SubList.size(); i++) {
			if (strcmp(name, m_SubList[i]->m_name) == 0) {
				return m_SubList[i];
			}
		}

		return NULL;
	}

	size_t GetSubNodeCount()
	{
		return m_SubList.size();
	}

	BOOL GetProperty(LPCTSTR lpPropertyName, ATL::CString &strValue)
	{
		CT2A key(lpPropertyName);
		for (size_t i = 0; i < m_PropertyList.size(); i++) {
			if (strcmp(key, m_PropertyList[i].key) == 0) {
				strValue = CA2T(m_PropertyList[i].value);
				return TRUE;
			}
		}

		return FALSE;
	}

	BOOL GetText(ATL::CString& text)
	{
		text = m_text;
		return (m_text == NULL) ? FALSE : TRUE;
	}

	BOOL GetName(ATL::CString& name)
	{
		name = m_name;
		return (m_name == NULL) ? FALSE : TRUE;
	}

private:
	inline BOOL Parse(LPSTR &lpEnd)
	{
		BOOL bRet = FALSE;

		if (!ParseHeadTag(lpEnd)) {
			return TRUE;
		}

		return ParseContent(lpEnd);
	}
	
	inline BOOL ClearBlank()
	{
		while (*m_Pos == ' ' || *m_Pos == '\r' || *m_Pos == '\n' || *m_Pos == '\t') {
			*(m_Pos++) = '\0';
		}

		return TRUE;
	}
	inline BOOL ParseHeadTag(LPSTR &lpEnd)
	{
		BOOL bRet = FALSE;
		m_Pos++;
		ClearBlank();		// ����հ��ַ�

		m_name = m_Pos;		// ��������
		while (*m_Pos != ' ' && *m_Pos != '/' && *m_Pos != '>') m_Pos++;

		while (*m_Pos) {
			if (*m_Pos == ' ') {			// <item id="ҵ��1"/>
				ClearBlank();
				continue;
			}
			else if (*m_Pos == '>') {		// <run>yes</run>
				bRet = TRUE;
				break;
			}
			else if (*m_Pos == '/') {		// <exp/>				 �ձ��
				*m_Pos++ = '\0';
				break;
			}
			else if (*m_Pos == '<') {
				break;
			}
			else if ((*m_Pos >= 'a' && *m_Pos <= 'z') ||
				(*m_Pos >= 'A' && *m_Pos <= 'Z') ||
				(*m_Pos >= '0' && *m_Pos <= '9')) {
				_tProperty prop;
				prop.key = m_Pos;
				while (*++m_Pos != '=');
				*m_Pos = '\0';
				while (*++m_Pos != '"');
				prop.value = m_Pos + 1;
				while (*++m_Pos != '"');
				*m_Pos = '\0';
				m_PropertyList.push_back(prop);
			}

			m_Pos++;
		}

		*(m_Pos++) = '\0';
		lpEnd = m_Pos;
		return bRet;
	}

	inline BOOL ParseContent(LPSTR &lpEnd)
	{
		BOOL bRet = FALSE;
	NEXT:
		ClearBlank();

		if (*m_Pos == '<') {
			if (*(m_Pos + 1) == '/') {		// �ڵ����
				while (*m_Pos++ != '>');
				lpEnd = m_Pos;
				bRet = TRUE;
			}
			else {				// �����ӽڵ�Ĵ���
				CXmlNode *sub = new CXmlNode(m_Pos);
				m_SubList.push_back(sub);
				sub->Parse(m_Pos);
				goto NEXT;
			}
		}
		else {
			m_text = m_Pos;
			while (*++m_Pos != '<');
			*m_Pos = '\0';
			while (*m_Pos++ != '>');
			lpEnd = m_Pos;
			bRet = TRUE;
		}

		return bRet;
	}
};

/* xml������ */
class CDummyXml
{
private:
	LPSTR m_lpFileContents;
	vector<CXmlNode*> m_NodeList;
	
public:
	CDummyXml()
	{ 
		m_rootNode = NULL;
		m_lpFileContents = NULL;
	}

	~CDummyXml()
	{
		if (m_lpFileContents) {
			delete m_lpFileContents;
		}
		for (size_t i = 0; i < m_NodeList.size(); i++) {
			delete m_NodeList[i];
		}
	}

	BOOL LoadFile(LPCTSTR lpFileName)
	{
		if (m_lpFileContents) {
			return FALSE;
		}
		HANDLE hFile = CreateFile(lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			return FALSE;
		}
		CHandleRelease ResHandle(hFile);

		DWORD dwFileSize = GetFileSize(hFile, 0);    // ��ȡ�ļ��Ĵ�С
		if (dwFileSize == 0xFFFFFFFF){
			return FALSE;
		}

		m_lpFileContents = new CHAR[dwFileSize];

		BOOL bRet = FALSE;
		DWORD dwTotal = 0;
		do {
			DWORD lpReadNumberOfBytes;
			bRet = ReadFile(hFile, m_lpFileContents, dwFileSize, &lpReadNumberOfBytes, NULL);
			if (!bRet) {
				break;
			}
			dwTotal += lpReadNumberOfBytes;
			if (dwTotal == dwFileSize) {
				break;
			}
		} while (bRet);

		return bRet;
	}

	CXmlNode* Parse()
	{
		m_rootNode = GetNode(1, TEXT("root"));
		if (m_rootNode == NULL) {
			return FALSE;
		}

		if (m_rootNode->Parse()) {
			return m_rootNode;
		}

		return NULL;
	}

	CXmlNode* GetNode(DWORD dwCount, ...)
	{
		CXmlNode * pNode = NULL;
		LPCTSTR lpTag = NULL;
		LPSTR lpCurPos = m_lpFileContents;
		va_list args;
		va_start(args, dwCount);
		while (dwCount--) {
			lpTag = va_arg(args, LPCTSTR);
			ATL::CString strTag = _T("<");
			strTag += lpTag;
			lpCurPos = strstr(lpCurPos, CT2CA(strTag));
			if (lpCurPos == NULL) {
				break;
			}
		}
		va_end(args);

		if (lpCurPos) {
			pNode = new CXmlNode(lpCurPos);
			m_NodeList.push_back(pNode);
		}

		return pNode;
	}

	CXmlNode* GetProjNode(LPCTSTR lpProjName)
	{
		if (m_rootNode == NULL) {
			return FALSE;
		}

		CXmlNode* pProjNode = m_rootNode->GetSubNode(TEXT("projlist"));
		if (pProjNode == NULL) {
			return FALSE;
		}

		for (size_t i = 0; i < pProjNode->GetSubNodeCount(); i++) {
			CXmlNode *pSubNode = pProjNode->GetSubNode(i);
			if (pSubNode && pSubNode->GetSubNode(TEXT("name"))) {
				CString text;
				if (pSubNode->GetSubNode(TEXT("name"))->GetText(text) && text == lpProjName) {
					return pSubNode;
				}
			}
		}

		return NULL;
	}

private:
	CXmlNode* m_rootNode;
};