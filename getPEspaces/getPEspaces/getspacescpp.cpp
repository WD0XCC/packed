#include"windows.h"
#include"stdio.h"


//��ȡPE�ļ����ڴ�
PBYTE ReadPEFile(char* PE_path) {
	// �ļ�·����������ת��
	int num = MultiByteToWideChar(0, 0, PE_path, -1, NULL, 0);
	wchar_t *wide = new wchar_t[num];
	MultiByteToWideChar(0, 0, PE_path, -1, wide, num);
	//printf("%ls\n", wide);

	//��PE�ļ�
	HANDLE hfile = CreateFile(
		wide,
		GENERIC_READ,
		NULL,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hfile == INVALID_HANDLE_VALUE) {
		printf("���ļ�ʧ�ܣ�%d\n", GetLastError());
		return NULL;
	}
	DWORD  dwSize = GetFileSize(hfile, NULL);
	//printf("�ļ���С: %d\n", dwSize);

	//���뻺������ ����PE�ļ���ȡ���ڴ�
	PBYTE peBuf = new BYTE[dwSize]{};
	if (!ReadFile(hfile, peBuf, dwSize, &dwSize, NULL)) {
		printf("[*] ��ȡPE�ļ����ڴ�ʧ��\n");
		return NULL;
	}
	printf("file size: %d\n", dwSize);
	return peBuf;
}

//��ȡ�����ڴ�
BOOL GetSpaces(PBYTE pBuf) {
	//����Ƿ���PE�ʼ۸�ʽ
	//printf()
	//1��ȡPE DOSͷ����Ϣ
	PIMAGE_DOS_HEADER pdos = (PIMAGE_DOS_HEADER)pBuf;
	if (pdos->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("��Ч��PE�ļ�\n");
		return FALSE;
	}

	//��ȡNTͷ�׵�ַ
	PIMAGE_NT_HEADERS  pheader = (PIMAGE_NT_HEADERS)(pBuf + pdos->e_lfanew);
	// ��ȡNTͷSignature�ֶ�
	DWORD p_header = pheader->Signature;
	if (p_header != IMAGE_NT_SIGNATURE) {
		printf("������Ч��PE�ļ�\n");
		return FALSE;
	}
	printf("[*] PE file formate Succeed\n");



	//��ʼ��ѯ���ݣ� ������Ϣ
	//��ȡNT�ļ�ͷ
	PIMAGE_FILE_HEADER pFileHeader = &pheader->FileHeader;
	//������Ϣ��
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pheader);
	char pName[9] = {};
	size_t  Baseads = 0;
	//��ʼ��ʼ��ַ = DOS + NT + ���α�

	Baseads = pdos->e_lfanew + sizeof(DWORD) + \
		sizeof(IMAGE_FILE_HEADER) + \
		pFileHeader->SizeOfOptionalHeader +
		sizeof(IMAGE_SECTION_HEADER)* pFileHeader->NumberOfSections;

	printf("[*] Baseadde: 0x%x\n", Baseads);
	size_t firstsize = Baseads;
	size_t startadd = Baseads;
	printf("[*] section[0]: %8s  available: 0x%x\n", "PE Header", Baseads);
	for (int i=0; i<pFileHeader->NumberOfSections; i++)
	{

		//�����õĿռ� = ��һ�����ε���ʼ��ַ - ɾһ������ʵ�ʴ�С
		//printf("[*] addr: 0x%x,  stratadd: 0x%x,  0x%x\n", pSec[i].PointerToRawData, startadd, firstsize);
		//size_t avai = pSec[i].PointerToRawData - 4- (startadd + firstsize);
		//memcpy_s(pName, 9, &pSec[i].Name, 8);
		//printf("[*] section Name�� %8s  available: 0x%x\n\n", pName, avai);
		//firstsize = pSec[i].Misc.PhysicalAddress;
		//startadd = pSec[i].PointerToRawData;
		size_t avai = pSec[i].SizeOfRawData - pSec[i].Misc.PhysicalAddress - 4;
		memcpy_s(pName, 9, &pSec[i].Name, 8);
		printf("[*] section[%d]: %8s  available: 0x%x\n", i, pName, avai);
		startadd += avai;
	}
	printf("[*] Total Size of use: 0x%x\n", startadd);
	return TRUE;
}
int  main(_In_ int argc, _In_reads_(argc) _Pre_z_ char** argv, _In_z_ char** envp) {

	//��ȡ����
	if (argc<1 || argc >2) {
		printf("======================\n");
		printf("Usage: getsapce  filepath\n");
		printf("please input file path\n\n");
		printf("======================\n");
		exit(0);
	}

	//printf("�ļ�·����%d,  %s\n", argc, argv[0]);
	PBYTE PEbuf = ReadPEFile(argv[1]);
	if (PEbuf == NULL)
	{
		printf("ReadPEfile Error: %d\n", GetLastError());
		exit(0);
	}

	BOOL spaces = GetSpaces(PEbuf);
	return 0;
}