#include"windows.h"
#include"stdio.h"


//读取PE文件到内存
PBYTE ReadPEFile(char* PE_path) {
	// 文件路径数据类型转换
	int num = MultiByteToWideChar(0, 0, PE_path, -1, NULL, 0);
	wchar_t *wide = new wchar_t[num];
	MultiByteToWideChar(0, 0, PE_path, -1, wide, num);
	//printf("%ls\n", wide);

	//打开PE文件
	HANDLE hfile = CreateFile(
		wide,
		GENERIC_READ,
		NULL,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hfile == INVALID_HANDLE_VALUE) {
		printf("打开文件失败：%d\n", GetLastError());
		return NULL;
	}
	DWORD  dwSize = GetFileSize(hfile, NULL);
	//printf("文件大小: %d\n", dwSize);

	//申请缓冲区， 并将PE文件读取到内存
	PBYTE peBuf = new BYTE[dwSize]{};
	if (!ReadFile(hfile, peBuf, dwSize, &dwSize, NULL)) {
		printf("[*] 读取PE文件到内存失败\n");
		return NULL;
	}
	printf("file size: %d\n", dwSize);
	return peBuf;
}

//获取空闲内存
BOOL GetSpaces(PBYTE pBuf) {
	//检查是否是PE问价格式
	//printf()
	//1获取PE DOS头部信息
	PIMAGE_DOS_HEADER pdos = (PIMAGE_DOS_HEADER)pBuf;
	if (pdos->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("无效的PE文件\n");
		return FALSE;
	}

	//获取NT头首地址
	PIMAGE_NT_HEADERS  pheader = (PIMAGE_NT_HEADERS)(pBuf + pdos->e_lfanew);
	// 获取NT头Signature字段
	DWORD p_header = pheader->Signature;
	if (p_header != IMAGE_NT_SIGNATURE) {
		printf("不是有效的PE文件\n");
		return FALSE;
	}
	printf("[*] PE file formate Succeed\n");



	//开始查询数据： 区段信息
	//获取NT文件头
	PIMAGE_FILE_HEADER pFileHeader = &pheader->FileHeader;
	//区段信息表
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pheader);
	char pName[9] = {};
	size_t  Baseads = 0;
	//开始起始地址 = DOS + NT + 区段表

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

		//可利用的空间 = 下一个区段的起始地址 - 删一个区段实际大小
		//printf("[*] addr: 0x%x,  stratadd: 0x%x,  0x%x\n", pSec[i].PointerToRawData, startadd, firstsize);
		//size_t avai = pSec[i].PointerToRawData - 4- (startadd + firstsize);
		//memcpy_s(pName, 9, &pSec[i].Name, 8);
		//printf("[*] section Name； %8s  available: 0x%x\n\n", pName, avai);
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

	//获取参数
	if (argc<1 || argc >2) {
		printf("======================\n");
		printf("Usage: getsapce  filepath\n");
		printf("please input file path\n\n");
		printf("======================\n");
		exit(0);
	}

	//printf("文件路径：%d,  %s\n", argc, argv[0]);
	PBYTE PEbuf = ReadPEFile(argv[1]);
	if (PEbuf == NULL)
	{
		printf("ReadPEfile Error: %d\n", GetLastError());
		exit(0);
	}

	BOOL spaces = GetSpaces(PEbuf);
	return 0;
}