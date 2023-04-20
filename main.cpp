#include<string>
#include<windows.h>
#include<iomanip>
#include<stdio.h>
#include<assert.h>
#include<iostream>

using namespace std;

#define MESSAGEBOXADDR 0x75EA0CA0
DWORD RvaToFoa(DWORD rva, LPVOID pFileBuffer);



uint8_t ShellCode[] = {
	0x6A, 0x00,
	0x6A, 0x00,
	0x6A, 0x00,
	0x6A, 0x00,
	0xE8, 0x00, 0x00, 0x00, 0x00,

	0xE9, 0x00, 0x00, 0x00, 0x00
};
//"E:\\ExeinfoPe\\exeinfope.exe"
//C:\\Users\\Administrator\\Desktop\\PETool 1.0.0.5.exe
//C:\\Users\\Administrator\\Desktop\\Source\\tool\\x64Dbg\\release\\x32\\x32dbg.exe
char file_path[] = "C:\\Users\\Administrator\\Desktop\\Source\\tool\\x64Dbg\\release\\x32\\x32dbg.exe";
char write_addsec_file_path[] = "C:\\Users\\Administrator\\Desktop\\PETool 1.0.0.5123.exe";



//const char* path = "C:\\Users\\Administrator\\Desktop\\PETool 1.0.0.5.exe";
//const char* pathout = "C:\\Users\\Administrator\\Desktop\\PETool 1.0.0.5.1exe";

DWORD ReadpeFile(IN const char* path, OUT LPVOID* pFileBuffer)
{
	FILE* pFile = NULL;
	DWORD FileSize = 0;
	PVOID pFileBufferTemp = NULL;

	pFile = fopen(path, "rb");

	if (!pFile)
	{
		printf("(ToLoaderPE)Can't open file!\n");
		return 0;
	}

	fseek(pFile, 0, SEEK_END);
	FileSize = ftell(pFile);
	printf("FileBuffer: %#x\n", FileSize);
	fseek(pFile, 0, SEEK_SET);
	pFileBufferTemp = malloc(FileSize);

	if (!pFileBufferTemp)
	{
		printf("(ToLoaderPE)Allocate dynamic memory failed!\n");
		fclose(pFile);
		return 0;
	}

	DWORD n = fread(pFileBufferTemp, FileSize, 1, pFile);

	if (!n)
	{
		printf("(ToLoaderPE)Read file failed!\n");
		free(pFileBufferTemp);
		fclose(pFile);
		return 0;
	}
	*pFileBuffer = pFileBufferTemp;
	pFileBufferTemp = NULL;
	fclose(pFile);
	return FileSize;
}

VOID PrintHeaders()
{
	LPVOID filebuffer;
	PIMAGE_DOS_HEADER dosHeader;
	//打开文件
	if (!ReadpeFile(file_path, &filebuffer))
	{
		printf("文件读取失败\n");
		return;
	}
	cout << "读取到的文件地址 : " << file_path << endl;

	//判断MZ位
	if (*((PWORD)filebuffer) != IMAGE_DOS_SIGNATURE)
	{
		cout << "Not a PE File" << endl;
	}

	cout << " *******************************DOS_HEADER *******************************" << endl;
	//解析Dos头
	dosHeader = (PIMAGE_DOS_HEADER)filebuffer;

	//打印Dos头内的数据
	cout << "e_magic    :  " << std::hex << std::setfill('0') << std::setw(4) << dosHeader->e_magic << endl;
	cout << "e_cblp     :  " << std::hex << std::setfill('0') << std::setw(4) << dosHeader->e_cblp << endl;
	cout << "e_cp       :  " << std::hex << std::setfill('0') << std::setw(4) << dosHeader->e_cp << endl;
	cout << "e_crlc     :  " << std::hex << std::setfill('0') << std::setw(4) << dosHeader->e_crlc << endl;
	cout << "e_cparhdr  :  " << std::hex << std::setfill('0') << std::setw(4) << dosHeader->e_cparhdr << endl;
	cout << "e_minalloc :  " << std::hex << std::setfill('0') << std::setw(4) << dosHeader->e_minalloc << endl;
	cout << "e_maxalloc :  " << std::hex << std::setfill('0') << std::setw(4) << dosHeader->e_maxalloc << endl;
	cout << "e_ss       :  " << std::hex << std::setfill('0') << std::setw(4) << dosHeader->e_ss << endl;
	cout << "e_sp       :  " << std::hex << std::setfill('0') << std::setw(4) << dosHeader->e_sp << endl;
	cout << "e_csum     :  " << std::hex << std::setfill('0') << std::setw(4) << dosHeader->e_csum << endl;
	cout << "e_ip       :  " << std::hex << std::setfill('0') << std::setw(4) << dosHeader->e_ip << endl;
	cout << "e_cs       :  " << std::hex << std::setfill('0') << std::setw(4) << dosHeader->e_cs << endl;
	cout << "e_lfarlc   :  " << std::hex << std::setfill('0') << std::setw(4) << dosHeader->e_lfarlc << endl;
	cout << "e_ovno     :  " << std::hex << std::setfill('0') << std::setw(4) << dosHeader->e_ovno << endl;

	cout << "e_res[4]   : ";
	for (size_t i = 0; i < 4; ++i)
	{
		cout << " " << std::hex << std::setfill('0') << std::setw(4) << dosHeader->e_res[i];
	}
	cout << endl;
	cout << "e_oemid    :  " << std::hex << std::setfill('0') << std::setw(4) << dosHeader->e_oemid << endl;
	cout << "e_oeminfo  :  " << std::hex << std::setfill('0') << std::setw(4) << dosHeader->e_oeminfo << endl;

	cout << "e_res2[10] : ";
	for (size_t i = 0; i < 10; ++i)
	{
		cout << " " << std::hex << std::setfill('0') << std::setw(4) << dosHeader->e_res2[i];
	}
	cout << endl;
	cout << "e_lfanew   :  " << std::hex << std::setfill('0') << std::setw(8) << dosHeader->e_lfanew << endl;



	//解析NT_HEADER中的signature

	PIMAGE_NT_HEADERS NTHeader = (PIMAGE_NT_HEADERS)((UINT64)filebuffer + dosHeader->e_lfanew);


	//解析IMAGE_FILE_HEADER
	PIMAGE_FILE_HEADER PeHeader = (PIMAGE_FILE_HEADER)(((UINT64)NTHeader) + 4);
	cout << " *******************************PE_HEADER *******************************" << endl;

	cout << "Machine                 :  " << std::hex << std::setfill('0') << std::setw(4) << PeHeader->Machine << endl;
	cout << "*NumberOfSections       :  " << std::hex << std::setfill('0') << std::setw(4) << PeHeader->NumberOfSections << endl;
	cout << "TimeDateStamp           :  " << std::hex << std::setfill('0') << std::setw(8) << PeHeader->TimeDateStamp << endl;
	cout << "PointerToSymbolTable    :  " << std::hex << std::setfill('0') << std::setw(8) << PeHeader->PointerToSymbolTable << endl;
	cout << "NumberOfSymbols         :  " << std::hex << std::setfill('0') << std::setw(8) << PeHeader->NumberOfSymbols << endl;
	cout << "*SizeOfOptionalHeader   :  " << std::hex << std::setfill('0') << std::setw(4) << PeHeader->SizeOfOptionalHeader << endl;
	cout << "*Characteristics        :  " << std::hex << std::setfill('0') << std::setw(4) << PeHeader->Characteristics << endl;


	//解析IAMGE_OPTIONAL_FILE_HEADER
	PIMAGE_OPTIONAL_HEADER OpPeHeader = (PIMAGE_OPTIONAL_HEADER)(((UINT64)PeHeader) + 20);
	cout << " *******************************OPTIONAL_HEADER *******************************" << endl;

	cout << "Magic                 :  " << std::hex << std::setfill('0') << std::setw(4) << OpPeHeader->Magic << endl;
	cout << "*MajorLinkerVersion       :  " << std::hex << std::setfill('0') << std::setw(2) << OpPeHeader->MajorLinkerVersion << endl;
	cout << "MinorLinkerVersion           :  " << std::hex << std::setfill('0') << std::setw(2) << OpPeHeader->MinorLinkerVersion << endl;
	cout << "SizeOfCode    :  " << std::hex << std::setfill('0') << std::setw(8) << OpPeHeader->SizeOfCode << endl;
	cout << "SizeOfInitializedData         :  " << std::hex << std::setfill('0') << std::setw(8) << OpPeHeader->SizeOfInitializedData << endl;
	cout << "*SizeOfUninitializedData   :  " << std::hex << std::setfill('0') << std::setw(8) << OpPeHeader->SizeOfUninitializedData << endl;
	cout << "*AddressOfEntryPoint        :  " << std::hex << std::setfill('0') << std::setw(8) << OpPeHeader->AddressOfEntryPoint << endl;
	cout << "*BaseOfCode        :  " << std::hex << std::setfill('0') << std::setw(8) << OpPeHeader->BaseOfCode << endl;
	cout << "*ImageBase        :  " << std::hex << std::setfill('0') << std::setw(16) << OpPeHeader->ImageBase << endl;
	cout << "*SectionAlignment        :  " << std::hex << std::setfill('0') << std::setw(8) << OpPeHeader->SectionAlignment << endl;
	cout << "*FileAlignment        :  " << std::hex << std::setfill('0') << std::setw(8) << OpPeHeader->FileAlignment << endl;
	cout << "*MajorOperatingSystemVersion        :  " << std::hex << std::setfill('0') << std::setw(4) << OpPeHeader->MajorOperatingSystemVersion << endl;
	cout << "*MinorOperatingSystemVersion        :  " << std::hex << std::setfill('0') << std::setw(4) << OpPeHeader->MinorOperatingSystemVersion << endl;
	cout << "*MajorImageVersion        :  " << std::hex << std::setfill('0') << std::setw(4) << OpPeHeader->MajorImageVersion << endl;
	cout << "*MajorSubsystemVersion        :  " << std::hex << std::setfill('0') << std::setw(4) << OpPeHeader->MajorSubsystemVersion << endl;
	cout << "*MinorSubsystemVersion        :  " << std::hex << std::setfill('0') << std::setw(4) << OpPeHeader->MinorSubsystemVersion << endl;
	cout << "*Win32VersionValue        :  " << std::hex << std::setfill('0') << std::setw(8) << OpPeHeader->Win32VersionValue << endl;
	cout << "*SizeOfImage        :  " << std::hex << std::setfill('0') << std::setw(8) << OpPeHeader->SizeOfImage << endl;
	cout << "*SizeOfHeaders        :  " << std::hex << std::setfill('0') << std::setw(8) << OpPeHeader->SizeOfHeaders << endl;
	cout << "*CheckSum        :  " << std::hex << std::setfill('0') << std::setw(8) << OpPeHeader->CheckSum << endl;
	cout << "*Subsystem        :  " << std::hex << std::setfill('0') << std::setw(4) << OpPeHeader->Subsystem << endl;
	cout << "*DllCharacteristics        :  " << std::hex << std::setfill('0') << std::setw(4) << OpPeHeader->DllCharacteristics << endl;
	cout << "*SizeOfStackReserve        :  " << std::hex << std::setfill('0') << std::setw(16) << OpPeHeader->SizeOfStackReserve << endl;
	cout << "*SizeOfStackCommit        :  " << std::hex << std::setfill('0') << std::setw(16) << OpPeHeader->SizeOfStackCommit << endl;
	cout << "*SizeOfHeapReserve        :  " << std::hex << std::setfill('0') << std::setw(16) << OpPeHeader->SizeOfHeapReserve << endl;
	cout << "*SizeOfHeapCommit        :  " << std::hex << std::setfill('0') << std::setw(16) << OpPeHeader->SizeOfHeapCommit << endl;
	cout << "*LoaderFlags        :  " << std::hex << std::setfill('0') << std::setw(8) << OpPeHeader->LoaderFlags << endl;
	cout << "*NumberOfRvaAndSizes        :  " << std::hex << std::setfill('0') << std::setw(8) << OpPeHeader->NumberOfRvaAndSizes << endl;


	//解析Section
	PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)(((UINT64)OpPeHeader) + PeHeader->SizeOfOptionalHeader);

	cout << " *******************************SECTION_HEADER *******************************" << endl;
	for (size_t i = 0; i < PeHeader->NumberOfSections; ++i)
	{
		cout << "Name : " << std::setfill('0') << std::setw(1) << SectionHeader[i].Name << endl;
		cout << "PhysicalAddress : " << std::setfill('0') << std::setw(8) << SectionHeader[i].Misc.PhysicalAddress << endl;
		cout << "VirtualSize : " << std::setfill('0') << std::setw(8) << SectionHeader[i].Misc.VirtualSize << endl;
		cout << "VirtualAddress : " << std::setfill('0') << std::setw(8) << SectionHeader[i].VirtualAddress << endl;
		cout << "SizeOfRawData : " << std::setfill('0') << std::setw(8) << SectionHeader[i].SizeOfRawData << endl;
		cout << "PointerToRawData : " << std::setfill('0') << std::setw(8) << SectionHeader[i].PointerToRawData << endl;
		cout << "PointerToRelocations : " << std::setfill('0') << std::setw(8) << SectionHeader[i].PointerToRelocations << endl;
		cout << "PointerToLinenumbers : " << std::setfill('0') << std::setw(8) << SectionHeader[i].PointerToLinenumbers << endl;
		cout << "NumberOfRelocations : " << std::setfill('0') << std::setw(4) << SectionHeader[i].NumberOfRelocations << endl;
		cout << "NumberOfLinenumbers : " << std::setfill('0') << std::setw(4) << SectionHeader[i].NumberOfLinenumbers << endl;
		cout << "Characteristics : " << std::setfill('0') << std::setw(8) << SectionHeader[i].Characteristics << endl;
		cout << endl;
		cout << endl;

	}

}

VOID PrintExportTable()
{
	LPVOID pFileBuffer;
	size_t filesize = 0;
	size_t ImageBufferSize = 0;

	filesize = ReadpeFile(file_path, &pFileBuffer);

	if (!filesize)
	{
		cout << "读取文件失败" << endl;
	}
	if (!pFileBuffer)
	{
		cout << "pFileBuffer创建失败" << endl;
		free(pFileBuffer);
	}

	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;

	if (*((PDWORD)((DWORD)pFileBuffer + DosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("(TestAddSection)Not a valid PE flag!\n");
		free(pFileBuffer);
		return ;
	}

	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)(((DWORD)pFileBuffer + DosHeader->e_lfanew));

	PIMAGE_FILE_HEADER PeHeader = (PIMAGE_FILE_HEADER)(((DWORD)NtHeader + 4));
	PIMAGE_OPTIONAL_HEADER32 OpHeader = (PIMAGE_OPTIONAL_HEADER32)(((DWORD)pFileBuffer + DosHeader->e_lfanew) + 4 + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER SecHeader = (PIMAGE_SECTION_HEADER)(((DWORD)OpHeader + PeHeader->SizeOfOptionalHeader));

	IMAGE_DATA_DIRECTORY pDirect = (IMAGE_DATA_DIRECTORY)OpHeader->DataDirectory[0];
	//得到偏
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(RvaToFoa(OpHeader->DataDirectory[0].VirtualAddress, pFileBuffer) + (UINT_PTR)pFileBuffer);

	cout << "pExport: " << pExport << endl;
	if (pExport == NULL)
	{
		cout << "导出表为空" << endl;
		return;
	}

	cout << " *******************************Export_Table *******************************" << endl;


	DWORD* FuncAddr = (DWORD*)((UINT_PTR)pFileBuffer + RvaToFoa(pExport->AddressOfFunctions, pFileBuffer));
	DWORD* FuncName = (DWORD*)((UINT_PTR)pFileBuffer + RvaToFoa(pExport->AddressOfNames, pFileBuffer));
	WORD* FuncOrder = (WORD*)((UINT_PTR)pFileBuffer + RvaToFoa(pExport->AddressOfNameOrdinals, pFileBuffer));

	cout << "Number of Functions: " << pExport->NumberOfFunctions << endl;
	cout << "Number of Names: " << pExport->NumberOfNames << endl;

	bool NameIsNull{ false };
	for (UINT i = 0; i < pExport->NumberOfFunctions; i++)
	{
		printf("函数地址:%x\t", *FuncAddr);
		for (UINT Order = 0; Order < pExport->NumberOfNames; Order++)
		{
			//看看在序号表中有没有等于地址表的索引的
			if (FuncOrder[Order] == i)
			{
				//如果序号表存在，则取序号表的索引 i，即取名称表的第i的元素
				printf("序号:%d\t", FuncOrder[Order]);
				NameIsNull = false;
				char* Name = (char*)(RvaToFoa(FuncName[Order], pFileBuffer)) + (UINT_PTR)pFileBuffer;
				printf("%s\n", Name);
				break;
			}
			else
			{
				NameIsNull = true;
			}
		}
		if (NameIsNull)
		{
			printf("NoName\n");
		}
		FuncAddr++;
	}

}

VOID PrintRelocTable()
{
	LPVOID pFileBuffer;
	size_t filesize = 0;
	size_t ImageBufferSize = 0;

	filesize = ReadpeFile(file_path, &pFileBuffer);

	if (!filesize)
	{
		cout << "读取文件失败" << endl;
	}
	if (!pFileBuffer)
	{
		cout << "pFileBuffer创建失败" << endl;
		free(pFileBuffer);
	}

	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;

	if (*((PDWORD)((DWORD)pFileBuffer + DosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("(TestAddSection)Not a valid PE flag!\n");
		free(pFileBuffer);
		return;
	}

	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)(((DWORD)pFileBuffer + DosHeader->e_lfanew));

	PIMAGE_FILE_HEADER PeHeader = (PIMAGE_FILE_HEADER)(((DWORD)NtHeader + 4));
	PIMAGE_OPTIONAL_HEADER32 OpHeader = (PIMAGE_OPTIONAL_HEADER32)(((DWORD)pFileBuffer + DosHeader->e_lfanew) + 4 + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER SecHeader = (PIMAGE_SECTION_HEADER)(((DWORD)OpHeader + PeHeader->SizeOfOptionalHeader));

	//得到RelocTable
	IMAGE_DATA_DIRECTORY pDirect = (IMAGE_DATA_DIRECTORY)OpHeader->DataDirectory[5];

	DWORD RelocOffset = RvaToFoa(pDirect.VirtualAddress, pFileBuffer);

	PIMAGE_BASE_RELOCATION Reloc = (PIMAGE_BASE_RELOCATION)((UINT64)pFileBuffer + RelocOffset);

	while (Reloc->VirtualAddress != 0 || Reloc->SizeOfBlock != 0)
	{
		DWORD Rva = Reloc->VirtualAddress + (UINT64)pFileBuffer;
		cout << "RVA = " << hex <<Reloc->VirtualAddress;

		DWORD RelocTableOffset = RvaToFoa(Reloc->VirtualAddress, (BYTE*)pFileBuffer);
		//cout << " FOA = " << hex<<RelocTableOffset ;

		DWORD SizeofBlock = Reloc->SizeOfBlock;
		//cout << " Size = " << SizeofBlock ;
		
		DWORD NumberofBlock = (Reloc->SizeOfBlock - 8) / 2;
		cout << " Items = " << dec << NumberofBlock << endl;


		WORD* RelocTemp = (WORD*)((DWORD)Reloc + 8);
		for (int i = 0; i < NumberofBlock; i++ , (WORD*)((BYTE)(RelocTemp)+2))
		{
			WORD offset = *((PWORD)((BYTE*)RelocTemp + i * 2));
			 //获取重定位项类型
			BYTE type = offset >> 12;
			//低12位是偏移，相对于块头
			WORD Blockoffset = (WORD)(offset & 0xFFF);
			WORD BlockFOA = Reloc->VirtualAddress + Blockoffset;
			cout << " FOA = " <<  hex << BlockFOA <<" Type = " << dec << (int)type << endl;
		}


		Reloc = (PIMAGE_BASE_RELOCATION)((UINT64)Reloc + SizeofBlock);
		cout << endl;

		
	}

}

VOID PrintImportTable()
{
	LPVOID pFileBuffer;
	size_t filesize = 0;
	size_t ImageBufferSize = 0;

	filesize = ReadpeFile(file_path, &pFileBuffer);

	if (!filesize)
	{
		cout << "读取文件失败" << endl;
	}
	if (!pFileBuffer)
	{
		cout << "pFileBuffer创建失败" << endl;
		free(pFileBuffer);
	}

	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;

	if (*((PDWORD)((DWORD)pFileBuffer + DosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("(TestAddSection)Not a valid PE flag!\n");
		free(pFileBuffer);
		return;
	}

	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)(((DWORD)pFileBuffer + DosHeader->e_lfanew));

	PIMAGE_FILE_HEADER PeHeader = (PIMAGE_FILE_HEADER)(((DWORD)NtHeader + 4));
	PIMAGE_OPTIONAL_HEADER32 OpHeader = (PIMAGE_OPTIONAL_HEADER32)(((DWORD)pFileBuffer + DosHeader->e_lfanew) + 4 + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER SecHeader = (PIMAGE_SECTION_HEADER)(((DWORD)OpHeader + PeHeader->SizeOfOptionalHeader));

	IMAGE_DATA_DIRECTORY pDirect = (IMAGE_DATA_DIRECTORY)OpHeader->DataDirectory[1];

	DWORD ImportOffset = RvaToFoa(pDirect.VirtualAddress, pFileBuffer);

	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)((UINT64)pFileBuffer + ImportOffset);

	while (pImport->Characteristics != 0)
	{
		DWORD NameOffset = RvaToFoa(pImport->Name, pFileBuffer);

		cout << "DLLName: " << (char*)((UINT64)pFileBuffer+NameOffset);
		cout << " Time: " << pImport->TimeDateStamp<<endl;
		//OriginalFirstThunk文件偏移
		DWORD OriOffset = RvaToFoa(pImport->OriginalFirstThunk, pFileBuffer);
		PIMAGE_THUNK_DATA pThunkData = (PIMAGE_THUNK_DATA)((DWORD)pFileBuffer + OriOffset);

		while (pThunkData->u1.AddressOfData != 0)
		{
			if (pThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				//最高位是1，表示是序号导入
				//低31位为序号
				DWORD ordinal = pThunkData->u1.Ordinal & 0x7FFFFFFF;

				cout << " 序号:"  << dec << ordinal << endl;
			}
			else
			{
				//最高位为0，函数名称导入
				DWORD AddressOfDataOffset = RvaToFoa(pThunkData->u1.AddressOfData, pFileBuffer);
				PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)((UINT64)pFileBuffer + AddressOfDataOffset);

				cout << " Hint" <<hex << pName->Hint;
				cout << " Name" << pName->Name;
				cout << endl;
			}
			pThunkData++;
		}
		pImport++;
	}
















}

DWORD  GetFunctionAddrByName(const char* lpProcName)
{
	LPVOID pFileBuffer;
	size_t filesize = 0;
	size_t ImageBufferSize = 0;
	char* lpName = NULL;

	filesize = ReadpeFile(file_path, &pFileBuffer);

	if (!filesize)
	{
		cout << "读取文件失败" << endl;
	}
	if (!pFileBuffer)
	{
		cout << "pFileBuffer创建失败" << endl;
		free(pFileBuffer);
	}

	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;

	if (*((PDWORD)((DWORD)pFileBuffer + DosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("(TestAddSection)Not a valid PE flag!\n");
		free(pFileBuffer);
		return -1;
	}

	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)(((DWORD)pFileBuffer + DosHeader->e_lfanew));

	PIMAGE_FILE_HEADER PeHeader = (PIMAGE_FILE_HEADER)(((DWORD)NtHeader + 4));
	PIMAGE_OPTIONAL_HEADER32 OpHeader = (PIMAGE_OPTIONAL_HEADER32)(((DWORD)pFileBuffer + DosHeader->e_lfanew) + 4 + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER SecHeader = (PIMAGE_SECTION_HEADER)(((DWORD)OpHeader + PeHeader->SizeOfOptionalHeader));

	IMAGE_DATA_DIRECTORY pDirect = (IMAGE_DATA_DIRECTORY)OpHeader->DataDirectory[0];
	//得到偏
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(RvaToFoa(OpHeader->DataDirectory[0].VirtualAddress, pFileBuffer) + (UINT_PTR)pFileBuffer);

	cout << "pExport: " << pExport << endl;
	if (pExport == NULL)
	{
		cout << "导出表为空" << endl;
		return -1;
	}

	

	//名字地址的偏移
	DWORD* FuncName = (DWORD*)((UINT_PTR)pFileBuffer + RvaToFoa(pExport->AddressOfNames, pFileBuffer));
	//DWORD pAddressOfNamesFoa = RvaToFoa(pExport->AddressOfNames, pFileBuffer);
	DWORD queryNumber = -1;

	for (int i = 0; i < pExport->NumberOfNames; i++, FuncName++)
	{
		//名字地址
		//得到名字（也是一个RVA）
		lpName = (char*)((DWORD)pFileBuffer + RvaToFoa(*FuncName, pFileBuffer));
		if (!strcmp(lpName, lpProcName))
		{
			queryNumber = i;
			printf("要找的函数名称：%s,函数名称表下标：%i\n", lpName, queryNumber);
			break;
		}
		
	}

	DWORD pFun = 0;
	if (queryNumber == -1)//没有用函数名字导出 
	{
		return pFun;
	}

	//找序号表
	WORD* FuncOrder = (WORD*)((UINT_PTR)pFileBuffer + RvaToFoa(pExport->AddressOfNameOrdinals, pFileBuffer));
	for (int i = 0; i < pExport->NumberOfFunctions; i++, FuncOrder++)
	{
		if (queryNumber == i)
		{
			queryNumber = *FuncOrder + pExport->Base;
			printf("要找的函数名称：%s,函数序号：%i\n", lpName, queryNumber);
			break;
		}
	}

	//找函数表
	
	DWORD* FuncAddr = (DWORD*)((UINT_PTR)pFileBuffer + RvaToFoa(pExport->AddressOfFunctions, pFileBuffer));
	for (int i = 0; i < pExport->NumberOfFunctions; i++, FuncAddr++)
	{
		if (i == (queryNumber - pExport->Base))
		{
			pFun = *FuncAddr;
			printf("要找的函数地址：%x,函数表下标：%i\n", pFun, i);
			break;
		}
	}

	return pFun;
}

DWORD FileBufferToImageBuffer(IN LPVOID pFileBuffer, OUT LPVOID* pImageBUffer)    //参数为一个地址, 由ReadpeFile返回
{
	
	//解析
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;

	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(((UINT64)pFileBuffer) + dosHeader->e_lfanew);
	
	PIMAGE_FILE_HEADER fileHeader = (PIMAGE_FILE_HEADER)((UINT64)ntHeader + 4);

	PIMAGE_OPTIONAL_HEADER opHeader = (PIMAGE_OPTIONAL_HEADER)(((UINT64)fileHeader) + 20);

	PIMAGE_SECTION_HEADER secHeader = (PIMAGE_SECTION_HEADER)(((UINT64)opHeader) + fileHeader->SizeOfOptionalHeader);


	//申请一块动态内存，大小跟filebuffer一样
	DWORD ImageSize = opHeader->SizeOfImage;
	
	* pImageBUffer = new char[ImageSize];

	//拷贝filebuffer中的heads到ImageBUffer

	memcpy(*pImageBUffer, pFileBuffer, opHeader->SizeOfHeaders);
	
	//拷贝节表
	for (size_t i = 0; i < fileHeader->NumberOfSections; ++i)
	{
		memcpy((PIMAGE_SECTION_HEADER)((DWORD_PTR)*pImageBUffer + secHeader[i].VirtualAddress), (PIMAGE_SECTION_HEADER)((DWORD_PTR)pFileBuffer + secHeader[i].PointerToRawData), secHeader[i].SizeOfRawData);
	}
	
	cout << "Create ImageBUffer successfully" << endl;
	

	return opHeader->SizeOfImage;
}

DWORD ImageBuffertoFileBuffer(IN LPVOID pImageBuffer, OUT LPVOID* pNewBUffer)
{
	//cout << pImageBuffer << endl;

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;

	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(((UINT64)pImageBuffer) + dosHeader->e_lfanew);

	PIMAGE_FILE_HEADER fileHeader = (PIMAGE_FILE_HEADER)((UINT64)ntHeader + 4);

	PIMAGE_OPTIONAL_HEADER opHeader = (PIMAGE_OPTIONAL_HEADER)(((UINT64)fileHeader) + 20);

	PIMAGE_SECTION_HEADER secHeader = (PIMAGE_SECTION_HEADER)(((UINT64)opHeader) + fileHeader->SizeOfOptionalHeader);


	dosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("Invalid DOS signature.\n");
		return 0;
	}

	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)pImageBuffer + dosHeader->e_lfanew);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("Invalid NT signature.\n");
		return 0;
	}

	// 获取节表
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)secHeader;
	// 找到最后一个节表
	PIMAGE_SECTION_HEADER pLastSection = (PIMAGE_SECTION_HEADER)(pSectionHeader + ntHeader->FileHeader.NumberOfSections - 1);

	// 计算文件大小
	size_t fileSize = pLastSection->PointerToRawData;
	fileSize += pLastSection->SizeOfRawData;

	// 分配内存
	*pNewBUffer = malloc(fileSize);
	memset(*pNewBUffer, 0, fileSize);

	// 复制头信息
	memcpy(*pNewBUffer, pImageBuffer, ntHeader->OptionalHeader.SizeOfHeaders);

	// 遍历节表，将每个节表中的数据复制到新文件缓冲区中
	for (size_t i = 0; i < fileHeader->NumberOfSections; i++)
	{
		memcpy((PIMAGE_SECTION_HEADER)((uintptr_t)*pNewBUffer + pSectionHeader[i].PointerToRawData), (PIMAGE_SECTION_HEADER)((DWORD_PTR)pImageBuffer + pSectionHeader[i].VirtualAddress), pSectionHeader[i].SizeOfRawData);
	}

	cout << "ImageBuffer to FileBuffer Succeeded" << endl;
	return fileSize;
}

BOOL MemoryToFile(PVOID pMemBuffer, DWORD size, LPSTR lpszFile)
{
	FILE* fp;
	fp = fopen(lpszFile, "wb");
	if (fp != NULL)
	{
		fwrite(pMemBuffer, size, 1, fp);
	}
	fclose(fp);
	printf("Store file success!\n");
	return 1;
}

DWORD RvaToFoa(DWORD rva, LPVOID pFileBuffer)
{
	//获得区段表
	/*
	Nt头的起始位置 + 可选头到Nt头的距离 + 可选头的大小
	*/
	

	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)(((DWORD)pFileBuffer + DosHeader->e_lfanew));

	PIMAGE_FILE_HEADER PeHeader = (PIMAGE_FILE_HEADER)(((DWORD)NtHeader + 4));
	PIMAGE_OPTIONAL_HEADER32 OpHeader = (PIMAGE_OPTIONAL_HEADER32)(((DWORD)pFileBuffer + DosHeader->e_lfanew) + 4 + IMAGE_SIZEOF_FILE_HEADER);
	
	PIMAGE_SECTION_HEADER pSelctionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)NtHeader + FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) + PeHeader->SizeOfOptionalHeader);
	// 遍历每一个区段，看看 RVA（某个东西在内存中的偏移地址）是否落在某个区段上
	for (UINT i = 0; i < PeHeader->NumberOfSections; i++)
	{
		/*
		数据的RVA - 区段的RVA = 数据 在内存中距离区段头的距离 s1
		数据的FOA - 区段的FOA = 数据 在文件中距离区段头的距离 s2
		s1=s2
		数据的FOA - 区段的FOA = 数据的RVA - 区段的RVA
		所以：已知数据的RVA求数据的FOA： 数据的FOA = 数据的RVA - 区段的RVA + 区段的FOA
		*/
		if (rva >= pSelctionHeader->VirtualAddress && rva < pSelctionHeader->VirtualAddress + pSelctionHeader->Misc.VirtualSize)
		{
			//rva必须在某一个区段的里面， 大于区段头部偏移，小于区段头加大小
			return rva - pSelctionHeader->VirtualAddress + pSelctionHeader->PointerToRawData;
		}
		pSelctionHeader++;
	}
	return 0;
}

VOID AddShellCode()
{
	LPVOID pFileBuffer;
	LPVOID pImageBUffer;
	LPVOID pNewBUffer;
	size_t ImageBufferSize = 0;
	if (!ReadpeFile(file_path, &pFileBuffer))
	{
		cout << "读取文件失败" << endl;
	}
	if (!pFileBuffer)
	{
		cout << "pFileBuffer创建失败" << endl;
		delete[]pFileBuffer;
	}

	ImageBufferSize = FileBufferToImageBuffer(pFileBuffer, &pImageBUffer);
	if (!pImageBUffer)
	{
		cout << "FileBuffer to ImageBuffer failed" << endl;
		delete[] pFileBuffer;
		return;
	}


	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)pImageBUffer;
	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)(((DWORD)pImageBUffer + DosHeader->e_lfanew));

	PIMAGE_FILE_HEADER PeHeader = (PIMAGE_FILE_HEADER)(((DWORD)NtHeader + 4));
	PIMAGE_OPTIONAL_HEADER32 OpHeader = (PIMAGE_OPTIONAL_HEADER32)(((DWORD)pImageBUffer + DosHeader->e_lfanew) + 4 + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER SecHeader = (PIMAGE_SECTION_HEADER)(((DWORD)OpHeader + PeHeader->SizeOfOptionalHeader));

	//判断是否有足够空间储存shellcode
	if (((SecHeader->SizeOfRawData) - (SecHeader->Misc.VirtualSize)) < sizeof(ShellCode))
	{
		cout << "代码区空间不足" << endl;
		delete[] pFileBuffer;
		delete[] pImageBUffer;
	}

	//从哪里开始修改Shellcode
	PBYTE CodeBegin = (PBYTE)((DWORD)pImageBUffer + SecHeader->VirtualAddress + SecHeader->Misc.VirtualSize);

	//储存Shellcode
	memcpy(CodeBegin, ShellCode, sizeof(ShellCode));

	//修正E8后的四字节地址  X偏移 = MessageBoxAddr - E8的下一条地址（运行时的地址）
	DWORD CallAddr = (MESSAGEBOXADDR - (OpHeader->ImageBase + ((DWORD)(CodeBegin + 0xD) - (DWORD)pImageBUffer)));

	//写到E8 + 9的位置
	*(PDWORD)(CodeBegin + 0x09) = CallAddr;

	//修正E9后的4字节 X偏移 = 要跳的地址 - E9的下一条地址（运行时的地址）
	DWORD JMPAddr = ((OpHeader->ImageBase + OpHeader->AddressOfEntryPoint) - (OpHeader->ImageBase + ((DWORD)(CodeBegin + sizeof(ShellCode) - (DWORD)pImageBUffer))));
	*(PDWORD)(CodeBegin + 0xE) = JMPAddr;

	//修改OEP
	OpHeader->AddressOfEntryPoint = (DWORD)CodeBegin - (DWORD)pImageBUffer;

	DWORD size = ImageBuffertoFileBuffer(pImageBUffer, &pNewBUffer);
	if (size = 0 || !pNewBUffer)
	{
		cout << "ImageBuffer to NewBuffer Failed" << endl;
		delete[] pFileBuffer;
		delete[] pImageBUffer;
		return;
	}

	BOOL isOK = MemoryToFile(pNewBUffer, size, write_addsec_file_path);
	if (isOK)
	{
		cout << "修改代码添加SHELLCODE 存盘成功" << endl;
		return;
	}

	delete[] pFileBuffer;
	delete[] pImageBUffer;
	delete[] pNewBUffer;
}

//VOID AddCodeInCodeSec()
//{
//	LPVOID pFileBuffer = NULL;
//	LPVOID pImageBuffer = NULL;
//	LPVOID pNewBuffer = NULL;
//	PIMAGE_DOS_HEADER pDosHeader = NULL;
//	PIMAGE_NT_HEADERS ntHeader = NULL;
//	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
//	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
//	PIMAGE_FILE_HEADER FileHeader = NULL;
//	PBYTE codeBegin = NULL;
//	BOOL isOK = FALSE;
//	DWORD size = 0;
//
//	//File-->FileBuffer
//	ReadpeFile(path, &pFileBuffer);
//	if (!pFileBuffer)
//	{
//		cout << "文件-->缓冲区失败" << endl;
//		return;
//	}
//
//	//FileBuffer-->ImageBuffer
//	FileBufferToImageBuffer(pFileBuffer, &pImageBuffer);
//	if (!pImageBuffer)
//	{
//		cout << "FileBuffer-->ImageBuffer失败" << endl;
//		delete[]pFileBuffer;
//		return;
//	}
//
//	//判断代码段空闲区域是否能够足够存储ShellCode代码
//	pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
//	ntHeader = (PIMAGE_NT_HEADERS)(((DWORD)pImageBuffer + pDosHeader->e_lfanew));
//	FileHeader = (PIMAGE_FILE_HEADER)(((DWORD)ntHeader + 4));
//	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)(((DWORD)pImageBuffer + pDosHeader->e_lfanew) + 4 + IMAGE_SIZEOF_FILE_HEADER);
//	pSectionHeader = (PIMAGE_SECTION_HEADER)(((DWORD)pOptionHeader + FileHeader->SizeOfOptionalHeader));
//	if (((pSectionHeader->SizeOfRawData) - (pSectionHeader->Misc.VirtualSize)) < sizeof(ShellCode))
//	{
//		cout << "代码区域空闲空间不够" << endl;
//		delete[]pFileBuffer;
//		delete[]pImageBuffer;
//	}
//
//	//将代码复制到空闲区域
//	codeBegin = (PBYTE)((DWORD)pImageBuffer + pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize);
//
//	memcpy(codeBegin, ShellCode, sizeof(ShellCode));
//
//	//修正E8-->call后面的代码区域
//	DWORD callAddr = (MESSAGEBOXADDR - (pOptionHeader->ImageBase + ((DWORD)(codeBegin + 0xD) - (DWORD)pImageBuffer)));
//
//	*(PDWORD)(codeBegin + 0x09) = callAddr;
//
//	/*
//	关于修正E8的理解，公式：X = 要跳转的地址 - (E8当前的地址 + 5)；
//	要跳转的地址，这里是毋庸置疑的，就是我们要加入代码MessageBox的地址；
//	然后要减去E8当前的地址+5的位置，这里不是太好理解；
//	我们的目的是要将E8后面的4个字节计算出来，然后写入到E8后面，也就是公式中X；
//	上面公式E8当前地址+5 ，而在此情况要定位到这个位置就要从代码的Dos开始通过指针相加；
//	进行位置偏移到E8当前地址+5的位置；
//	所以定位codeBegin的位置是：pImageBuffer指针最开始的位置（Dos头位置）通过内存中偏移的宽度移动到第一个节表的位置；
//	也就是上面的pSectionHeader->VirtualAddress 操作形式；
//	然后再偏移第一个节表在内存中对齐前实际的宽度（尺寸）pSectionHeader->Misc.VirtualSize；
//	上述一番操作之后就到了第一个节表没有对齐前的位置，这个位置就是我们可以添加ShellCode代码的起始位置；
//	到了添加ShellCode代码的起始位置之后，就要想办法添加E8位置后面的4个字节，此时根据ShellCode代码的宽度；
//	进行计算，确认0x6A 00 0x6A 00 0x6A 00 0x6A 00 E8 00 00 00 00 刚好向后面数13个位置，按照十六进制看；
//	就是0xD，所以在codeBegin偏移0xD个位置即可到达E9的位置，这也就是我们说的(E8当前的地址 + 5);
//	到了上面的位置之后，由于我们最终是需要在程序运行之后在内存中添加ShellCode代码；所以这里一定要计算出；
//	其准确的偏移地址，这样不管怎么拉伸到哪个位置，都能准确找到位置；
//	注意：这里需要注意一点理解，上面说的pImageBuffer这个是我们加载程序到我们申请的内存中，绝不是程序在；
//	运行中的那个内存，这里一定要理解清楚，她们是不一样的，理解了这个就能理解上面代码为什么要减去Dos头的；
//	首地址，(DWORD)(codeBegin + 0xD) - (DWORD)pImageBuffer)
//	*/
//
//	//修正E9-->jmp后面的代码区域
//	DWORD jmpAddr = ((pOptionHeader->ImageBase + pOptionHeader->AddressOfEntryPoint) - (pOptionHeader->ImageBase + ((DWORD)(codeBegin + sizeof(ShellCode) - (DWORD)pImageBuffer))));
//
//	*(PDWORD)(codeBegin + 0x0E) = jmpAddr;
//
//	/*
//	公式：X = 要跳转的地址 - (E9当前的地址 + 5)
//	这里同样是要计算出E9后面4个字节的地址，我们的目的是在这里添加OEP的地址，让其执行完成MessageBox之后跳转；
//	OEP的地址，那么这里就要先计算出OEP地址，就是pOptionHeader->ImageBase + pOptionHeader->AddressOfEntryPoint；
//	再减去(E9当前的地址 + 5) 0x6A 00 0x6A 00 0x6A 00 0x6A 00 E8 00 00 00 00 E9 00 00 00 00；
//	(DWORD)codeBegin + SHELLCODELENGTH 就是加上ShellCode总长度，偏移完成之后减去ImageBuffer首地址再加上ImageBase；
//	*/
//
//	//修正OEP
//
//	pOptionHeader->AddressOfEntryPoint = (DWORD)codeBegin - (DWORD)pImageBuffer;
//
//	//修正OEP好理解，就是定位到OEP地址，然后直接通过codeBegin地址减去pImageBuffer的首地址即可；
//
//	//ImageBuffer-->NewBuffer
//	size = ImageBuffertoFileBuffer(pImageBuffer, &pNewBuffer);
//	if (size == 0 || !pNewBuffer)
//	{
//		cout << "ImageBuffer-->NewBuffer失败" << endl;
//		delete[]pFileBuffer;
//		delete[]pImageBuffer;
//		return;
//	}
//
//	//NewBuffer-->文件
//	isOK = MemoryToFile(pNewBuffer, size, path);
//	if (isOK)
//	{
//		cout << "修改代码添加SHELLCODE 存盘成功" << endl;
//		return;
//	}
//
//	//释放内存
//	delete[]pFileBuffer;
//	delete[]pImageBuffer;
//	delete[]pNewBuffer;
//}

DWORD Align(DWORD size, DWORD ALIGN_BASE)
{
	assert(0 != ALIGN_BASE);
	if (size % ALIGN_BASE)
	{
		size = (size / ALIGN_BASE + 1) * ALIGN_BASE;
	}
	return size;
}

DWORD Alignment(DWORD alignment_value, DWORD addend, DWORD address)
{
	int n = 0;
	if (addend / alignment_value)
	{
		if (addend % alignment_value)
		{
			n = addend / alignment_value + 1;
		}
		else
		{
			n = addend / alignment_value;
		}
	}
	else
	{
		if (addend)
			n = 1;
		else
			n = 0;
	}
	address += n * alignment_value;
	return address;
}

//添加节的步骤：
//	1. 自定义添加节的大小（最好是对齐的）
//	2. 读取exe到Filebuffer
//	3. 创建一个大小 = filesize + 自定义节大小的动态内存  ----》 Imagebuffer
//  4. 复制Filebuffer到Imagebuffer
//  5. 判断大小是否足够放节表*2
//  6. 如果有足够位置放， 复制第一个节到我们创新节的地方，复制大小为一个section大小
//  7. 设置新节的属性
//		1. Name是字符串，8个字节
//		2. VirtualSize 和 Sizeofrawdata  为你自己定义的大小
//		3. Virtualaddress 为上一个节的Virtualaddress + VirtualSize 要内存对齐的
//		4. Pointertorawdata 为上一个节的Pointertorawdata + Sizeofrawdata  要文件对齐
//		5. Numberofsection 需要 +1
//      6. Sizeofimage 为 原来的大小 + 新节的大小   需要内存对齐
//  8. 设置新节后一个节全为0
//  9. 存盘

DWORD AddNewSection(const char* file_path, PVOID pFileBuffer, PVOID* pNewFileBuffer)
{
	LPVOID pImageBUffer;
	size_t filesize = 0;
	size_t ImageBufferSize = 0;
	
	filesize = ReadpeFile(file_path, &pFileBuffer);
	
	if (!filesize)
	{
		cout << "读取文件失败" << endl;
	}
	if (!pFileBuffer)
	{
		cout << "pFileBuffer创建失败" << endl;
		delete[]pFileBuffer;
	}

	size_t AddSecTotal = filesize + 0x1000;
	

	pImageBUffer = malloc(AddSecTotal);

	if (!pImageBUffer)
	{
		printf("(TestAddSection)Allocate dynamic memory failed!\n");
		return 0;
	}
	
	//初始化ImageBuffer
	memset(pImageBUffer, 0, AddSecTotal);
	//将FileBuffer中的数据复制到ImageBuffer中，大小为Filebuffer
	memcpy(pImageBUffer, pFileBuffer, filesize);


	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)pImageBUffer;

	if (*((PDWORD)((DWORD)pImageBUffer + DosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("(TestAddSection)Not a valid PE flag!\n");
		free(pImageBUffer);
		return -1;
	}

	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)(((DWORD)pImageBUffer + DosHeader->e_lfanew));

	PIMAGE_FILE_HEADER PeHeader = (PIMAGE_FILE_HEADER)(((DWORD)NtHeader + 4));
	PIMAGE_OPTIONAL_HEADER32 OpHeader = (PIMAGE_OPTIONAL_HEADER32)(((DWORD)pImageBUffer + DosHeader->e_lfanew) + 4 + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER SecHeader = (PIMAGE_SECTION_HEADER)(((DWORD)OpHeader + PeHeader->SizeOfOptionalHeader));

	//新节的指针
	PIMAGE_SECTION_HEADER newSec = SecHeader;
	for (DWORD i = 0; i < PeHeader->NumberOfSections; i++, newSec++)
	{
		
	}

	PIMAGE_SECTION_HEADER LastSec = SecHeader + (PeHeader->NumberOfSections - 1);
	//PIMAGE_SECTION_HEADER LastSec = newSec - 1;

	//复制.text内容到新结
	memset(newSec, 0, 0x1000);
	memcpy(newSec, SecHeader, sizeof(IMAGE_SECTION_HEADER));


	//判断SizeOFHeader能否放下多余两个节区（一个新增节区，一个全0节区代表区块结束）
	//分三种情况：1.节表后直接可以放下两个节区 2.节表后放不下，但是dos头后pe前可放下 3.前两种情况都不行，需扩大最后一个节把代码填进去
	//就讨论第一种情况吧...

	//所有头的大小 - (新节的头 - pAddSectionTemp) -> 新节的头 - pAddSectionTemp就是偏移
	if (80 <= (OpHeader->SizeOfHeaders - ((DWORD)(newSec - pImageBUffer))))
	{
		printf("Enough.\n");
		//得到最后一个节的信息
		newSec-- ;
		//填充节

		//Alignment返回值是上一个节表 + 对齐值 = 新节表偏移地址    ret_loc3 = 新节表偏移地址
		//DWORD ret_loc3 = Alignment(OpHeader->SectionAlignment, (DWORD)LastSec->Misc.VirtualSize, (DWORD)LastSec->PointerToRawData);
		//memset(((PBYTE)(DWORD)pImageBUffer + ret_loc3), 0, 0x1000);
		
		// 计算按文件对齐方式对齐后的Raw Data偏移
		DWORD rawOffset = (LastSec->PointerToRawData + LastSec->SizeOfRawData + OpHeader->FileAlignment - 1) / OpHeader->FileAlignment * OpHeader->FileAlignment;

		// 计算按内存对齐方式对齐后的Virtual Address
		DWORD virtAddress = (LastSec->VirtualAddress + LastSec->Misc.VirtualSize + OpHeader->SectionAlignment - 1) / OpHeader->SectionAlignment * OpHeader->SectionAlignment;

		//在新的Raw Data偏移处填充0
		memset((PBYTE)pImageBUffer + rawOffset, 0, 0x1000);

	
		//改节数目
		PeHeader->NumberOfSections = PeHeader->NumberOfSections + 1;
		//填充节表
		//pSectionHeaderTemp指向新节表
		newSec++;
		memcpy(newSec, SecHeader, IMAGE_SIZEOF_SECTION_HEADER);
		memcpy(newSec, ".addsec", 8);

		//newSec->VirtualAddress = ret_loc3;
		//newSec->VirtualAddress = Align(LastSec->VirtualAddress + LastSec->Misc.VirtualSize, OpHeader->SectionAlignment);
		newSec->VirtualAddress = virtAddress;
		newSec->SizeOfRawData = 0x1000;
		//newSec->PointerToRawData = ret_loc3;
		//newSec->PointerToRawData = LastSec->PointerToRawData + LastSec->SizeOfRawData, OpHeader->FileAlignment;
		newSec->PointerToRawData = rawOffset;
		newSec->Misc.VirtualSize = 0x1000;
		//OpHeader->SizeOfImage = AddSecTotal;
		

		
		OpHeader->SizeOfImage = Align(OpHeader->SizeOfImage + 1000, OpHeader->SectionAlignment);

	


		//后面再添IMAGE_SIZEOF_SECTION_HEADER个0
		newSec++;
		memset(newSec, 0, IMAGE_SIZEOF_SECTION_HEADER);
	}
	else
	{
		free(pImageBUffer);
		printf("Insufficient.\n");
	}



	size_t ret_loc4 = MemoryToFile(pImageBUffer, AddSecTotal, write_addsec_file_path);
	if (!ret_loc4)
	{
		printf("(TestAddSection)Store memory failed.\n");
		return 0;
	}

	*pNewFileBuffer = pImageBUffer; //暂存的数据传给参数后释放

	//主函数free了
	//free(pAddSectionTemp);
	pImageBUffer = NULL;

	return AddSecTotal;
}

VOID operate()
{
	PVOID pFileBuffer = NULL;
	PVOID pNewFileBuffer = NULL;
	PVOID pImageBuffer = NULL;

	DWORD ret5 = AddNewSection(file_path, &pFileBuffer, &pNewFileBuffer);
	printf("TestAddSection Buffer: %#x\n", ret5);

	free(pFileBuffer);
	free(pNewFileBuffer);
	free(pImageBuffer);
}

//扩大节
// 1. 打开Filebuffer
// 2. 创建一块新的内存 大小为 sizeofimage + 想添加的大小（内存对齐）
// 3. 
DWORD EnlargeSection()
{
	LPVOID pFileBuffer;
	LPVOID pImageBuffer;
	LPVOID NewBuffer;
	size_t ImageBufferSize = 0;

	size_t filesize = ReadpeFile(file_path, &pFileBuffer);

	if (!filesize)
	{
		cout << "读取文件失败" << endl;
	}
	if (!pFileBuffer)
	{
		cout << "pFileBuffer创建失败" << endl;
		delete[]pFileBuffer;
	}

	//目前是Filebuffer的状态
	PIMAGE_DOS_HEADER pDos = NULL;
	PIMAGE_NT_HEADERS pNT = NULL;
	PIMAGE_FILE_HEADER pFile = NULL;
	PIMAGE_OPTIONAL_HEADER pOption = NULL;
	PIMAGE_SECTION_HEADER pSection = NULL;

	pDos = (PIMAGE_DOS_HEADER)((PWORD)(DWORD)pFileBuffer);

	pNT = (PIMAGE_NT_HEADERS)((PWORD)((DWORD)pFileBuffer + pDos->e_lfanew));
	pFile = (PIMAGE_FILE_HEADER)((DWORD)pNT + 4);
	pOption = (PIMAGE_OPTIONAL_HEADER)((PWORD)((DWORD)pFile + IMAGE_SIZEOF_FILE_HEADER));
	pSection = (PIMAGE_SECTION_HEADER)((DWORD)pOption + pFile->SizeOfOptionalHeader);

	//创建一块内存ImageBuffer

	size_t sizee = pOption->SizeOfImage + 0x1000;
	pImageBuffer = malloc(sizee);
	memset(pImageBuffer, 0, sizee);

	//拷贝头到ImageBuffer
	memcpy(pImageBuffer, pFileBuffer, pOption->SizeOfHeaders);

	//拷贝节表
	for (size_t i = 0; i < pFile->NumberOfSections; ++i)
	{
		memcpy((BYTE*)((DWORD_PTR)pImageBuffer + pSection[i].VirtualAddress), (BYTE*)((DWORD_PTR)pFileBuffer + pSection[i].PointerToRawData), pSection[i].SizeOfRawData);
	}


	//解析ImageBuffer的头
	pDos = (PIMAGE_DOS_HEADER)((PWORD)(DWORD)pImageBuffer);

	pNT = (PIMAGE_NT_HEADERS)((PWORD)((DWORD)pImageBuffer + pDos->e_lfanew));
	pFile = (PIMAGE_FILE_HEADER)((DWORD)pNT + 4);
	pOption = (PIMAGE_OPTIONAL_HEADER)((PWORD)((DWORD)pFile + IMAGE_SIZEOF_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSection1 = (PIMAGE_SECTION_HEADER)((DWORD)pOption + pFile->SizeOfOptionalHeader);

	//扩大最后一个节，修改属性
	PIMAGE_SECTION_HEADER LastSec = pSection1;

	//得到最后一个节
	for (int i = 1; i < pFile->NumberOfSections; i++, LastSec++)
	{

	}


	pOption->SizeOfImage = sizee;
	LastSec->Misc.VirtualSize += 0x1000;
	LastSec->SizeOfRawData += 0x1000;

	size_t  Newbuffersize = ImageBuffertoFileBuffer(pImageBuffer, &NewBuffer);


	BOOL isOk = MemoryToFile(NewBuffer, Newbuffersize, write_addsec_file_path);
	if (isOk == 1)
	{
		printf("存盘成功\n");
	}

	
	free(pFileBuffer);
	free(pImageBuffer);
	free(NewBuffer);
	return sizee;

}

DWORD 合并Section()
{
	LPVOID pFileBuffer;
	LPVOID pImageBuffer;
	LPVOID NewBuffer;
	size_t ImageBufferSize = 0;

	size_t filesize = ReadpeFile(file_path, &pFileBuffer);

	if (!filesize)
	{
		cout << "读取文件失败" << endl;
	}
	if (!pFileBuffer)
	{
		cout << "pFileBuffer创建失败" << endl;
		delete[]pFileBuffer;
	}

	//目前是Filebuffer的状态
	PIMAGE_DOS_HEADER pDos = NULL;
	PIMAGE_NT_HEADERS pNT = NULL;
	PIMAGE_FILE_HEADER pFile = NULL;
	PIMAGE_OPTIONAL_HEADER pOption = NULL;
	PIMAGE_SECTION_HEADER pSection = NULL;

	pDos = (PIMAGE_DOS_HEADER)((PWORD)(DWORD)pFileBuffer);

	pNT = (PIMAGE_NT_HEADERS)((PWORD)((DWORD)pFileBuffer + pDos->e_lfanew));
	pFile = (PIMAGE_FILE_HEADER)((DWORD)pNT + 4);
	pOption = (PIMAGE_OPTIONAL_HEADER)((PWORD)((DWORD)pFile + IMAGE_SIZEOF_FILE_HEADER));
	pSection = (PIMAGE_SECTION_HEADER)((DWORD)pOption + pFile->SizeOfOptionalHeader);

	size_t sizee = pOption->SizeOfImage;
	pImageBuffer = malloc(sizee);
	memset(pImageBuffer, 0, sizee);

	//拷贝头到ImageBuffer
	memcpy(pImageBuffer, pFileBuffer, pOption->SizeOfHeaders);

	//拷贝节表
	for (size_t i = 0; i < pFile->NumberOfSections; ++i)
	{
		memcpy((BYTE*)((DWORD_PTR)pImageBuffer + pSection[i].VirtualAddress), (BYTE*)((DWORD_PTR)pFileBuffer + pSection[i].PointerToRawData), pSection[i].SizeOfRawData);
	}


	//解析ImageBuffer的头
	pDos = (PIMAGE_DOS_HEADER)((PWORD)(DWORD)pImageBuffer);

	pNT = (PIMAGE_NT_HEADERS)((PWORD)((DWORD)pImageBuffer + pDos->e_lfanew));
	pFile = (PIMAGE_FILE_HEADER)((DWORD)pNT + 4);
	pOption = (PIMAGE_OPTIONAL_HEADER)((PWORD)((DWORD)pFile + IMAGE_SIZEOF_FILE_HEADER));
	PIMAGE_SECTION_HEADER pSection1 = (PIMAGE_SECTION_HEADER)((DWORD)pOption + pFile->SizeOfOptionalHeader);


	//DWORD dwMax = pSection1[pFile->NumberOfSections - 1].Misc.VirtualSize > pSection1[pFile->NumberOfSections - 1].SizeOfRawData ? pSection1[pFile->NumberOfSections - 1].Misc.VirtualSize : pSection1[pFile->NumberOfSections - 1].SizeOfRawData;
	pSection1->Misc.VirtualSize = pSection1->SizeOfRawData = pOption->SizeOfImage - pSection1->VirtualAddress;
	for (size_t i = 1; i < pFile->NumberOfSections; i++)
	{
		pSection1->Characteristics |= pSection1[i].Characteristics;
	}

	//清空节表项
	memset(pSection1 + 1, 0, IMAGE_SIZEOF_SECTION_HEADER * (pFile->NumberOfSections - 1));

	pFile->NumberOfSections = 1;
	

	size_t  Newbuffersize = ImageBuffertoFileBuffer(pImageBuffer, &NewBuffer);

	BOOL isOk = MemoryToFile(NewBuffer, Newbuffersize, write_addsec_file_path);
	if (isOk == 1)
	{
		printf("存盘成功\n");
	}


	free(pFileBuffer);
	free(pImageBuffer);
	free(NewBuffer);
	return sizee;





}

int main()
{
	//operate();
	//PrintExportTable();
	//PrintHeaders();
	//EnlargeSection();
	//合并Section();
	//PrintRelocTable();
	//operate();

	PrintImportTable();
	//GetFunctionAddrByName("BridgeAlloc"); 
	//cout << "Done is ok" << endl;
	getchar();
	return 0;
}




