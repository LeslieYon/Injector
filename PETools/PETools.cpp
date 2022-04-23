//
// Created by Mr.Yll on 2022/3/27.
//

#include "PETools.h"
#include "..\\Remote.h"

const char *Err_Read_Invalid = "OpenPEFile Error : Can not open file to read.";
const char *Err_Write_Invalid = "OpenPEFile Error : Can not open file to write.";
const char *Err_Size_Invalid = "OpenPEFile Error : File Size is too small.";
const char *Err_e_magic_Invalid = "OpenPEFile Error : e_magic is invalid.";
const char *Err_Buffer_Invalid = "Buff Error : Buffer is invalid.";
const char *Err_Type_Unknown = "BufferType Error : Buffer type is unknown.";
const char *Err_NTSignature_Unknown = "GetBufferInfo : NT header signature is invalid.";
const char *Err_pExportTable_Invalid = "GetBufferInfo : Pointer to Export Table is invalid.";
const char *Err_File_NULL = "ReadFileToFileBuffer : File handle is NULL.";
const char *Err_FileSize_Unclear = "ReadFileToFileBuffer : File Size is not clear.";
const char *Err_Memory_Invalid = "Error : Memory could not be allocated.";
const char *Err_FileBuffer_Invalid = "FileBufferToImageBuffer : FileBuffer is invalid.";
const char *Err_SizeOfHeaders_OutOfBounds = "Section Copy Error : Size of headers is too large.";
const char *Err_AddressOfSection_OutOfBounds = "Section Copy Error : Address Of Section is beyond limit.";
const char *Err_SizeOfSection_OutOfBounds = "Section Copy Error : Size Of section is too large.";
const char *Err_ImageBuffer_Invalid = "ImageBufferToFileBuffer : ImageBuffer is invalid.";
const char *Err_HeadersSize_Unknown = "AddSection Error : One of the Section size is Unknown.";
const char *Err_BlankArea_Small = "AddSection Error : Blank area is too small.";
const char *Err_e_lfanew_Invalid = "GetBufferInfo Error : NT header offset is invalid.";
const char *Err_SectionName_Invalid = "Section Name String Error : Section name is invalid.";
const char *Err_RVA2FOA_Par_Invalid = "RVA2FOA : pPEBuffer invalid.";
const char *Err_FOA2RVA_Par_Invalid = "FOA2RVA : pPEBuffer invalid.";
const char *Err_RVA_Invalid = "RVA2FOA : Could not convert RVA to FOA , RVA is invalid.";
const char *Err_FOA_Invalid = "FOA2RVA : Could not convert FOA to RVA , FOA is invalid.";
const char *Err_FuncName_Invalid = "GetFuncFOAWithName : Function name is invalid.";
const char *Err_RebudRT_NewImageBase_Invalid = "RebuildRelocationTable : Could not rebulid relocation table , because NewImageBase is invalid.";

void Error(const char *Message) {
    printf(Message);
    printf("\n");
    //ExitProcess(-1);
}

DWORD GetPEFileSize(FILE *File) {
    DWORD OriOffset = ftell(File);
    fseek(File, 0, SEEK_END);
    DWORD FileSize = ftell(File);
    fseek(File, OriOffset, SEEK_SET);
    return FileSize;
}

FILE *OpenPEFile(const char *FilePath) noexcept(false) {
    if (!FilePath || !*FilePath) Error(Err_Read_Invalid);
    FILE *PEFile = nullptr;
    if (fopen_s(&PEFile, FilePath, "rb")) {
        _set_errno(0);
        Error(Err_Read_Invalid);
    }
    if (GetPEFileSize(PEFile) < sizeof(_IMAGE_DOS_HEADER) + IMAGE_SIZEOF_FILE_HEADER + sizeof(_IMAGE_OPTIONAL_HEADER)) {
        fclose(PEFile);
        Error(Err_Size_Invalid);
    }
    WORD e_magic = 0;
    fread(&e_magic, sizeof(WORD), 1, PEFile);
    if (e_magic != IMAGE_DOS_SIGNATURE) {
        fclose(PEFile);
        Error(Err_e_magic_Invalid);
    }
    fseek(PEFile, 0, SEEK_SET);
    return PEFile;
}

void *ReadFileToFileBuffer(FILE *File) {
    if (!File) Error(Err_File_NULL);
    size_t FileSize = GetPEFileSize(File);
    void *FileBuffer = malloc(FileSize);
    if (!FileBuffer) Error(Err_Memory_Invalid);
    memset(FileBuffer, NULL, FileSize);
    fread(FileBuffer, FileSize, 1, File);
    PointersToPEBuffer FileBufferInfo;
    //GetBufferInfo(FileBuffer, FileBufferInfo, BufferType::FileBuffer);
    //if (FileSize != FileBufferInfo.PEBufferSize) Error(Err_FileSize_Unclear);
    return FileBuffer;
}

PointersToPEBuffer &
__fastcall GetBufferInfo(const void *Buffer, PointersToPEBuffer &PPEFile, BufferType Type, bool IsExtra) {
    if (!Buffer) Error(Err_Buffer_Invalid);
    PPEFile.PDOSHeader = (_IMAGE_DOS_HEADER *) Buffer;
    if (PPEFile.PDOSHeader->e_lfanew < sizeof(IMAGE_DOS_HEADER))
        Error(Err_e_lfanew_Invalid);
    PPEFile.PNTHeader = (_IMAGE_NT_HEADERS *)
            ((DWORD64) PPEFile.PDOSHeader + PPEFile.PDOSHeader->e_lfanew);
    if (PPEFile.PNTHeader->Signature != IMAGE_NT_SIGNATURE)
        Error(Err_NTSignature_Unknown);
    PPEFile.PPEHeader = (_IMAGE_FILE_HEADER *)
            ((DWORD64) PPEFile.PNTHeader + sizeof(PPEFile.PNTHeader->Signature));
    PPEFile.POptionHeader = (_IMAGE_OPTIONAL_HEADER *) (PPEFile.PPEHeader + 1);
    PPEFile.PSectionTable = (_IMAGE_SECTION_HEADER *)
            ((DWORD64) PPEFile.POptionHeader + PPEFile.PPEHeader->SizeOfOptionalHeader);
    if (Type == ImageBuffer) {
        PPEFile.PEBufferSize = PPEFile.POptionHeader->SizeOfImage;
        if (IsExtra) {
            if (PPEFile.POptionHeader->DataDirectory[0].VirtualAddress >= PPEFile.POptionHeader->SizeOfImage)
                Error(Err_pExportTable_Invalid);
            if (PPEFile.POptionHeader->DataDirectory[0].VirtualAddress)
            {
                PPEFile.pExportTable = (_IMAGE_EXPORT_DIRECTORY *)
                        ((char *) Buffer + PPEFile.POptionHeader->DataDirectory[0].VirtualAddress);
            }
            if (PPEFile.POptionHeader->DataDirectory[5].VirtualAddress)
            {
                PPEFile.pRelocationTable = (_IMAGE_BASE_RELOCATION *)
                        ((DWORD) PPEFile.POptionHeader->DataDirectory[5].VirtualAddress + (DWORD64) Buffer);
            }
            if (PPEFile.POptionHeader->DataDirectory[1].VirtualAddress)
            {
                PPEFile.pImportTable = (_IMAGE_IMPORT_DESCRIPTOR *) (
                        (DWORD) PPEFile.POptionHeader->DataDirectory[1].VirtualAddress + (DWORD64) Buffer);
            }
        }
    } else if (Type == FileBuffer) {
        _IMAGE_SECTION_HEADER *PLastSectionTable = PPEFile.PSectionTable + PPEFile.PPEHeader->NumberOfSections - 1;
        PPEFile.PEBufferSize = PLastSectionTable->PointerToRawData + PLastSectionTable->SizeOfRawData;
        if (IsExtra) {
            if (PPEFile.POptionHeader->DataDirectory[0].VirtualAddress)
            {
                PPEFile.pExportTable = (_IMAGE_EXPORT_DIRECTORY *)
                        ((char *) Buffer +
                         (DWORD64) RVA2FOA((void *) PPEFile.POptionHeader->DataDirectory[0].VirtualAddress, Buffer));
            }
            if (PPEFile.POptionHeader->DataDirectory[5].VirtualAddress)
            {
                PPEFile.pRelocationTable = (_IMAGE_BASE_RELOCATION *)
                        RVA2FOA((void *) ((DWORD) (PPEFile.POptionHeader->DataDirectory[5].VirtualAddress) +
                                          (DWORD64) Buffer), Buffer, Buffer);
            }
            if (PPEFile.POptionHeader->DataDirectory[1].VirtualAddress)
            {
                PPEFile.pImportTable = (_IMAGE_IMPORT_DESCRIPTOR *) RVA2FOA(
                        (char *) PPEFile.POptionHeader->DataDirectory[1].VirtualAddress + (DWORD64) Buffer, Buffer, Buffer);
            }
        }
    } else Error(Err_Type_Unknown);
    return PPEFile;
}

void *FileBufferToImageBuffer(const void *FileBuffer) {
    if (!FileBuffer) Error(Err_FileBuffer_Invalid);
    PointersToPEBuffer FileBufferInfo;
    GetBufferInfo(FileBuffer, FileBufferInfo, BufferType::FileBuffer);
    void *ImageBuffer = malloc(FileBufferInfo.POptionHeader->SizeOfImage);
    if (!ImageBuffer) Error(Err_Memory_Invalid);
    memset(ImageBuffer, NULL, FileBufferInfo.POptionHeader->SizeOfImage);
    //由于部分PE文件即使头部有一部分在某个节中，也可以正常运行，因此下面的判断暂时忽略
    //if (FileBufferInfo.POptionHeader->SizeOfHeaders > FileBufferInfo.PSectionTable->PointerToRawData)
    //	Error(Err_SizeOfHeaders_OutOfBounds);

    memcpy(ImageBuffer, FileBuffer, FileBufferInfo.POptionHeader->SizeOfHeaders);
    PointersToPEBuffer ImageBufferInfo;
    GetBufferInfo(ImageBuffer, ImageBufferInfo, BufferType::ImageBuffer);
    for (DWORD i = 0; i < ImageBufferInfo.PPEHeader->NumberOfSections; i++, ImageBufferInfo.PSectionTable++) {
        if (ImageBufferInfo.PSectionTable->PointerToRawData >= FileBufferInfo.PEBufferSize ||
            ImageBufferInfo.PSectionTable->VirtualAddress >= ImageBufferInfo.POptionHeader->SizeOfImage)
            Error(Err_AddressOfSection_OutOfBounds);
        if (i + 1 == ImageBufferInfo.PPEHeader->NumberOfSections) {
            if (ImageBufferInfo.PSectionTable->SizeOfRawData >
                FileBufferInfo.PEBufferSize - ImageBufferInfo.PSectionTable->PointerToRawData)
                Error(Err_SizeOfSection_OutOfBounds);
        } else {
            if (ImageBufferInfo.PSectionTable->SizeOfRawData >
                (ImageBufferInfo.PSectionTable + 1)->PointerToRawData - ImageBufferInfo.PSectionTable->PointerToRawData)
                Error(Err_SizeOfSection_OutOfBounds);
        }
        memcpy(
                (char *) ImageBuffer + ImageBufferInfo.PSectionTable->VirtualAddress,
                (char *) FileBuffer + ImageBufferInfo.PSectionTable->PointerToRawData,
                ImageBufferInfo.PSectionTable->SizeOfRawData);
    }
    ImageBufferInfo.PSectionTable -= ImageBufferInfo.PPEHeader->NumberOfSections;
    return ImageBuffer;
}

void *ImageBufferToFileBuffer(const void *ImageBuffer) {
    if (!ImageBuffer) Error(Err_ImageBuffer_Invalid);
    PointersToPEBuffer ImageBufferInfo;
    GetBufferInfo(ImageBuffer, ImageBufferInfo, BufferType::ImageBuffer);
    PointersToPEBuffer FileBufferInfo;
    GetBufferInfo(ImageBuffer, FileBufferInfo, BufferType::FileBuffer); //临时获取FileBuffer大小
    void *FileBuffer = malloc(FileBufferInfo.PEBufferSize);
    if (!FileBuffer) Error(Err_Memory_Invalid);
    memset(FileBuffer, NULL, FileBufferInfo.PEBufferSize);
    //由于部分PE文件即使头部有一部分在某个节中，也可以正常运行，因此下面的判断暂时忽略
    //if (FileBufferInfo.POptionHeader->SizeOfHeaders > FileBufferInfo.PSectionTable->PointerToRawData)
    //	Error(Err_SizeOfHeaders_OutOfBounds);

    memcpy(FileBuffer, ImageBuffer, ImageBufferInfo.POptionHeader->SizeOfHeaders);
    GetBufferInfo(FileBuffer, FileBufferInfo, BufferType::FileBuffer);
    for (DWORD i = 0; i < FileBufferInfo.PPEHeader->NumberOfSections; i++, FileBufferInfo.PSectionTable++) {
        if (FileBufferInfo.PSectionTable->PointerToRawData >= FileBufferInfo.PEBufferSize ||
            FileBufferInfo.PSectionTable->VirtualAddress >= FileBufferInfo.POptionHeader->SizeOfImage)
            Error(Err_AddressOfSection_OutOfBounds);
        if (i + 1 == ImageBufferInfo.PPEHeader->NumberOfSections) {
            if (FileBufferInfo.PSectionTable->SizeOfRawData >
                FileBufferInfo.PEBufferSize - FileBufferInfo.PSectionTable->PointerToRawData)
                Error(Err_SizeOfSection_OutOfBounds);
        } else {
            if (FileBufferInfo.PSectionTable->SizeOfRawData >
                (FileBufferInfo.PSectionTable + 1)->PointerToRawData - FileBufferInfo.PSectionTable->PointerToRawData)
                Error(Err_SizeOfSection_OutOfBounds);
        }
        memcpy((char *) FileBuffer + FileBufferInfo.PSectionTable->PointerToRawData,
               (char *) ImageBuffer + FileBufferInfo.PSectionTable->VirtualAddress,
               FileBufferInfo.PSectionTable->SizeOfRawData);
    }
    FileBufferInfo.PSectionTable -= FileBufferInfo.PPEHeader->NumberOfSections;
    return FileBuffer;
}

void SaveFileBufferToDisk(const void *FileBuffer, const char *NewFilePath) {
    FILE *NewFile = nullptr;
    if (fopen_s(&NewFile, NewFilePath, "wb"))//fopen_s函数在低版本VS中可能引起兼容性问题
    {
        _set_errno(0);
        Error(Err_Write_Invalid);
    }
    PointersToPEBuffer FileBufferInfo;
    GetBufferInfo(FileBuffer, FileBufferInfo, BufferType::FileBuffer);
    fwrite(FileBuffer, FileBufferInfo.PEBufferSize, 1, NewFile);
    fclose(NewFile);
}

_IMAGE_SECTION_HEADER *
AddSection(void **PointerToPBuffer, BufferType Type, const char *SectionName, DWORD Characteristics,
           DWORD SectionSize, const void *NewSectionData) {
    const DWORD IMAGE_SIZEOF_DOSHEADER = sizeof(IMAGE_DOS_HEADER);
    if (!PointerToPBuffer || !*PointerToPBuffer) Error(Err_Buffer_Invalid);
    void *Buffer = *PointerToPBuffer;
    if (!SectionName) Error(Err_SectionName_Invalid);
    if (!Buffer) Error(Err_Buffer_Invalid);
    PointersToPEBuffer BufferInfo;
    GetBufferInfo(Buffer, BufferInfo, Type);
    DWORD SizeOfRawHeaders = (BufferInfo.PDOSHeader->e_lfanew) +
                             (sizeof(BufferInfo.PNTHeader->Signature)) +
                             (IMAGE_SIZEOF_FILE_HEADER) +
                             (BufferInfo.PPEHeader->SizeOfOptionalHeader) +
                             (IMAGE_SIZEOF_SECTION_HEADER * BufferInfo.PPEHeader->NumberOfSections);
    if (SizeOfRawHeaders > BufferInfo.POptionHeader->SizeOfHeaders)
        Error(Err_HeadersSize_Unknown);
    for (DWORD i = SizeOfRawHeaders; i < SizeOfRawHeaders + IMAGE_SIZEOF_SECTION_HEADER * 2; i++) {
        if (((BYTE *) Buffer)[i]) {
            if (BufferInfo.PDOSHeader->e_lfanew - IMAGE_SIZEOF_DOSHEADER < IMAGE_SIZEOF_SECTION_HEADER * 2)
                Error(Err_BlankArea_Small);
            memmove(
                    (char *) Buffer + IMAGE_SIZEOF_DOSHEADER,
                    (char *) Buffer + BufferInfo.PDOSHeader->e_lfanew,
                    SizeOfRawHeaders - BufferInfo.PDOSHeader->e_lfanew);
            memset(
                    (char *) Buffer + SizeOfRawHeaders - (BufferInfo.PDOSHeader->e_lfanew - IMAGE_SIZEOF_DOSHEADER),
                    NULL,
                    BufferInfo.PDOSHeader->e_lfanew - IMAGE_SIZEOF_DOSHEADER
            );
            BufferInfo.PDOSHeader->e_lfanew = IMAGE_SIZEOF_DOSHEADER;
            GetBufferInfo(Buffer, BufferInfo, Type);
            break;
        }
    }
    DWORD SectionSizeAlignment = (Type == BufferType::FileBuffer) ?
                                 (SectionSize + BufferInfo.POptionHeader->FileAlignment - 1) /
                                 BufferInfo.POptionHeader->FileAlignment * BufferInfo.POptionHeader->FileAlignment :
                                 (SectionSize + BufferInfo.POptionHeader->SectionAlignment - 1) /
                                 BufferInfo.POptionHeader->SectionAlignment *
                                 BufferInfo.POptionHeader->SectionAlignment;
    void *NewBuffer = malloc(BufferInfo.PEBufferSize + SectionSizeAlignment);
    memset(NewBuffer, NULL, BufferInfo.PEBufferSize + SectionSizeAlignment);
    memcpy(NewBuffer, Buffer, BufferInfo.PEBufferSize);
    Buffer = NewBuffer;
    GetBufferInfo(Buffer, BufferInfo, Type);
    IMAGE_SECTION_HEADER *pNewSectionTable = BufferInfo.PSectionTable + BufferInfo.PPEHeader->NumberOfSections++;
    pNewSectionTable->PointerToRawData =
            (BufferInfo.PSectionTable + BufferInfo.PPEHeader->NumberOfSections - 2)->PointerToRawData +
            (BufferInfo.PSectionTable + BufferInfo.PPEHeader->NumberOfSections - 2)->SizeOfRawData;
    pNewSectionTable->Misc.VirtualSize = SectionSize;
    if (Type == BufferType::FileBuffer) {
        pNewSectionTable->SizeOfRawData = SectionSizeAlignment;
        GetBufferInfo(Buffer, BufferInfo, BufferType::ImageBuffer);
        pNewSectionTable->VirtualAddress = BufferInfo.PEBufferSize;
        void *pNewSection = (char *) Buffer + pNewSectionTable->PointerToRawData;
        if (NewSectionData)
            memcpy(pNewSection, NewSectionData, SectionSize);
        GetBufferInfo(Buffer, BufferInfo, Type);
        BufferInfo.POptionHeader->SizeOfImage += (SectionSize + BufferInfo.POptionHeader->SectionAlignment - 1) /
                                                 BufferInfo.POptionHeader->SectionAlignment *
                                                 BufferInfo.POptionHeader->SectionAlignment;
    } else if (Type == BufferType::ImageBuffer) {
        pNewSectionTable->SizeOfRawData =
                (SectionSize + BufferInfo.POptionHeader->FileAlignment - 1) / BufferInfo.POptionHeader->FileAlignment *
                BufferInfo.POptionHeader->FileAlignment;
        pNewSectionTable->VirtualAddress = BufferInfo.PEBufferSize;
        void *pNewSection = (char *) Buffer + pNewSectionTable->VirtualAddress;
        if (NewSectionData)
            memcpy(pNewSection, NewSectionData, SectionSize);
        BufferInfo.POptionHeader->SizeOfImage += SectionSizeAlignment;
    }
    memcpy(pNewSectionTable->Name, SectionName,
           strlen(SectionName) > IMAGE_SIZEOF_SHORT_NAME ? IMAGE_SIZEOF_SHORT_NAME : strlen(SectionName));
    pNewSectionTable->Characteristics = Characteristics;
    free(*PointerToPBuffer);
    *PointerToPBuffer = Buffer;
    return pNewSectionTable;
}

_IMAGE_SECTION_HEADER *MergeSection(void **PointerToPBuffer, BufferType Type, const char *NewSectionName) {
    if (!PointerToPBuffer || !*PointerToPBuffer) Error(Err_Buffer_Invalid);
    void *PBuffer = *PointerToPBuffer;
    if (!NewSectionName) Error(Err_SectionName_Invalid);
    if (Type == BufferType::FileBuffer) {
        PBuffer = FileBufferToImageBuffer(PBuffer);
    }
    PointersToPEBuffer BufferInfo;
    GetBufferInfo(PBuffer, BufferInfo, BufferType::ImageBuffer);
    DWORD Characteristics = 0x0;
    for (DWORD i = 0; i < BufferInfo.PPEHeader->NumberOfSections; i++, BufferInfo.PSectionTable++) {
        Characteristics |= BufferInfo.PSectionTable->Characteristics;
    }
    BufferInfo.PSectionTable -= BufferInfo.PPEHeader->NumberOfSections;
    _IMAGE_SECTION_HEADER *PNewSection = BufferInfo.PSectionTable;
    PNewSection->Characteristics = Characteristics;
    PNewSection->Misc.VirtualSize =
            (BufferInfo.PSectionTable + BufferInfo.PPEHeader->NumberOfSections - 1)->VirtualAddress +
            (BufferInfo.PSectionTable + BufferInfo.PPEHeader->NumberOfSections - 1)->Misc.VirtualSize
            - PNewSection->VirtualAddress;
    PNewSection->PointerToRawData = PNewSection->VirtualAddress;
    PNewSection->SizeOfRawData =
            (((BufferInfo.PSectionTable + BufferInfo.PPEHeader->NumberOfSections - 1)->VirtualAddress +
              (BufferInfo.PSectionTable + BufferInfo.PPEHeader->NumberOfSections - 1)->Misc.VirtualSize -
              BufferInfo.PSectionTable->VirtualAddress) + (BufferInfo.POptionHeader->FileAlignment - 1))
            / BufferInfo.POptionHeader->FileAlignment * BufferInfo.POptionHeader->FileAlignment;
    memset(PNewSection->Name, 0x0, IMAGE_SIZEOF_SHORT_NAME);
    memcpy(PNewSection->Name, NewSectionName,
           strlen(NewSectionName) > IMAGE_SIZEOF_SHORT_NAME ? IMAGE_SIZEOF_SHORT_NAME : strlen(NewSectionName));
    if (BufferInfo.PPEHeader->NumberOfSections >= 0x1) {
        memset(PNewSection + 1, NULL, IMAGE_SIZEOF_SECTION_HEADER * (BufferInfo.PPEHeader->NumberOfSections - 1));
    }
    BufferInfo.PPEHeader->NumberOfSections = 0x1;
    BufferInfo.POptionHeader->FileAlignment = BufferInfo.POptionHeader->SectionAlignment;
    if (Type == BufferType::FileBuffer) {
        free(*PointerToPBuffer);
        *PointerToPBuffer = PBuffer;
    }
    return PNewSection;
}

void *_fastcall RVA2FOA(void *RVA, const void *pPEBuffer, const void *OffsetBase) {
    if (!pPEBuffer) Error(Err_RVA2FOA_Par_Invalid);
    //if ((void*)((DWORD)RVA - (DWORD)OffsetBase) == NULL) return OffsetBase;    // RVA(0) == FOA(0)  已被包含于下方首部处理中

    PointersToPEBuffer FileBufferInfo;
    //注意：Buffer类型不确定，但在这里不影响函数整体功能，此处假设为FileBuffer
    GetBufferInfo(pPEBuffer, FileBufferInfo, BufferType::FileBuffer);
    if ((DWORD64) RVA < (DWORD64) OffsetBase) Error(Err_RVA_Invalid);
    RVA = (void *) ((DWORD64) RVA - (DWORD64) OffsetBase);
    if ((DWORD64) RVA < FileBufferInfo.POptionHeader->SizeOfHeaders)
        return (void *) ((DWORD64) RVA + (DWORD64) OffsetBase);  // 若RVA在首部，则不经任何处理直接返回
    if ((DWORD64) RVA >= FileBufferInfo.POptionHeader->SizeOfHeaders &&
        (DWORD64) RVA < FileBufferInfo.PSectionTable->VirtualAddress)
        Error(Err_RVA_Invalid); // 若RVA在首部和第一个节的空隙，则判定为无效偏移
    DWORD SizeOfVirtualData = 0;
    for (DWORD i = 0; i < FileBufferInfo.PPEHeader->NumberOfSections; i++, FileBufferInfo.PSectionTable++) {
        SizeOfVirtualData = i + 1 == FileBufferInfo.PPEHeader->NumberOfSections ?
                            FileBufferInfo.PSectionTable->VirtualAddress +
                            (FileBufferInfo.PSectionTable->Misc.VirtualSize +
                             FileBufferInfo.POptionHeader->SectionAlignment - 1) /
                            FileBufferInfo.POptionHeader->SectionAlignment *
                            FileBufferInfo.POptionHeader->SectionAlignment :
                            (FileBufferInfo.PSectionTable + 1)->VirtualAddress;
        if ((DWORD64) RVA >= FileBufferInfo.PSectionTable->VirtualAddress && (DWORD64) RVA < SizeOfVirtualData) {
            if ((DWORD64) RVA <
                FileBufferInfo.PSectionTable->VirtualAddress + FileBufferInfo.PSectionTable->SizeOfRawData) {
                return (void *)
                        ((DWORD64) RVA - FileBufferInfo.PSectionTable->VirtualAddress +
                         FileBufferInfo.PSectionTable->PointerToRawData + (DWORD64) OffsetBase);
            } else {
                Error(Err_RVA_Invalid); //若RVA在当前节和下一节的空隙，则判定为无效偏移
            }
        }
    }
    FileBufferInfo.PSectionTable -= FileBufferInfo.PPEHeader->NumberOfSections;
    Error(Err_RVA_Invalid);
    //return nullptr;
}

void *_fastcall FOA2RVA(void *FOA, const void *pPEBuffer, const void *OffsetBase) {
    if (!pPEBuffer) Error(Err_FOA2RVA_Par_Invalid);
    PointersToPEBuffer FileBufferInfo;
    GetBufferInfo(pPEBuffer, FileBufferInfo, BufferType::FileBuffer);
    if ((DWORD64) FOA < (DWORD64) OffsetBase) Error(Err_FOA_Invalid);
    FOA = (void *) ((DWORD64) FOA - (DWORD64) OffsetBase);
    if ((DWORD64) FOA >= FileBufferInfo.PEBufferSize) Error(Err_FOA_Invalid);
    if ((DWORD64) FOA < FileBufferInfo.POptionHeader->SizeOfHeaders)
        return (void *) ((DWORD64) FOA + (DWORD64) OffsetBase);
    for (DWORD i = 0; i < FileBufferInfo.PPEHeader->NumberOfSections; i++, FileBufferInfo.PSectionTable++) {
        //printf("0x%08X~0x%08X : 0x%08X %s\n",  FileBufferInfo.PSectionTable->PointerToRawData,  FileBufferInfo.PSectionTable->PointerToRawData + FileBufferInfo.PSectionTable->SizeOfRawData, FileBufferInfo.PSectionTable->SizeOfRawData, FileBufferInfo.PSectionTable->Name);
        if ((DWORD64) FOA >= FileBufferInfo.PSectionTable->PointerToRawData && (DWORD64) FOA <
                                                                               FileBufferInfo.PSectionTable->PointerToRawData +
                                                                               FileBufferInfo.PSectionTable->SizeOfRawData) {
            return (void *) ((DWORD64) FOA - FileBufferInfo.PSectionTable->PointerToRawData +
                             FileBufferInfo.PSectionTable->VirtualAddress + (DWORD64) OffsetBase);
        }
    }
    FileBufferInfo.PSectionTable -= FileBufferInfo.PPEHeader->NumberOfSections;
    Error(Err_FOA_Invalid);
    //return nullptr;
}

void *
_fastcall GetFuncFOAWithNameOrdinal(const void *FileBuffer, WORD NameOrdinalOfFunction, void *OffsetBase) {
    if (!FileBuffer) Error(Err_FileBuffer_Invalid);
    PointersToPEBuffer FileBufferInfo;
    GetBufferInfo(FileBuffer, FileBufferInfo, BufferType::FileBuffer, true);
    if (!FileBufferInfo.pExportTable) return OffsetBase;
    if (NameOrdinalOfFunction < FileBufferInfo.pExportTable->Base ||
        NameOrdinalOfFunction > FileBufferInfo.pExportTable->Base + FileBufferInfo.pExportTable->NumberOfFunctions - 1)
        return nullptr;
    WORD *RVAOfNameOrdinals = (WORD *) ((char *) FileBuffer +
                                        (DWORD64) RVA2FOA((void *) FileBufferInfo.pExportTable->AddressOfNameOrdinals,
                                                          FileBuffer));;
    void **RVAOfFunctionsTable = (void **) ((char *) FileBuffer +
                                            (DWORD64) RVA2FOA((void *) FileBufferInfo.pExportTable->AddressOfFunctions,
                                                              FileBuffer));
    char **RVAOfNamesTable = (char **) ((char *) FileBuffer +
                                        (DWORD64) RVA2FOA((void *) FileBufferInfo.pExportTable->AddressOfNames,
                                                          FileBuffer));
    for (DWORD i = 0; i < FileBufferInfo.pExportTable->NumberOfNames; i++) {
        if (NameOrdinalOfFunction - FileBufferInfo.pExportTable->Base == RVAOfNameOrdinals[i]) {
            //printf("0x%08X\n", RVAOfFunctionsTable[RVAOfNameOrdinals[i]]);
            return (void *) ((DWORD64) RVA2FOA(RVAOfFunctionsTable[RVAOfNameOrdinals[i]], FileBuffer) +
                             (DWORD64) OffsetBase);
        }
    }
    //printf("0x%08X\n", RVAOfFunctionsTable[NameOrdinalOfFunction - FileBufferInfo.pExportTable->Base]);
    return (void *) ((DWORD64) RVA2FOA(RVAOfFunctionsTable[NameOrdinalOfFunction - FileBufferInfo.pExportTable->Base],
                                       FileBuffer) + (DWORD64) OffsetBase);
}

void *_fastcall GetFuncFOAWithName(const void *FileBuffer, const char *FunctionName, void *OffsetBase) {
    if (!FunctionName || !*FunctionName) Error(Err_FuncName_Invalid);
    if (!FileBuffer) Error(Err_FileBuffer_Invalid);
    PointersToPEBuffer FileBufferInfo;
    GetBufferInfo(FileBuffer, FileBufferInfo, BufferType::FileBuffer, true);
    if (!FileBufferInfo.pExportTable) return OffsetBase;
    WORD *RVAOfNameOrdinals = (WORD *) ((char *) FileBuffer +
                                        (DWORD64) RVA2FOA((void *) FileBufferInfo.pExportTable->AddressOfNameOrdinals,
                                                          FileBuffer));
    void **RVAOfFunctionsTable = (void **) ((char *) FileBuffer +
                                            (DWORD64) RVA2FOA((void *) FileBufferInfo.pExportTable->AddressOfFunctions,
                                                              FileBuffer));
    char **RVAOfNamesTable = (char **) ((char *) FileBuffer +
                                        (DWORD64) RVA2FOA((void *) FileBufferInfo.pExportTable->AddressOfNames,
                                                          FileBuffer));
    char *RVAOfFunctionName = nullptr;
    for (DWORD i = 0; i < FileBufferInfo.pExportTable->NumberOfNames; i++) {
        RVAOfFunctionName = (char *) FileBuffer + (DWORD64) RVA2FOA((void *) RVAOfNamesTable[i], FileBuffer);
        if (!strcmp(FunctionName, RVAOfFunctionName)) {
            //printf("0x%08X\n", RVAOfFunctionsTable[RVAOfNameOrdinals[i]]);
            return (void *) ((DWORD64) RVA2FOA(RVAOfFunctionsTable[RVAOfNameOrdinals[i]], FileBuffer) +
                             (DWORD64) OffsetBase);
        }
    }
    return OffsetBase;
}

bool _fastcall RebuildRelocationTable(void *pPEBuffer, BufferType Type, void *NewImageBase) {
    if (!pPEBuffer) Error(Err_Buffer_Invalid);
    if (!NewImageBase) Error(Err_RebudRT_NewImageBase_Invalid);
    PointersToPEBuffer BufferInfo;
    GetBufferInfo(pPEBuffer, BufferInfo, Type, true);
    if (BufferInfo.POptionHeader->ImageBase == (DWORD64) NewImageBase) return true; //新旧ImageBase相等时不做任何处理
    if (!BufferInfo.pRelocationTable) //不存在重定位表时仅更改ImageBase
    {
        BufferInfo.POptionHeader->ImageBase = (DWORD64) NewImageBase;
        return false;
    }
    void *pRelocationTableItemOffsetData = nullptr;
    IMAGE_BASE_RELOCATION *Raw_pRelocationTable = BufferInfo.pRelocationTable;
    while (BufferInfo.pRelocationTable->SizeOfBlock &&
           BufferInfo.pRelocationTable->VirtualAddress)  //只有当 基址 和 块大小 都不为0时才判定为有效数据
    {
        for (DWORD i = 0;
             i < (BufferInfo.pRelocationTable->SizeOfBlock - 8) / 2; i++)  //当前块条目数 = ( 当前块大小 - 头部大小 ) / 单个条目大小
        {
            //只有每一条目的二进制 高4位 为0011（十进制3）的时候才判定为有效数据
            if ((0xF000 & *(WORD * )((DWORD64)(BufferInfo.pRelocationTable) + 8 + i * 2)) >> 12 == 3)
            {
                //每一个条目的二进制数据的 低12位 是实际数据
                void *OffsetRVA = (void *) (BufferInfo.pRelocationTable->VirtualAddress +
                                            (0x0FFF &
                                             *(WORD * )((DWORD64)(BufferInfo.pRelocationTable) +
                                                        8 + i * 2)) + (DWORD64) pPEBuffer);
                pRelocationTableItemOffsetData = (Type == BufferType::FileBuffer) ? RVA2FOA(OffsetRVA, pPEBuffer,
                                                                                            pPEBuffer) : OffsetRVA;
                //新绝对地址 = 旧绝对地址 - 旧ImageBase + 新ImageBase
                *(DWORD *) pRelocationTableItemOffsetData =
                        *(DWORD *) pRelocationTableItemOffsetData - BufferInfo.POptionHeader->ImageBase +
                        (DWORD64) NewImageBase;
            }
        }
        BufferInfo.pRelocationTable = (_IMAGE_BASE_RELOCATION * ) //向后移动重定位表指针
                ((DWORD64) BufferInfo.pRelocationTable + BufferInfo.pRelocationTable->SizeOfBlock);
    }
    BufferInfo.pRelocationTable = Raw_pRelocationTable; //还原重定位表指针，由于是函数末尾，可以忽略
    BufferInfo.POptionHeader->ImageBase = (DWORD64) NewImageBase;
    return true;
}

bool _fastcall SetNewImageBase(void *NewImageBase, void *pPEBuffer, BufferType Type) {
    //注意：本函数可完全由RebuildRelocationTable函数替代，此处仅作接口使用
    return RebuildRelocationTable(pPEBuffer, Type, NewImageBase);
}

bool __fastcall BuildImportTable(void* pPEBuffer, BufferType Type){
    if (!pPEBuffer) Error(Err_Buffer_Invalid);
    PointersToPEBuffer BufferInfo;
    GetBufferInfo(pPEBuffer, BufferInfo, Type, true);
    if(!BufferInfo.pImportTable)
    {
        printf("Warn: ImportTable does not exist!\n",BufferInfo.pImportTable);
        return true;
    }
    _IMAGE_IMPORT_DESCRIPTOR* pImportTable_local = BufferInfo.pImportTable;
    while(pImportTable_local->FirstThunk)
    {
        //获取当前DLL名称
        char* pDllName = Type==BufferType::ImageBuffer?
                (char*)pPEBuffer + pImportTable_local->Name:
                (char*)pPEBuffer+(DWORD)RVA2FOA((void*)pImportTable_local->Name,pPEBuffer);
        HMODULE hmodule = LoadLibraryA(pDllName);
        if (!hmodule)
        {
            printf("Can't Load library:%s\n",pDllName);
            Error("BuildImportTable failed, LoadLibraryA error!\n");
            return false;
        }
        //printf("BuildImportTable: %s loaded on %08x\n",pDllName,hmodule);
        DWORD THUNKDATA32 = 0;
        DWORD OriginalFirstThunk_local=pImportTable_local->OriginalFirstThunk;
        DWORD FirstThunk_local=pImportTable_local->FirstThunk;
        while (true)
        {
            //读取由当前Dll导入的所有函数
            THUNKDATA32 = Type==BufferType::ImageBuffer?
                                             *(DWORD*)((char*)pPEBuffer+OriginalFirstThunk_local):
                                             *(DWORD*)((char*)pPEBuffer+(DWORD)RVA2FOA((void*)OriginalFirstThunk_local,pPEBuffer));
            if (!THUNKDATA32)
            {
                break;
            }
            void* funcAddr = nullptr;
            if (THUNKDATA32&0x80000000)
            {
                //以函数序号获取地址
                funcAddr = (void*) GetProcAddress(hmodule,(LPCSTR)(THUNKDATA32&0x7fffffff));
                //printf("Proc id:%d ",THUNKDATA32&0x7fffffff);
            } else {
                //以函数名获取地址
                char* funcName = Type==BufferType::ImageBuffer?
                                 (char*)((char*)pPEBuffer+THUNKDATA32+2):
                                 (char*)((char*)pPEBuffer+(DWORD)RVA2FOA((void*)THUNKDATA32,pPEBuffer)+2);
                funcAddr = (void*) GetProcAddress(hmodule,(LPCSTR)funcName);
                //printf("Proc name:%s ",funcName);
            }
            if (!funcAddr) {
                //printf(" does not found.\n",pDllName);
                Error("BuildImportTable failed, can't find function!\n");
                return false;
            }
            DWORD* pFirstThunk = Type==BufferType::ImageBuffer?
                                 (DWORD*)((char*)pPEBuffer+FirstThunk_local):
                                 (DWORD*)((char*)pPEBuffer+(DWORD)RVA2FOA((void*)FirstThunk_local,pPEBuffer));
            //写入函数真实地址到IAT表
            *pFirstThunk = (DWORD)funcAddr;
            //printf("addr [%08x] wirte to [%08x]\n",funcAddr,pFirstThunk);
            OriginalFirstThunk_local+=sizeof(DWORD);
            FirstThunk_local+=sizeof(DWORD);
        }
        ++pImportTable_local;
    }
    return true;
}

bool SetupIATHOOK(const void* OriginAddr,const void* NewAddr,void* pPEBuffer, BufferType Type,bool IsUninstall)
{
    bool IsSeccuss = false;
    PointersToPEBuffer BufferInfo;
    GetBufferInfo(pPEBuffer, BufferInfo, Type, true);
    if(!BufferInfo.pImportTable)
    {
        return IsSeccuss;
    }
    _IMAGE_IMPORT_DESCRIPTOR* pImportTable_local = BufferInfo.pImportTable;
    while(pImportTable_local->FirstThunk)
    {
        DWORD THUNKDATA32 = 0;
        DWORD OriginalFirstThunk_local=pImportTable_local->OriginalFirstThunk;
        DWORD FirstThunk_local=pImportTable_local->FirstThunk;
        while (true)
        {
            THUNKDATA32 = Type==BufferType::ImageBuffer?
                          *(DWORD*)((char*)pPEBuffer+OriginalFirstThunk_local):
                          *(DWORD*)((char*)pPEBuffer+(DWORD)RVA2FOA((void*)OriginalFirstThunk_local,pPEBuffer));
            if (!THUNKDATA32)
            {
                break;
            }
            DWORD* pFirstThunk = Type==BufferType::ImageBuffer?
                                 (DWORD*)((char*)pPEBuffer+FirstThunk_local):
                                 (DWORD*)((char*)pPEBuffer+(DWORD)RVA2FOA((void*)FirstThunk_local,pPEBuffer));
            if (IsUninstall) //卸载IAT hook
            {
                if (*pFirstThunk==(DWORD)NewAddr)
                {
                    DWORD oldProtect = 0;
                    VirtualProtect(pFirstThunk,sizeof(void*),PAGE_EXECUTE_READWRITE,&oldProtect); //设置内存页属性以允许写入数据
                    *pFirstThunk = (DWORD)OriginAddr; //恢复IAT Hook
                    DWORD temp = 0;
                    VirtualProtect(pFirstThunk,sizeof(void*),oldProtect,&temp);
                    IsSeccuss = true;
                    return IsSeccuss;
                }
            } else { //设置IAT Hook
                if (*pFirstThunk==(DWORD)OriginAddr)
                {
                    DWORD oldProtect = 0;
                    VirtualProtect(pFirstThunk,sizeof(void*),PAGE_EXECUTE_READWRITE,&oldProtect); //设置内存页属性以允许写入数据
                    *pFirstThunk = (DWORD)NewAddr; //设置IAT Hook
                    DWORD temp = 0;
                    VirtualProtect(pFirstThunk,sizeof(void*),oldProtect,&temp);
                    IsSeccuss = true;
                    return IsSeccuss;
                }
            }
            OriginalFirstThunk_local+=sizeof(DWORD);
            FirstThunk_local+=sizeof(DWORD);
        }
        ++pImportTable_local;
    }
    return IsSeccuss;
}