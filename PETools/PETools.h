//
// Created by Mr.Yll on 2022/3/27.
//

#ifndef SHELL_PETOOLS_H
#define SHELL_PETOOLS_H
#pragma once

#include <iostream>
#include <Windows.h>
#include <winnt.h>
#include <memory>
#include <cstring>
#include <exception>

using std::malloc;
using std::memset;
using std::memcpy;
using std::memmove;
using std::exception;
using std::string;

enum BufferType
{
    ImageBuffer,
    FileBuffer
};

struct PointersToPEBuffer
{
    _IMAGE_DOS_HEADER* PDOSHeader = nullptr;
    _IMAGE_NT_HEADERS* PNTHeader = nullptr;
    _IMAGE_FILE_HEADER* PPEHeader = nullptr;
    _IMAGE_OPTIONAL_HEADER* POptionHeader = nullptr;
    _IMAGE_SECTION_HEADER* PSectionTable = nullptr;
    _IMAGE_EXPORT_DIRECTORY* pExportTable = nullptr;
    _IMAGE_IMPORT_DESCRIPTOR* pImportTable = nullptr;
    _IMAGE_BASE_RELOCATION* pRelocationTable = nullptr;
    DWORD PEBufferSize = 0;
};

DWORD GetPEFileSize(FILE*File);

FILE* OpenPEFile(const char* FilePath);

PointersToPEBuffer& __fastcall GetBufferInfo(const void* Buffer, PointersToPEBuffer& PPEFile, BufferType Type, bool IsExtra = false);

void* ReadFileToFileBuffer(FILE* File);

void* FileBufferToImageBuffer(const void* FileBuffer);

void* ImageBufferToFileBuffer(const void* ImageBuffer);

void SaveFileBufferToDisk(const void* FileBuffer, const char* NewFilePath);

#define CodeSection	(IMAGE_SCN_CNT_CODE|IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_READ)
#define DataSection (IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE|IMAGE_SCN_CNT_INITIALIZED_DATA)
#define ResSection (IMAGE_SCN_MEM_READ|IMAGE_SCN_CNT_INITIALIZED_DATA)

_IMAGE_SECTION_HEADER * AddSection(void ** PointerToPBuffer, BufferType Type, const char* SectionName, DWORD Characteristics, DWORD SectionSize,const void* NewSectionData = nullptr);

_IMAGE_SECTION_HEADER * MergeSection(void ** PointerToPBuffer, BufferType Type, const char* NewSectionName);

void * __fastcall RVA2FOA(void* RVA, const void* pPEBuffer, const void* OffsetBase = nullptr);

void * __fastcall FOA2RVA(void* FOA, const void* pPEBuffer, const void* OffsetBase = nullptr);

void * __fastcall GetFuncFOAWithNameOrdinal(const void* FileBuffer, WORD NameOrdinalOfFunction, void* OffsetBase = nullptr);

void * __fastcall GetFuncFOAWithName(const void* FileBuffer, const char* FunctionName, void* OffsetBase = nullptr);

//注意：本函数可完全由RebuildRelocationTable函数替代，此处仅作接口使用
bool __fastcall SetNewImageBase(void* NewImageBase, void* pPEBuffer, BufferType Type);

bool __fastcall RebuildRelocationTable(void* pPEBuffer, BufferType Type, void* NewImageBase);

bool __fastcall BuildImportTable(void* pPEBuffer, BufferType Type);

bool __fastcall SetupIATHOOK(const void* OriginAddr,const void* NewAddr,void* pPEBuffer, BufferType Type,bool IsUninstall = false);

void Error(const char* Message);

#endif //SHELL_PETOOLS_H
