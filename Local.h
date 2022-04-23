//
// Created by Mr.Yll on 2022/4/15.
//

#ifndef INJECTOR_LOCAL_H
#define INJECTOR_LOCAL_H

#include <windows.h>
#include <cstdio>
#include <tlhelp32.h>
#include <ctime>
#include "PETools/PETools.h"

#define BUTTON_OPEN_PROCESS 1001
#define BUTTON_EDIT_PROCESS_NAME 1002
#define BUTTON_LISTEN_MessageBox 1003
#define BUTTON_REMOTECALL_MessageBox 1004
#define BUTTON_LISTEN_HEIGHT_CALC 1005
#define BUTTON_ADD_HEIGHT 1006
#define BUTTON_LOG_OUTPUT 1007

#define Opcode_LocalThread_Start_Listen_MessageBox 0xa5
#define Opcode_LocalThread_Stop_Listen_MessageBox 0xa6
#define Opcode_LocalThread_Start_Listen_Height 0xa7
#define Opcode_LocalThread_Stop_Listen_Height 0xa8
#define Opcode_LocalThread_RemoteCall_MessageBox 0xa9
#define Opcode_LocalThread_RemoteCall_HeightAdd_Start 0xaa
#define Opcode_LocalThread_CloseProcess 0xab
#define Opcode_LocalThread_RemoteCall_HeightAdd_Stop 0xac
#define Opcode_Nop 0xff

#define OpCode_RemoteThread_Setup_Success 0xa0
#define Opcode_RemoteThread_Listen_MessageBox 0xa1
#define Opcode_RemoteThread_RemoteCall_MessageBox_Success 0xa2
#define Opcode_RemoteThread_Listen_Height 0xa3
#define Opcode_RemoteThread_Listen_HeightAdd 0xa4
#define Opcode_RemoteThread_Init_Success 0xb0
#define Opcode_RemoteThread_Init_Failed 0xb1
#define Opcode_RemoteThread_Listen_MessageBox_Start 0xb2
#define Opcode_RemoteThread_Listen_MessageBox_Stop 0xb3
#define Opcode_RemoteThread_Listen_HeightAdd_Start 0xb4
#define Opcode_RemoteThread_Listen_HeightAdd_Stop 0xb5
#define Opcode_RemoteThread_GetMainWindowHandle_Success 0xb6
#define Opcode_RemoteThread_Listen_Height_Stop 0xb7
#define Opcode_RemoteThread_Listen_Height_Start 0xb8
#define Opcode_RemoteThread_Exit 0xfe

extern HANDLE hMapObject;
extern HANDLE hMapView;
extern HANDLE g_hMutex;

struct BRIDGE_MESSAGE{
    DWORD OpCode_Remote;
    DWORD OpCode_Local;
    DWORD MESSAGE_Offset;
    DWORD SizeOfMessage;
};

enum Side{local,remote};

extern BOOL CreateSharedMemory();

extern VOID ClearMessage();

extern VOID BridgeSendMessage(DWORD Message,const void* Data,DWORD sizeOfData,Side side,bool IsStandAlone=false);

#endif //INJECTOR_LOCAL_H
