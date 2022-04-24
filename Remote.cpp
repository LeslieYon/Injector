//
// Created by Mr.Yll on 2022/4/15.
//

#include "Remote.h"

VOID PrintLogRemote(LPCWSTR format, ...) {
    va_list args;
    unsigned int len = 256;
    TCHAR *buffer = nullptr;
    va_start(args, format);
    len = _vscwprintf(format, args) + sizeof(TCHAR);
    buffer = (TCHAR *) malloc(len * sizeof(TCHAR));
    if (nullptr != buffer) {
        vswprintf(buffer, len, format, args); // C4996
        MessageBox(0, buffer, TEXT("调试"), 0);
        free(buffer);
    }
    va_end(args);
}

HANDLE hMainModule;

typedef int WINAPI (*pMessageBox)(HWND hWnd,LPCWSTR lpText,LPCWSTR lpCaption,UINT uType);
pMessageBox ori_MessageBoxW;
HWND hRemoteWindow;
/**
 * @LeslieYon 通过InlineHook调用的函数，原型应该与被Hook的函数一致.
 * @return 原始MessageBox的返回值.
 */
int WINAPI Hook_MessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType) {
    hRemoteWindow = hWnd;
    if (hRemoteWindow) {
        BridgeSendMessage(Opcode_RemoteThread_GetMainWindowHandle_Success, nullptr, 0, remote, true);
    }
    BridgeSendMessage(Opcode_RemoteThread_Listen_MessageBox, lpText, wcslen(lpText) * 2 + 2, remote, true);
    return ori_MessageBoxW(hWnd, lpText, lpCaption, uType);
}

BOOL isListenMessageBox_Remote = FALSE;
DWORD WINAPI ListenMessageBox(_In_ LPVOID lpParameter) {
    if (!ori_MessageBoxW) {
        HMODULE hUSER32dll = GetModuleHandle(TEXT("USER32.dll"));
        ori_MessageBoxW = (pMessageBox) GetProcAddress(hUSER32dll, "MessageBoxW");
    }
    if (lpParameter) //安装IAT Hook
    {
        if (SetupIATHOOK((void *) ori_MessageBoxW, (void *) Hook_MessageBoxW, hMainModule, ImageBuffer)) {
            BridgeSendMessage(Opcode_RemoteThread_Listen_MessageBox_Start, nullptr, 0, remote, true);
            return true;
        }
    } else { //卸载IAT Hook
        if (SetupIATHOOK((void *) ori_MessageBoxW, (void *) Hook_MessageBoxW, hMainModule, ImageBuffer, true)) {
            BridgeSendMessage(Opcode_RemoteThread_Listen_MessageBox_Stop, nullptr, 0, remote, true);
            return true;
        }
    }
    return false;
}

void *FindHookAddr(const void *ModuleAddr, void *buffer, DWORD Size) {
    PointersToPEBuffer BufferInfo;
    GetBufferInfo(ModuleAddr, BufferInfo, BufferType::ImageBuffer);
    for (DWORD i = 0; i < BufferInfo.PEBufferSize - Size; i++) {
        if (memcmp((char *) ModuleAddr + i, buffer, Size) == 0)
            return (char *) ModuleAddr + i;
    }
    return nullptr;
}

typedef INT_PTR (*RemoteDlgproc)(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

RemoteDlgproc remoteDlgproc;

DWORD WINAPI RemoteCallMessageBox(_In_ LPVOID lpParameter) {
    if (!remoteDlgproc) {
        BYTE buffer[] = {0x55, 0x8b, 0xec, 0x81, 0xec, 0x44, 0x01, 0x00, 0x00, 0xa1}; //Dlgproc函数的特征码
        remoteDlgproc = (RemoteDlgproc) FindHookAddr(hMainModule, buffer, sizeof(buffer));
        if (!remoteDlgproc)
            PrintLogRemote(TEXT("找不到Dlgproc函数!"));
    }
    remoteDlgproc(hRemoteWindow, WM_COMMAND, 1002, NULL);
    return true;
}

BOOL isListenHeight=FALSE;
HANDLE hListenHeight;
DWORD WINAPI ListenHeight(_In_ LPVOID lpParameter) {
    HANDLE hEDITHeight = GetDlgItem(hRemoteWindow, 1003);
    TCHAR szHeightBuff[0x50]{};
    BridgeSendMessage(Opcode_RemoteThread_Listen_Height_Start, nullptr,0,remote,true);
    while (isListenHeight)
    {
        GetWindowText((HWND) hEDITHeight, szHeightBuff, 0x50);
        BridgeSendMessage(Opcode_RemoteThread_Listen_Height,szHeightBuff,wcslen(szHeightBuff)*2+2,remote, true);
        Sleep(1000);
    }
    BridgeSendMessage(Opcode_RemoteThread_Listen_Height_Stop, nullptr,0,remote,true);
    return true;
}

void SendInitFailed(LPCWSTR Reason)
{
    BridgeSendMessage(Opcode_RemoteThread_Init_Failed,(void*)Reason, wcslen(Reason)*2 + 2,remote, true);
}

/**
 * @LeslieYon 用于InlineHook的裸函数.
 */
__declspec(naked) void WINAPI AddHeight_Hook()
{
    asm(".intel_syntax noprefix\n\t"
        "add esp,8\n\t"
        "add esi,0x64\n\t"
        "sub esi,1\n\t"
        "jmp [esp-8]\n\t"
        ".att_syntax noprefix\n\t");
}

void *inlineHookAddr;

BOOL isListenHeightAdd = FALSE;
DWORD WINAPI SetupInlineHook(_In_ LPVOID lpParameter) {
    auto isUninstall = (DWORD) lpParameter;
    BYTE buffer[] = {0x83, 0xc4, 0x04, 0x83, 0xee, 0x01}; //需要InlineHook位置的特征码
    if (!inlineHookAddr) {
        DWORD oldProtect = 0;
        inlineHookAddr = FindHookAddr(hMainModule, buffer, sizeof(buffer));
        if (!inlineHookAddr)
            PrintLogRemote(TEXT("找不到InlineHook位置!"));
        VirtualProtect(inlineHookAddr, sizeof(buffer), PAGE_EXECUTE_READWRITE, &oldProtect);
    }
    if (isUninstall) {
        memcpy(inlineHookAddr, buffer, sizeof(buffer));
        BridgeSendMessage(Opcode_RemoteThread_Listen_HeightAdd_Stop, nullptr,0,remote, true);
    } else {
        #pragma pack (1)
        struct Call{
            BYTE call = 0xe8;
            DWORD addr = 0;
            BYTE nop = 0x90;
        };
        #pragma pack ()
        Call* call = new(inlineHookAddr)Call;
        call->addr = (DWORD) AddHeight_Hook - ((DWORD) inlineHookAddr + sizeof(buffer) - 1);
        BridgeSendMessage(Opcode_RemoteThread_Listen_HeightAdd_Start, nullptr,0,remote, true);
    }
    return 0;
}

/**
 * @LeslieYon 远程线程接收消息主循环.
 */
DWORD WINAPI RemoteMainLoop(_In_ LPVOID) {
    //打开通信缓冲区
    CreateSharedMemory();
    //创建互斥体
    g_hMutex = OpenMutex(MUTEX_ALL_ACCESS, FALSE, TEXT("Injector_ReadWrite"));
    //获取主模块句柄
    hMainModule = GetModuleHandle(TEXT("SrcTest.exe"));
    if (!hMainModule) {
        //获取主模块句柄失败
        SendInitFailed(TEXT("获取主模块句柄失败"));
        return false;
    }
    //发送初始化成功消息
    BridgeSendMessage(Opcode_RemoteThread_Init_Success, nullptr, 0, remote, true);
    //远程线程接收消息主循环
    while (true) {
        WaitForSingleObject(g_hMutex, INFINITE);
        switch ((*(BRIDGE_MESSAGE *) hMapView).OpCode_Local) {
            case Opcode_Nop:
                break;
            case Opcode_LocalThread_Start_Listen_MessageBox: {
                ClearMessage();
                isListenMessageBox_Remote = TRUE;
                CreateThread(NULL, 0, ListenMessageBox, (LPVOID) true, NULL, 0);
                break;
            }
            case Opcode_LocalThread_Stop_Listen_MessageBox: {
                ClearMessage();
                isListenMessageBox_Remote = FALSE;
                CreateThread(NULL, 0, ListenMessageBox, (LPVOID) false, NULL, 0);
                break;
            }
            case Opcode_LocalThread_RemoteCall_MessageBox: {
                CreateThread(NULL, 0, RemoteCallMessageBox, 0, 0, 0);
                ClearMessage();
                break;
            }
            case Opcode_LocalThread_Start_Listen_Height: {
                isListenHeight = TRUE;
                hListenHeight = CreateThread(NULL, 0, ListenHeight, 0, 0, 0);
                ClearMessage();
                break;
            }
            case Opcode_LocalThread_Stop_Listen_Height: {
                isListenHeight = FALSE;
                CloseHandle(hListenHeight);
                ClearMessage();
                break;
            }
            case Opcode_LocalThread_RemoteCall_HeightAdd_Start: {
                isListenHeightAdd = TRUE;
                CreateThread(NULL, 0, SetupInlineHook, (LPVOID)false, 0, 0);
                ClearMessage();
                break;
            }
            case Opcode_LocalThread_RemoteCall_HeightAdd_Stop: {
                isListenHeightAdd = FALSE;
                CreateThread(NULL, 0, SetupInlineHook, (LPVOID)true, 0, 0);
                ClearMessage();
                break;
            }
            case Opcode_LocalThread_CloseProcess: {
                ClearMessage();
                ReleaseMutex(g_hMutex);
                if (isListenHeight)
                {
                    isListenHeight = FALSE;
                    WaitForSingleObject(hListenHeight,INFINITE);
                }
                if (isListenMessageBox_Remote)
                {
                    isListenMessageBox_Remote = FALSE;
                    HANDLE hStopListenMessagebox  = CreateThread(NULL, 0, ListenMessageBox, (LPVOID) false, NULL, 0);
                    WaitForSingleObject(hStopListenMessagebox,INFINITE);
                }
                if (isListenHeightAdd)
                {
                    isListenHeightAdd = FALSE;
                    HANDLE hStopClistenHeightAdd = CreateThread(NULL, 0, SetupInlineHook, (LPVOID)true, 0, 0);
                    WaitForSingleObject(hStopClistenHeightAdd,INFINITE);
                }
                BridgeSendMessage(Opcode_RemoteThread_Exit, nullptr, 0, remote, true);
                return true;
            }
            default: {
                MessageBox(0, TEXT("无法识别的操作码"), TEXT("提示"), 0);
                ClearMessage();
                break;
            }
        }
        ReleaseMutex(g_hMutex);
        Sleep(500);
    }
    return true;
}

/**
 * 通过方式2注入进程时，模块开始执行的入口点,
 * 此函数原型应与ThreadProc函数一致,
 * 此函数返回值作为线程退出代码传递给父进程.
 */
extern "C" __declspec(dllexport) DWORD WINAPI Entry(DWORD ImageBase) {
    //注入代码运行第一步：重新修复导入表
    if (!BuildImportTable((void *) ImageBase, BufferType::ImageBuffer)) {
        MessageBox(nullptr, TEXT("Build ImportTable Failed!"), TEXT("Error"), 0);
        return -1;
    }
    HANDLE hRemoteMainLoop = CreateThread(NULL, 0, RemoteMainLoop, NULL, NULL, 0);
    WaitForSingleObject(hRemoteMainLoop, INFINITE);
    DWORD szExitCode = 0;
    GetExitCodeThread(hRemoteMainLoop, &szExitCode);
    CloseHandle(hRemoteMainLoop);
    return szExitCode;
}