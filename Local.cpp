//
// Created by Mr.Yll on 2022/4/15.
//
#include "Local.h"

HINSTANCE hinstance;
HWND hwnd;
HWND hwndOpenProcessButton;
HWND hwndEditProcessNameButton;
HWND hwndMessageBoxButton;
HWND hwndMessageBoxRemoteCallButton;
HWND hwndCalcButton;
HWND hwndCalcRemoteCallButton;
HWND hwndLogOutputButton;
TCHAR szProcessName[256]{};
HANDLE hRemoteHandle;

HANDLE hMapObject;
HANDLE hMapView;

BOOL isInjected = FALSE;
BOOL isListenMessageBox = FALSE;
BOOL isAddedHeight = FALSE;
BOOL isListenedHeight = FALSE;

HANDLE g_hMutex;
HANDLE hProcess;
void* ImageLoadAddr;
DWORD ImageSize;

/**
 * @LeslieYon 向日志输出对话框写入标准格式日志.
 * @param format - 格式化字符串.
 */
VOID PrintLog(LPCWSTR format,...)
{
    va_list args;
    unsigned int len = 256 ;
    TCHAR *buffer = nullptr;
    va_start( args, format );
    len = _vscwprintf(format,args) + sizeof(TCHAR);
    buffer = (TCHAR*)malloc( len * sizeof(TCHAR) );
    if ( nullptr != buffer )
    {
        vswprintf(buffer,len, format, args); // C4996
        time_t t = time(NULL);
        struct tm* stime=localtime(&t);
        TCHAR timestr[32]{0};
        snwprintf(timestr,10,TEXT("%02d:%02d:%02d "),stime->tm_hour,stime->tm_min,stime->tm_sec);
        SendMessage(hwndLogOutputButton, EM_SETSEL, -2, -1);
        SendMessage(hwndLogOutputButton,EM_REPLACESEL,true,(LONG)timestr);
        SendMessage(hwndLogOutputButton,EM_REPLACESEL,true,(LONG)buffer);
        SendMessage(hwndLogOutputButton,EM_REPLACESEL,true,(LONG)TEXT("\r\n"));
        free( buffer );
    }
    va_end(args);
}

BOOL CreateSharedMemory()
{
    //创建FileMapping对象
    hMapObject = CreateFileMapping((HANDLE)0xFFFFFFFF,NULL,PAGE_READWRITE,0,0x1000,TEXT("shared"));
    if(!hMapObject)
    {
        PrintLog(TEXT("创建共享内存失败"));
        return false;
    }
    //将FileMapping对象映射到自己的进程
    hMapView = MapViewOfFile(hMapObject,FILE_MAP_WRITE,0,0,0);
    if(!hMapView)
    {
        PrintLog(TEXT("内存映射失败"));
        return false;
    }
    return true;
}

VOID ClearMessage()
{
    BRIDGE_MESSAGE message{};
    message.OpCode_Local = Opcode_Nop;
    message.OpCode_Remote = Opcode_Nop;
    memcpy(hMapView,&message,sizeof(message));
}

/**
 * @LeslieYon 主进程和注入的模块之间的通信函数.
 * @param Message - 要发送消息的类型.
 * @param Data - 要发送消息附加的数据.
 * @param sizeOfData - 要附加数据的大小.
 * @param side - 辨识消息的发送者是主进程或者子模块.
 * @param IsStandAlone - 此消息是否在主消息循环之外发送.
 */
VOID BridgeSendMessage(DWORD Message,const void* Data,DWORD sizeOfData,Side side,bool IsStandAlone)
{
    if (IsStandAlone) //主消息循环外发送消息，需要等待缓冲区空闲
    {
        while (true)
        {
            WaitForSingleObject(g_hMutex,INFINITE);
            if ((*(BRIDGE_MESSAGE*)hMapView).OpCode_Remote==Opcode_Nop&&(*(BRIDGE_MESSAGE*)hMapView).OpCode_Local==Opcode_Nop)
            {
                BridgeSendMessage(Message,Data,sizeOfData,side,false);
                ReleaseMutex(g_hMutex);
                return;
            }
            ReleaseMutex(g_hMutex);
            Sleep(500);
        }
    } else { //主消息循环内发送消息，直接发送
        BRIDGE_MESSAGE message{};
        if (side==local)
        {
            message.OpCode_Local = Message;
            message.OpCode_Remote = Opcode_Nop;
        } else {
            message.OpCode_Local = Opcode_Nop;
            message.OpCode_Remote = Message;
        }
        if (Data&&sizeOfData>0)
        {
            message.MESSAGE_Offset = (DWORD)((char*)hMapView + sizeof(message));
            memcpy((void*)message.MESSAGE_Offset, Data, sizeOfData);
            message.MESSAGE_Offset = sizeof(message);
            message.SizeOfMessage = sizeOfData;
        }
        memcpy(hMapView,&message,sizeof(message));
        return;
    }
}

/**
 * @LeslieYon 通过直接写入内存的方式注入进程.
 * @return 远程线程句柄.
 */
HANDLE MemWrite()
{
    //获取当前进程加载基址
    HANDLE handle = GetModuleHandleA(nullptr);
    PointersToPEBuffer BufferInfo;
    GetBufferInfo(handle, BufferInfo, BufferType::ImageBuffer);
    void* NewImageBuffer = malloc(BufferInfo.PEBufferSize);
    memcpy(NewImageBuffer,handle,BufferInfo.PEBufferSize);
    //在目标进程中分配内存空间
    ImageLoadAddr = VirtualAllocEx(hProcess,nullptr, BufferInfo.PEBufferSize, MEM_RESERVE | MEM_COMMIT,PAGE_EXECUTE_READWRITE);
    //根据分配的内存空间位置，修复重定位
    if (!RebuildRelocationTable(NewImageBuffer, BufferType::ImageBuffer, ImageLoadAddr)) //重定位PE文件
    {
        Error("Can't rebulid Src PE relocation!");
        return nullptr;
    }
    //将PE文件镜像写入目标进程
    if (!WriteProcessMemory(hProcess, ImageLoadAddr, NewImageBuffer, BufferInfo.PEBufferSize, nullptr)) {
        Error("Can't write Src PE file to new process!");
        return nullptr;
    }
    //计算注入的PE文件的入口点的位置
    DWORD EntryAddress = (DWORD)GetProcAddress((HMODULE)handle,"Entry@4")-(DWORD)handle+(DWORD)ImageLoadAddr;
    //远程新建一个线程，使其从入口点的位置开始执行
    //为了方便，此处直接将注入模块的加载位置作为参数传递给入口函数
    HANDLE RemoteThreadHandle = CreateRemoteThread(hProcess,NULL,0,(LPTHREAD_START_ROUTINE)EntryAddress,ImageLoadAddr,0,NULL);
    ImageSize = BufferInfo.PEBufferSize;
    return RemoteThreadHandle;
}

/**
 * @LeslieYon 通过进程名称打开进程.
 * @param name - 要打开的进程名称.
 */
HANDLE GetProcessByName(PCWSTR name)
{
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (wcscmp(entry.szExeFile, name) == 0)
            {
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);
                return hProcess;
            }
        }
    }
    return nullptr;
}

DWORD WINAPI CloseProcess(_In_ LPVOID lpParameter) {
    WaitForSingleObject(hRemoteHandle,INFINITE);
    //释放目标进程中申请的内存空间
    if (!VirtualFreeEx(hProcess,ImageLoadAddr,ImageSize,MEM_DECOMMIT))
    {
        PrintLog(TEXT("VirtualFree failed (%d)."),GetLastError());
        return false;
    }
    CloseHandle(hRemoteHandle);
    hProcess = nullptr;
    ImageSize = 0;
    hRemoteHandle = nullptr;
    isInjected = FALSE;
    SendMessage(hwndOpenProcessButton,WM_SETTEXT,0,(LONG)TEXT("打开进程"));
    EnableWindow(hwndOpenProcessButton,true);
    EnableWindow(hwndEditProcessNameButton, true);
    EnableWindow(hwndMessageBoxButton,false);
    EnableWindow(hwndMessageBoxRemoteCallButton,false);
    EnableWindow(hwndCalcButton,false);
    EnableWindow(hwndCalcRemoteCallButton,false);
    PrintLog(TEXT("远程线程已终止..."));
    return true;
}

DWORD WINAPI LocalMessageReceiveLoop(_In_ LPVOID lpParameter) {
    PrintLog(TEXT("开始接收远程消息..."));
    while (true)
    {
        WaitForSingleObject(g_hMutex,INFINITE);
        switch ((*(BRIDGE_MESSAGE*)hMapView).OpCode_Remote) {
            case Opcode_Nop:
                break;
            case Opcode_RemoteThread_Listen_Height:
            {
                DWORD Height = _wtoi((const TCHAR*)((char*)hMapView + (*(BRIDGE_MESSAGE*)hMapView).MESSAGE_Offset));
                PrintLog(TEXT("Height:%d"),Height);
                ClearMessage();
                break;
            }
            case Opcode_RemoteThread_Listen_MessageBox:
            {
                PrintLog(TEXT("MessageBox:\r\n%S"),(const TCHAR*)((char*)hMapView + (*(BRIDGE_MESSAGE*)hMapView).MESSAGE_Offset) );
                ClearMessage();
                break;
            }
            case Opcode_RemoteThread_Listen_MessageBox_Start:
            {
                SendMessage(hwndMessageBoxButton,WM_SETTEXT,0,(LONG)TEXT("停止监视MessageBox"));
                PrintLog(TEXT("开始监听MessageBox..."));
                isListenMessageBox = TRUE;
                ClearMessage();
                EnableWindow(hwndMessageBoxButton,true);
                break;
            }
            case Opcode_RemoteThread_Listen_MessageBox_Stop:
            {
                SendMessage(hwndMessageBoxButton,WM_SETTEXT,0,(LONG)TEXT("开始监视MessageBox"));
                PrintLog(TEXT("停止监听MessageBox..."));
                isListenMessageBox = FALSE;
                ClearMessage();
                EnableWindow(hwndMessageBoxButton,true);
                break;
            }
            case Opcode_RemoteThread_Listen_HeightAdd_Start:
            {
                SendMessage(hwndCalcRemoteCallButton,WM_SETTEXT,0,(LONG)TEXT("取消身高+100"));
                PrintLog(TEXT("身高计算已被干预+100..."));
                isAddedHeight = TRUE;
                ClearMessage();
                EnableWindow(hwndCalcRemoteCallButton,true);
                break;
            }
            case Opcode_RemoteThread_Listen_HeightAdd_Stop:
            {
                SendMessage(hwndCalcRemoteCallButton,WM_SETTEXT,0,(LONG)TEXT("身高+100"));
                PrintLog(TEXT("身高计算干预已取消..."));
                isAddedHeight = FALSE;
                ClearMessage();
                EnableWindow(hwndCalcRemoteCallButton,true);
                break;
            }
            case Opcode_RemoteThread_Listen_Height_Start:
            {
                SendMessage(hwndCalcButton,WM_SETTEXT,0,(LONG)TEXT("停止监视身高计算"));
                PrintLog(TEXT("已开始监听身高计算..."));
                isListenedHeight = TRUE;
                ClearMessage();
                EnableWindow(hwndCalcButton,true);
                break;
            }
            case Opcode_RemoteThread_Listen_Height_Stop:
            {
                SendMessage(hwndCalcButton,WM_SETTEXT,0,(LONG)TEXT("开始监视身高计算"));
                PrintLog(TEXT("已停止监听身高计算..."));
                isListenedHeight = FALSE;
                ClearMessage();
                EnableWindow(hwndCalcButton,true);
                break;
            }
            case Opcode_RemoteThread_Init_Success:
            {
                PrintLog(TEXT("远程线程初始化成功..."));
                ClearMessage();
                EnableWindow(hwndMessageBoxButton,true);
                //EnableWindow(hwndMessageBoxRemoteCallButton,true);
                //EnableWindow(hwndCalcButton,true);
                EnableWindow(hwndCalcRemoteCallButton,true);
                break;
            }
            case Opcode_RemoteThread_GetMainWindowHandle_Success:
            {
                ClearMessage();
                EnableWindow(hwndMessageBoxRemoteCallButton,true);
                EnableWindow(hwndCalcRemoteCallButton,true);
                EnableWindow(hwndCalcButton,true);
                break;
            }
            case Opcode_RemoteThread_Exit:
            {
                ClearMessage();
                PrintLog(TEXT("远程线程正在退出..."));
                ReleaseMutex(g_hMutex);
                CreateThread(NULL,0,CloseProcess,0,NULL,0);
                PrintLog(TEXT("停止接收远程消息..."));
                return true;
            }
            case Opcode_RemoteThread_Init_Failed:
            {
                PrintLog(TEXT("远程线程初始化失败：\r\n%S"),(const TCHAR*)((char*)hMapView + (*(BRIDGE_MESSAGE*)hMapView).MESSAGE_Offset));
                ClearMessage();
                ReleaseMutex(g_hMutex);
                CreateThread(NULL,0,CloseProcess,0,NULL,0);
                PrintLog(TEXT("停止接收远程消息..."));
                return true;
            }
            default:
            {
                PrintLog(TEXT("无法识别的远程操作码"));
                ClearMessage();
                break;
            }
        }
        ReleaseMutex(g_hMutex);
        Sleep(500);
    }
    return true;
}

DWORD WINAPI InjectToProcess(_In_ LPVOID lpParameter) {
    hProcess = GetProcessByName(szProcessName);
    if (!hProcess)
    {
        MessageBox(hwnd,TEXT("打开进程失败！"),TEXT("错误"),MB_ICONERROR|MB_OK);
        EnableWindow(hwndOpenProcessButton,true);
        PrintLog(TEXT("打开进程失败！"));
        return false;
    }
    hRemoteHandle = MemWrite();
    if (!hRemoteHandle)
    {
        MessageBox(hwnd,TEXT("注入进程失败！"),TEXT("错误"),MB_ICONERROR|MB_OK);
        PrintLog(TEXT("注入进程失败！"));
        EnableWindow(hwndOpenProcessButton,true);
        return false;
    }

    //调整按钮状态
    isInjected = TRUE;
    SendMessage(hwndOpenProcessButton,WM_SETTEXT,0,(LONG)TEXT("关闭进程"));
    EnableWindow(hwndOpenProcessButton,true);
    EnableWindow(hwndEditProcessNameButton, false);

    //启动接收消息循环
    CreateThread(NULL,0,LocalMessageReceiveLoop,0,NULL,0);
    return true;
}

LRESULT CALLBACK Wndproc(
        HWND hwnd, //消息所属窗口句柄
        UINT uMsg, //消息类型
        WPARAM wParam,
        LPARAM lParam
) {
    switch (uMsg) {
        case WM_CREATE: {
            printf("WM_CREATE: %08x %08x\n", wParam, lParam);
            return 0;
        }
        case WM_DESTROY: {
            PostQuitMessage(0);
            return 0;
        }
        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case BUTTON_OPEN_PROCESS:
                {
                    if (isInjected) //已打开进程
                    {
                        PrintLog(TEXT("尝试关闭远程线程..."));
                        BridgeSendMessage(Opcode_LocalThread_CloseProcess, nullptr,0,local, true); //发送关闭远程线程消息
                    }
                    else //未打开进程
                    {
                        GetWindowText(hwndEditProcessNameButton,szProcessName,256);
                        EnableWindow(hwndOpenProcessButton,false);
                        if (wcslen(szProcessName))
                        {
                            CreateThread(NULL,0,InjectToProcess,0,0,0);
                        } else {
                            EnableWindow(hwndOpenProcessButton,true);
                        }
                    }
                    return 0;
                }
                case BUTTON_LISTEN_MessageBox:
                {
                    EnableWindow(hwndMessageBoxButton,false);
                    if (isListenMessageBox)
                    {
                        BridgeSendMessage(Opcode_LocalThread_Stop_Listen_MessageBox, nullptr,0,local, true);
                    } else {
                        BridgeSendMessage(Opcode_LocalThread_Start_Listen_MessageBox, nullptr,0,local, true);
                    }
                    return 0;
                }
                case BUTTON_LISTEN_HEIGHT_CALC:
                {
                    EnableWindow(hwndCalcButton,false);
                    if (isListenedHeight)
                    {
                        BridgeSendMessage(Opcode_LocalThread_Stop_Listen_Height, nullptr,0,local, true);
                    } else {
                        BridgeSendMessage(Opcode_LocalThread_Start_Listen_Height, nullptr,0,local, true);
                    }
                    return 0;
                }
                case BUTTON_REMOTECALL_MessageBox:
                {
                    PrintLog(TEXT("尝试远程调用MessageBox..."));
                    BridgeSendMessage(Opcode_LocalThread_RemoteCall_MessageBox, nullptr,0,local, true);
                    return 0;
                }
                case BUTTON_ADD_HEIGHT:
                {
                    EnableWindow(hwndCalcRemoteCallButton,false);
                    if (isAddedHeight)
                    {
                        BridgeSendMessage(Opcode_LocalThread_RemoteCall_HeightAdd_Stop, nullptr,0,local, true);
                    } else {
                        BridgeSendMessage(Opcode_LocalThread_RemoteCall_HeightAdd_Start, nullptr,0,local, true);
                    }
                    return 0;
                }
            }
        }
        default:
            break;
    }
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

/**
 * @brief 将某个窗口根据桌面或者另一个窗口居中.
 * @param hwnd - 要剧居中的窗口句柄.
 * @param hwndCenter - 要参考的窗口句柄，0表示以桌面为参考.
 */
void CenterWindow(HWND hwnd, HWND hwndCenter)
{
    // Determine owner window to center against.
    DWORD dwStyle = GetWindowLong(hwnd, GWL_STYLE);
    if (hwndCenter == NULL)
    {
        if(dwStyle & WS_CHILD)
            hwndCenter = GetParent(hwnd);
        else
            hwndCenter = GetWindow(hwnd, GW_OWNER);
    }

    // Get coordinates of the window relative to its parent.
    RECT rcDlg;
    GetWindowRect(hwnd, &rcDlg);
    RECT rcArea;
    RECT rcCenter;
    HWND hwndParent;
    if ((dwStyle & WS_CHILD) == 0)
    {
        // Don't center against invisible or minimized windows.
        if (hwndCenter != NULL)
        {
            DWORD dwStyleCenter = GetWindowLong(hwndCenter, GWL_STYLE);
            if (! (dwStyleCenter & WS_VISIBLE) || (dwStyleCenter & WS_MINIMIZE))
                hwndCenter = NULL;
        }

        // Center within screen coordinates.
        SystemParametersInfo(SPI_GETWORKAREA, NULL, &rcArea, NULL);
        if(hwndCenter == NULL)
            rcCenter = rcArea;
        else
            GetWindowRect(hwndCenter, &rcCenter);
    }
    else
    {
        // Center within parent client coordinates.
        hwndParent = GetParent(hwnd);
        GetClientRect(hwndParent, &rcArea);
        GetClientRect(hwndCenter, &rcCenter);
        MapWindowPoints(hwndCenter, hwndParent, (POINT*)&rcCenter, 2);
    }

    int nDlgWidth = rcDlg.right - rcDlg.left;
    int nDlgHeight = rcDlg.bottom - rcDlg.top;

    // Find dialog's upper left based on rcCenter.
    int xLeft = (rcCenter.left + rcCenter.right) / 2 - nDlgWidth / 2;
    int yTop = (rcCenter.top + rcCenter.bottom) / 2 - nDlgHeight / 2;

    // If the dialog is outside the screen, move it inside.
    if (xLeft < rcArea.left)
        xLeft = rcArea.left;
    else if (xLeft + nDlgWidth > rcArea.right)
        xLeft = rcArea.right - nDlgWidth;

    if (yTop < rcArea.top)
        yTop = rcArea.top;
    else if (yTop + nDlgHeight > rcArea.bottom)
        yTop = rcArea.bottom - nDlgHeight;

    // Map screen coordinates to child coordinates.
    SetWindowPos(hwnd, NULL, xLeft, yTop, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
}

/**
 * @LeslieYon 主消息循环.
 * @param lpParameter - 未使用.
 */
DWORD WINAPI MainLoop(_In_ LPVOID lpParameter) {
    TCHAR className[] = TEXT("MainWindow");
    WNDCLASS wndclass{}; //此处需要进行初始化
    wndclass.hbrBackground = (HBRUSH) COLOR_MENU;
    wndclass.lpfnWndProc = Wndproc;
    wndclass.lpszClassName = className;
    wndclass.hInstance = hinstance;
    RegisterClass(&wndclass);

    hwnd = CreateWindow(
            className,
            TEXT("监视器"),
            WS_OVERLAPPEDWINDOW ^ WS_THICKFRAME ^ WS_MAXIMIZEBOX , //https://docs.microsoft.com/en-us/windows/win32/winmsg/window-styles
            10, 10,
            400, 300,
            NULL,
            NULL,
            hinstance,
            NULL);
    if (!hwnd) return 0;

    hwndOpenProcessButton = CreateWindow(
            TEXT("button"),
            TEXT("打开进程"),
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_DEFPUSHBUTTON ,
            250, 30,
            80, 20,
            hwnd,
            (HMENU) BUTTON_OPEN_PROCESS,
            hinstance,
            NULL);

    hwndEditProcessNameButton = CreateWindow(
            TEXT("EDIT"),
            TEXT("SrcTest.exe"),
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_DEFPUSHBUTTON,
            80, 30,
            150, 20,
            hwnd,
            (HMENU) BUTTON_EDIT_PROCESS_NAME,
            hinstance,
            NULL);

    hwndMessageBoxButton = CreateWindow(
            TEXT("button"),
            TEXT("开始监视MessageBox"),
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_DEFPUSHBUTTON | WS_DISABLED,
            40, 70,
            180, 20,
            hwnd,
            (HMENU) BUTTON_LISTEN_MessageBox,
            hinstance,
            NULL);

    hwndMessageBoxRemoteCallButton = CreateWindow(
            TEXT("button"),
            TEXT("远程调用"),
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_DEFPUSHBUTTON | WS_DISABLED,
            230, 70,
            120, 20,
            hwnd,
            (HMENU) BUTTON_REMOTECALL_MessageBox,
            hinstance,
            NULL);

    hwndCalcButton = CreateWindow(
            TEXT("button"),
            TEXT("开始监视身高计算"),
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_DEFPUSHBUTTON | WS_DISABLED,
            40, 100,
            180, 20,
            hwnd,
            (HMENU) BUTTON_LISTEN_HEIGHT_CALC,
            hinstance,
            NULL);

    hwndCalcRemoteCallButton = CreateWindow(
            TEXT("button"),
            TEXT("身高+100"),
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_DEFPUSHBUTTON | WS_DISABLED,
            230, 100,
            120, 20,
            hwnd,
            (HMENU) BUTTON_ADD_HEIGHT,
            hinstance,
            NULL);

    hwndLogOutputButton = CreateWindow(
            TEXT("EDIT"),
            TEXT("Log Output:\r\n"),
            WS_BORDER | WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
            40, 140,
            310, 100,
            hwnd,
            (HMENU) BUTTON_LOG_OUTPUT,
            hinstance,
            NULL);
    CenterWindow(hwnd, nullptr); //居中显示主窗口
    ShowWindow(hwnd, SW_SHOW);
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return true;
}

int CALLBACK WinMain(HINSTANCE hinstance,
                     HINSTANCE hPrevInstance,
                     LPSTR lpCmdLine,
                     int nCmdShow){
    ::hinstance = hinstance;
    CreateSharedMemory();
    BridgeSendMessage(Opcode_Nop, nullptr,0,local);
    g_hMutex = CreateMutex(NULL,FALSE, TEXT("Injector_ReadWrite"));
    HANDLE hMain = CreateThread(NULL,0,MainLoop,hinstance,0,NULL);
    WaitForSingleObject(hMain,INFINITE);
    return true;
}