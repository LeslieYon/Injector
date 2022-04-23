//
// Created by Mr.Yll on 2022/4/15.
//

#ifndef INJECTOR_REMOTE_H
#define INJECTOR_REMOTE_H

#include "Local.h"

DWORD WINAPI RemoteMainLoop(_In_ LPVOID lpParameter);

VOID PrintLogRemote(LPCWSTR format, ...);

#endif //INJECTOR_REMOTE_H
