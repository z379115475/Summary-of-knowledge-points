#pragma once
#include <windows.h>
#include <stdio.h>

HANDLE MemExecu(void   * ABuffer, long  Len, char   * CmdParam, unsigned  long   * ProcessId);
BOOL MemStop(HANDLE& hProcess);