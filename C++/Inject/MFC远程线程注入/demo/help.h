#pragma once
#include"pch.h"
#define MAX_PATH 256


BOOL InjectLib(INT dwProcessId, PTSTR pFileName);
BOOL FreeLib(INT dwProcessId, PTSTR pFileName);