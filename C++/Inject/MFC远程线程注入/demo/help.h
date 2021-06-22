#pragma once
#include"pch.h"



BOOL InjectLib(INT dwProcessId, PTSTR pFileName);
BOOL FreeLib(INT dwProcessId, PTSTR pFileName);