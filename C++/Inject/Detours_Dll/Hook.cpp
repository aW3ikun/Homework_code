#include"Hook.h"

inline std::wstring to_wide_string(const std::string& input)
{
	std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
	return converter.from_bytes(input);
}

int WINAPI Newsend(SOCKET s,const char* buf,int len,int flags) {
	string strbuf = buf;
	wstring wsbuf = L"Write: " + to_wide_string(strbuf) + L"\n";
	Log((LPWSTR)wsbuf.c_str());
	return send(s, buf, len, flags);
}
BOOL NewWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD  nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
	//MessageBox(NULL, L"WriteFile Success!", NULL, MB_OK);
	//wsprintf(lpTemp, L"Write: %s \n", lpBuffer);
	//Log(lpTemp);
	return WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}
map<LPVOID, LPVOID> Sum() {
	DllFunction dllfunc1;
	dllfunc1.DllName = "kernel32.dll";
	dllfunc1.vFunction = { "WriteFile" };
	vector<LPVOID> newFunc = { NewWriteFile };
	return GetFunc(dllfunc1, newFunc);
}

map<LPVOID, LPVOID> GetFunc(DllFunction dllfunc, vector<LPVOID> newFunc) {
	map<LPVOID, LPVOID> mapHookFunc;
	string dllname = dllfunc.DllName;
	vector<std::string> oldFunc = dllfunc.vFunction;
	if (oldFunc.size() == newFunc.size()) {
		for (size_t i = 0; i < oldFunc.size(); i++) {
			LPVOID hookfunc = DetourFindFunction(dllname.c_str(), oldFunc[i].c_str());
			if (hookfunc != NULL) {
				mapHookFunc.insert(make_pair(hookfunc, (LPVOID)newFunc[i]));
			}
		}
	}
	return mapHookFunc;
}