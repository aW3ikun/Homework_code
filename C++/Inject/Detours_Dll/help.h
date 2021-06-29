#pragma once
#include"global.h"


class DetoursMyHook
{

public:
	DetoursMyHook(map<LPVOID, LPVOID>, BOOL );
	DetoursMyHook();
	~DetoursMyHook();
	void InsertMap(map<LPVOID, LPVOID>,BOOL );
private:
	VOID SetHook();
	VOID UnHook();
	map<LPVOID, LPVOID> mapHookFunc;
	BOOL bHook;

};


