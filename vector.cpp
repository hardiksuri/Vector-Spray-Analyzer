#pragma comment(lib, "detours.lib")

#undef UNICODE
#include<cstdio>
#include<windows.h>
#include<stdlib.h>
#include<tchar.h>
#include<string.h>
#include<detours.h>
#include <iostream>
#include <fstream>
using namespace std;

typedef void *pFunc;
static PDETOUR_TRAMPOLINE Trampoline;
char c[50];
char d[500];
int vector,vsize;
PVOID DetourPtr;
PVOID TargetPtr;
HMODULE GetModH;
ofstream myfile;

const char *GetFlashPath()
{
   HKEY hKey;
   LONG lResult;
   DWORD dwType = REG_SZ;
   char buf[255] = {0};
   DWORD dwBufSize = sizeof(buf);
   lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Macromedia\\FlashPlayerActiveX", 0, KEY_READ, &hKey);
    if(lResult == ERROR_SUCCESS)
	{
		RegQueryValueEx( hKey, "PlayerPath", 0, &dwType, (LPBYTE)buf, &dwBufSize);
		RegCloseKey(hKey);
	}
OutputDebugString(buf);
return buf;
}

 DWORD hook()
{
	myfile.open ("C:\\vector.txt", ios::out | ios::app | ios::binary); 
	LoadLibrary("C:\\Windows\\system32\\Macromed\\Flash\\Flash32_12_0_0_38.ocx");
	GetModH=GetModuleHandle("Flash32_12_0_0_38.ocx");
	DWORD err=GetLastError();
	//DWORD addr=(int)GetModH+0x6232C0;  //RVA 0x6232C0 for 12.0.0.38
	DWORD addr=(int)GetModH+0x626BE0;  //RVA 6564F3=><unit>, 6563A3 => <int>, 656643 => <Number>, clear routine(unit)=>626BE0
	sprintf (c, "Hooking Address: 0x%08x, Last error: %x",addr,err);
	OutputDebugString(c);
	return addr;
}
 
__declspec(naked) void MyFunc()
{
	
	__asm {
		pushad;
		mov eax,dword ptr [ecx];
		mov vector,eax;
		mov vsize,edi;
	}
	
	sprintf (d, "Address: 0x%08x, Size: %x\n",vector,vsize);
	OutputDebugString(d);
	myfile<<d;
	
	__asm popad;
	__asm jmp [Trampoline];

}

DWORD address=hook();

pFunc FuncToDetour = (pFunc)(address);


INT APIENTRY DllMain(HMODULE hDLL, DWORD Reason, LPVOID Reserved)
{
	
	LPTSTR pszOutput;
	switch(Reason)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hDLL);
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttachEx(&FuncToDetour, MyFunc,&Trampoline,&TargetPtr,&DetourPtr);
		DetourTransactionCommit();
		break;
	case DLL_PROCESS_DETACH:
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		myfile.close();
		DetourDetach(&(PVOID&)FuncToDetour, MyFunc);
		DetourTransactionCommit();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}

