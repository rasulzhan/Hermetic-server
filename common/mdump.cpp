#include <windows.h>
//#include "../Parse/parse.h"
//#include "../Parse/Memory.h"
#include "mdump.h"
#include <iostream>

//extern TParse PrsMain;
extern char   app_path[MAX_PATH];

LONG WINAPI TopLevelCycleFilter( struct _EXCEPTION_POINTERS *pExceptionInfo )
{
	int retval = EXCEPTION_EXECUTE_HANDLER;
	int rt;
	for(;;){
	    rt = 5;
	    if(rt == 4)
		   break;
	    Sleep(100);
    }
	return retval;
}
LONG WINAPI TopLevelEmptyFilter( struct _EXCEPTION_POINTERS *pExceptionInfo )
{
	int retval = EXCEPTION_EXECUTE_HANDLER;
	return retval;
}
LONG WINAPI TopLevelFilter( struct _EXCEPTION_POINTERS *pExceptionInfo )
{
	char szDumpPath[_MAX_PATH] = "app.dmp\0";
	char szScratch [_MAX_PATH];
	LONG retval = EXCEPTION_CONTINUE_SEARCH;
	HWND hParent = NULL;						// find a better value for your app

	HMODULE hDll = NULL;	

	// load any version we can

	hDll = LoadLibrary( "DBGHELP.DLL" );

	LPCTSTR szResult = NULL;

	if (hDll)
	{
		MINIDUMPWRITEDUMP pDump = (MINIDUMPWRITEDUMP) GetProcAddress( hDll, "MiniDumpWriteDump" );
		if (pDump)
		{			

//			PrsMain.ZeroMem(szDumpPath, _MAX_PATH);
//			PrsMain.ZeroMem(szScratch, _MAX_PATH);
//
//			PrsMain.StrCopy( szDumpPath, app_path);
//			PrsMain.StrAdd(szDumpPath, "app.dmp" );

			// ask the user if they want to save a dump file
			if (MessageBox( NULL, "A fatal exception has occured, would you like to save a diagnostic file?", szDumpPath, MB_YESNO )==IDYES)
			{
				// create the file
				HANDLE hFile = CreateFile( szDumpPath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS,
					FILE_ATTRIBUTE_NORMAL, NULL );

				if (hFile!=INVALID_HANDLE_VALUE)
				{
					_MINIDUMP_EXCEPTION_INFORMATION ExInfo;

					ExInfo.ThreadId = GetCurrentThreadId();
					ExInfo.ExceptionPointers = pExceptionInfo;
					ExInfo.ClientPointers = NULL;

					// write the dump
					BOOL bOK = pDump( GetCurrentProcess(), GetCurrentProcessId(), hFile, MiniDumpNormal, &ExInfo, NULL, NULL );
					if (bOK)
					{
                        sprintf( szScratch, "Successfully saved %s", szDumpPath );
						szResult = szScratch;
						retval = EXCEPTION_EXECUTE_HANDLER;
					}
					else
					{
                        sprintf( szScratch, "Failed to save %s (error %d)", szDumpPath, GetLastError() );
                        printf( szScratch, "Failed to save %s (error %d)", szDumpPath, GetLastError() );
						szResult = szScratch;
					}
					CloseHandle(hFile);
				}
				else
				{
                    sprintf( szScratch, "Failed to create %s (error %d)", szDumpPath, GetLastError() );
					szResult = szScratch;
				}
			}
		}
		else
		{
			szResult = "DBGHELP.DLL is outdated\0";
		}
	}
	else
	{
		szResult = "DBGHELP.DLL was not found\0";
	}

	if (szResult)
		MessageBox(NULL, szResult, szDumpPath, MB_OK );

	return retval;
}
