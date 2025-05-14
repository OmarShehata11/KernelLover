#include <yara.h>
#include <stdio.h>
#include <wchar.h>
#include <assert.h>
#include <stdlib.h>
#include <vector>
#include <string>
#include <psapi.h>
#include <cctype>
#include <iostream>
#include <filesystem>
#include "yaraHead.h"



namespace fs = std::filesystem; // for the file system iterator


#define BUFFER_SIZE 200
#define THREAD_NUMBER 8

const char* DIR_YARA_PATH = "D:\\yara rules\\rules\\mal";
const char* LOG_FILE_PATH = "C:\\Users\\Omar Shehata\\Desktop\\LOG FILE.log";

FILE* pLogFile;
TCHAR gServiceName[] = TEXT("YaraEngine"); // name for the service.

SERVICE_STATUS_HANDLE gHandleService; // handle for the handle function for the service. 
SERVICE_STATUS gServiceStatus;   // service status needed for the SCM.

// check the # of rule matched.
int ruleMatchedProc = 0;
int ruleMatchedFile = 0;

// Call-Back function for the Scanner
int YaraCallBack(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data);

void Usage(wchar_t* procName);
void DbgMsg(const char* zcFormat, ...);
void InitLogFile();
// Function to convert memory protection constants to human-readable strings
const char* GetMemoryProtectionString(DWORD protection);

void ServiceMain(DWORD serviceArgc, LPWSTR* lpServiceArgv);
DWORD HandlerFunc(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext);
void ChangeServStatus(DWORD controlCode);

DWORD WINAPI ThreadProc(LPVOID parameter);


namespace YaraNS
{
	class YaraClass
	{
	
	private:
		YR_COMPILER* pYaraCompiler = nullptr;
		YR_RULES* pYaraRules = nullptr;
	public:
		YaraClass()
		{
			if ((yr_initialize()) != ERROR_SUCCESS)
				fprintf_s(pLogFile, "[-] error while init the libyara\n");

			if ((yr_compiler_create(&pYaraCompiler) != ERROR_SUCCESS))
				fprintf_s(pLogFile,"[-] error, while creating the compiler\n");

		}


		~YaraClass()
		{  // clean up everything.
			yr_compiler_destroy(pYaraCompiler);

			if ((yr_finalize()) != ERROR_SUCCESS)
				fprintf_s(pLogFile,"[-] error while finalize the libyara\n");
		}

		int CompileRuleFile(const char* fileName)
		{
			FILE* yaraFile;
			errno_t errorCode;

			errorCode = fopen_s(&yaraFile, fileName, "r");

			if (errorCode != 0)
			{
				fprintf_s(pLogFile,"[-] error while openning the yara file, error code %d\n", errorCode);
				return -2;
			}
			/* NOTE:
			   You can add a call back function in case if there's an error while compiling the yara file
			   and you want to know detailed errors about the compilation error. but I won't use it.
			*/

			// Now add the file:
			if ((yr_compiler_add_file(pYaraCompiler, yaraFile, NULL, NULL)) != 0)
			{
				fprintf_s(pLogFile,"[-] error while compiling the yara file.\n");
				return -1;
			}
			
			/* BIG NOTE:
				If the 	yr_compiler_add_file() function failed, you can't use the compiler any more, 
				neither for adding more rules (rules file) nor getting compiled rules.
			*/



			fclose(yaraFile);

			// now everything is good, let's return.
			return ERROR_SUCCESS;


		}

		bool AddRuleToCompiler()
		{
			if ((yr_compiler_get_rules(pYaraCompiler, &pYaraRules)) != ERROR_SUCCESS)
			{
				fprintf_s(pLogFile,"[-] error while using yr_compiler_get_rules() function.\n");
				return false;
			}
			return true;
		}

		// scan a file :
		int ScanFile(const char* fileName)
		{

			if ((yr_rules_scan_file(pYaraRules, fileName, SCAN_FLAGS_REPORT_RULES_MATCHING, YaraCallBack, nullptr, 0)) != ERROR_SUCCESS)
			{
				fprintf_s(pLogFile, "[-] error while scanning the target file. error code %d", GetLastError());
				return -1;
			}
			
			OutputDebugStringA("now the scan in ScanFile function has finished.");
			// now the scan is succedded, and the callback function is called. let's return.
			return ERROR_SUCCESS;
		}

		// scan a memory rather than a file:
		void ScanMemory(std::vector<byte> region, PMEMORY_BASIC_INFORMATION RegionInfoUserData) 
		{
			const unsigned char* buffer = ( unsigned char*)region.data();
			int bufferSize = region.size();

			if (strlen((char*)buffer) == 0)
				return;

			int ret = yr_rules_scan_mem(pYaraRules, buffer, bufferSize, SCAN_FLAGS_NO_TRYCATCH, YaraCallBack, RegionInfoUserData, 0);
		}
		
		// adding a list of yara files from a dir
		bool IterateDir(const char* Dir)
		{
			int numOfYaraFile = 0;
			for (const auto &file : fs::recursive_directory_iterator(Dir))
			{
				if (file.path().extension() == ".yar" || file.path().extension() == ".yara")
				{
					if (CompileRuleFile(file.path().string().c_str()) != ERROR_SUCCESS)
					{
						fprintf_s(pLogFile,"[-] error while adding the yara file : \033[34;5%s\033[0m\n", file.path().string().c_str());
						return false;
					}
					fprintf_s(pLogFile,"[+] file %s has been added to the compiler...\n", file.path().string().c_str());
					numOfYaraFile++;

				}
			}

			if (numOfYaraFile)
			{
				fprintf_s(pLogFile,"[+] Number of Yara files found : %d\n", numOfYaraFile);
				return true;
			}
			return false;
		}
	
	};



	/* inside the namespace, not the class. */

	std::vector<MEMORY_BASIC_INFORMATION> GetProcRegions(HANDLE hProcess)
	{
		std::vector<MEMORY_BASIC_INFORMATION> MemRegions;
		MEMORY_BASIC_INFORMATION MemInfo;
		LPVOID offset = 0;
		while ( VirtualQueryEx(hProcess, offset, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION)) ) 
		{
			offset = (LPVOID)(reinterpret_cast<DWORD_PTR>(MemInfo.BaseAddress) + MemInfo.RegionSize); // update the offset to get the next regions
			
			// skip those regions at all :
			if (MemInfo.Protect == PAGE_NOACCESS)
				continue;

			MemRegions.push_back(MemInfo); // push the result to the vector
		}

		// check if it worked at all:
		if (MemRegions.size() == 0)
		{
			fprintf_s(pLogFile,"[-] error: while using VirtualQueryEx. can't read\n");
			return std::vector<MEMORY_BASIC_INFORMATION>{};
		}
	
		// everyThing is ok
		return MemRegions;
	}


	// read memory
	std::vector<byte> ReadMemory(HANDLE hProcess, LPVOID baseAddress, DWORD sizeOfModule)
	{
		std::vector<byte> buffer(sizeOfModule);

		if (!(ReadProcessMemory(hProcess, baseAddress, buffer.data(), sizeOfModule, nullptr)) && (GetLastError() != 299))
		{
			fprintf_s(pLogFile,"[-] error while reading the memory. error code %d\n", GetLastError());
			return std::vector<byte>{}; // return empty vector.
		}
		if (buffer.size() == 0)
			return std::vector<byte>{};

		return buffer;
	}


	// get the base address of a process
	TCHAR* GetProcName(HANDLE hProcess)
	{
		TCHAR lpImageFileName[BUFFER_SIZE];

		// get the module name :
		if (!GetModuleFileNameEx(hProcess, 0, lpImageFileName, BUFFER_SIZE))
		{
			fprintf_s(pLogFile,"[-] error while getting the image file name. %d\n", GetLastError());
			return nullptr;
		}
		return lpImageFileName;
	}
}

YaraNS::YaraClass yara;

/*
SUMMARY:
	Entry point for the service.
*/
int wmain(int argc, wchar_t* const* argv)
{
	SERVICE_TABLE_ENTRY ServiceTable[] =
	{
		{gServiceName, (LPSERVICE_MAIN_FUNCTION)ServiceMain},
		{NULL, NULL}
	};

	OutputDebugString(L"I'm in the wmain function.");


	bool succ = StartServiceCtrlDispatcher(ServiceTable); // Now thread goes to the service main function...
	
	if (!succ)
		OutputDebugString(L"ERROR: while calling StartServiceCtrlDispatcher function.");

	return 0;
}



 int YaraCallBack(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data)
{
	 YR_RULE* YRule = nullptr;
	 YR_MODULE_IMPORT* yModule = nullptr;

	switch (message)
	{
	case CALLBACK_MSG_RULE_MATCHING:

		// increase the # of rule matched.

		YRule = (YR_RULE*)message_data;

		if (user_data != nullptr)
		{
			ruleMatchedProc++;

			PMEMORY_BASIC_INFORMATION RegInfo = (PMEMORY_BASIC_INFORMATION)user_data;
		
		
			// print the matched rules and details
			fprintf_s(pLogFile,"\n**>> matshes for rule : %s\n", YRule->identifier);
			fprintf_s(pLogFile,"--------------------------------------------------------\n");
			fprintf_s(pLogFile,"| Page/Region Base address | Protection | Yara ID Found |\n");
			fprintf_s(pLogFile,"--------------------------------------------------------\n");
		
			for (int i = 0; i < YRule->num_atoms; i++)
				fprintf_s(pLogFile,"|0x%-20p ====> %-12s ====> %-15s\n", RegInfo->BaseAddress, GetMemoryProtectionString(RegInfo->Protect), YRule->strings[i].identifier);
		
			fprintf_s(pLogFile,"--------------------------------------------------------\n");

		}

		else
		{
			ruleMatchedFile++;

			fprintf_s(pLogFile,"\n **>> matshes for rule : %s, AND TAGS : %s\n", YRule->identifier, YRule->tags);
			
			fprintf_s(pLogFile,"\n|ID FOUND:\n");
			
			// iterate for every string that matches
			for (int i = 0; i < YRule->num_atoms; i++)
				fprintf_s(pLogFile,"\\%s\n", YRule->strings[i].identifier);
				
		}

		fprintf_s(pLogFile,"<=========================================================================>\n");
		break;

	case CALLBACK_MSG_IMPORT_MODULE:
		break;

	case CALLBACK_MSG_MODULE_IMPORTED:
		break;

	case CALLBACK_MSG_TOO_MANY_MATCHES:
		fprintf_s(pLogFile,"the message is : CALLBACK_MSG_TOO_MANY_MATCHES\n");
		break;

	case CALLBACK_MSG_CONSOLE_LOG:
		fprintf_s(pLogFile,"the message is : CALLBACK_MSG_CONSOLE_LOG\n");
		break;
	
	}

	 
	return CALLBACK_CONTINUE;
}

 // Function to convert memory protection constants to human-readable strings
 const char* GetMemoryProtectionString(DWORD protection) {
	 if (protection == 0) {
		 return "No Access";
	 }

	 // Check for individual flags using bitwise operations
	 std::string result;
	 if (protection & PAGE_NOACCESS) result += "PAGE_NOACCESS | ";
	 if (protection & PAGE_READONLY) result += "PAGE_READONLY | ";
	 if (protection & PAGE_READWRITE) result += "PAGE_READWRITE | ";
	 if (protection & PAGE_WRITECOPY) result += "PAGE_WRITECOPY | ";
	 if (protection & PAGE_EXECUTE) result += "PAGE_EXECUTE | ";
	 if (protection & PAGE_EXECUTE_READ) result += "PAGE_EXECUTE_READ | ";
	 if (protection & PAGE_EXECUTE_READWRITE) result += "PAGE_EXECUTE_READWRITE | ";
	 if (protection & PAGE_EXECUTE_WRITECOPY) result += "PAGE_EXECUTE_WRITECOPY | ";
	 if (protection & PAGE_GUARD) result += "PAGE_GUARD | ";
	 if (protection & PAGE_NOCACHE) result += "PAGE_NOCACHE | ";
	 if (protection & PAGE_WRITECOMBINE) result += "PAGE_WRITECOMBINE | ";

	 // Remove the trailing " | " if there are flags
	 if (!result.empty()) {
		 result.pop_back();
		 result.pop_back();
	 }

	 return result.c_str();
 }

 void Usage(wchar_t * procName)
 {
	 fprintf_s(pLogFile,"\nUSAGE : %ls -y <yaraFile> [OPTION..]\nOPTIONS:\n\t-f FILE:\tspecify the FILE to be scanned.\n\t-p PID:\tspecify the PID of the process to be scanned.\n\t-d DIR:\tspecify DIR path that hold num of yara files.\n\t-h:\tprint the help page.\n\nAUTHORED BY : OMAR SHEHATA\n", procName);
	 exit(0);
 }


 void ServiceMain(DWORD serviceArgc, LPWSTR* lpServiceArgv)
 {
	 bool connctSucc;
	 HANDLE hCompletionRoutine;
	 OVERLAPPED overlappedStructure;
	 PDATA_FROM_KERNEL dataFromKernel = NULL;
	 PTHREAD_PARAMETERS threadParameter;

	 gHandleService = RegisterServiceCtrlHandlerEx(gServiceName, (LPHANDLER_FUNCTION_EX)HandlerFunc, nullptr);

	 if (gHandleService == 0)
	 {
		 DbgMsg("error while registering for the service control handler. error code %d", GetLastError());
		 return;
	 }
	
	 // init the status : 
	 ChangeServStatus(0);

	 // now do the needed initialization for the service :
	 // I will accept the data through a pipe line, so there's no need to use the getopt anymore.
	 

	 HANDLE hProcess, hThread[THREAD_NUMBER], hPipe;
	 DWORD threadID;

	 OutputDebugStringA("[YARA ENGINE] Initializing the log file ...");
	 InitLogFile();

	 OutputDebugStringA("[YARA ENGINE] Loading the Yara files...");

	 // we should first load the yara files :
	 if (!(yara.IterateDir(DIR_YARA_PATH)))
	 {
		 DbgMsg("[YARA ENGINE] ERROR : while iterating to the dir path of yara rules, error code %d", GetLastError());
		 ChangeServStatus(SERVICE_STOPPED);
	 }
	 OutputDebugString(L"[YARA ENGINE] LOADING OF YARA FILE IS DONE +++");

	 if (!(yara.AddRuleToCompiler()))
	 {
		 DbgMsg("[YARA ENGINE]  Error while adding the rules to the compiler. error code %d", GetLastError());
		 ChangeServStatus(SERVICE_STOPPED);
	 }

	 gServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE;

	 SetServiceStatus(gHandleService, &gServiceStatus);

	 /* the work of the pipe line : */
	 hPipe = CreateNamedPipe(L"\\\\.\\pipe\\YaraEngine", PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_READMODE_BYTE, 2, PIPE_UNLIMITED_INSTANCES, sizeof(BUFFER_DATA), NMPWAIT_USE_DEFAULT_WAIT, nullptr);
	 if (hPipe == INVALID_HANDLE_VALUE)
	 {
		 fprintf_s(pLogFile, "Error while creating the pipe line, exiting. error code %d", GetLastError());
		 ChangeServStatus(SERVICE_STOPPED);
		 return;
	 }

	 OutputDebugString(L"CREATING OF PIPE LINE IS DONE +++");

	 // creation of a completion routine ..
	 hCompletionRoutine = CreateIoCompletionPort(hPipe, NULL, 0, THREAD_NUMBER);

	 if (hCompletionRoutine == NULL)
	 {
		 fprintf_s(pLogFile, "[-] ERROR while creating the completion routine.\n");
		 CloseHandle(hPipe);
		 ChangeServStatus(SERVICE_STOPPED);
		 return;
	 }

	 // INIT THE THREAD PARAMETERS
	 threadParameter = (PTHREAD_PARAMETERS)malloc(sizeof(THREAD_PARAMETERS));
	 
	 if (threadParameter == NULL)
	 {
		 fprintf_s(pLogFile, "[-]ERROR: couldn't allocate space for thread parameters.\n");
		 CloseHandle(hPipe);
		 ChangeServStatus(SERVICE_STOPPED);
		 return;
	 }

	 threadParameter->hCompletionRoutine = hCompletionRoutine;
	 threadParameter->hPipe = hPipe;

	 // now create an instance 
	 connctSucc = ConnectNamedPipe(hPipe, NULL);

	 if (!connctSucc)
	 {
		 fprintf_s(pLogFile, "[-]ERROR : while calling ConnectNamedPipe. error code is : %d\n", GetLastError());
		 CloseHandle(hPipe);
		 ChangeServStatus(SERVICE_STOPPED);
	 }



	 for (int i = 0; i < THREAD_NUMBER; i++)
	 { 
		 hThread[i] = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)ThreadProc, (LPVOID)threadParameter, 0, nullptr);

		 if (hThread[i] == NULL)
		 {
			 // here there's a problem with the thread. just print bro ..
			 fprintf_s(pLogFile, "[-]ERROR : couldn't create thread number %d.\n", i);
		 }

		 dataFromKernel = (PDATA_FROM_KERNEL)malloc(sizeof(DATA_FROM_KERNEL));
		 
		 if (dataFromKernel== NULL)
		 {
			 fprintf_s(pLogFile, "[-]ERROR: couldn't allocate space for data from kernel.\n");
			 CloseHandle(hPipe);
			 ChangeServStatus(SERVICE_STOPPED);
			 break;
		 }

		 memset(&dataFromKernel->Overlapped, 0, sizeof(OVERLAPPED));

		 connctSucc = ReadFile(hPipe, dataFromKernel, sizeof(DATA_FROM_KERNEL), NULL, &dataFromKernel->Overlapped);


		 if ((GetLastError()) != ERROR_IO_PENDING)
		 {
			 fprintf_s(pLogFile, "[-]ERROR: the state is not pending !.\n");
			 break;
		 }

		 fprintf_s(pLogFile, "[*]NOTE: the thread number %d is in the pending state ...\n", i);

	 }

	 WaitForMultipleObjectsEx(THREAD_NUMBER, hThread, TRUE, INFINITE, FALSE);

	 fprintf_s(pLogFile, "[+]DONE: all threads are out now.\n");

	 CloseHandle(hPipe);

 }
 
 /*
 SUMMARY:
	handler function for the service 
 */
 DWORD HandlerFunc(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext)
 {
	 switch (dwControl)
	 {
	 case SERVICE_CONTROL_INTERROGATE:
		 break;

	 case SERVICE_CONTROL_STOP:
		 OutputDebugStringA("Service Trying to stop\n");

		 ChangeServStatus(SERVICE_STOPPED);
		 break;

	 case SERVICE_CONTROL_PAUSE:
		 OutputDebugStringA("Service Trying to pause\n");
		 ChangeServStatus(SERVICE_PAUSED);
		 break;


	 case SERVICE_CONTROL_CONTINUE:
		 OutputDebugStringA("Service Trying to continue\n");

		 ChangeServStatus(SERVICE_RUNNING);
		 break;

	 default:
		 break;
	 }

	 return NO_ERROR;

 }

 /*
 SUMMARY:
	used to change the service status.
 */
 void ChangeServStatus(DWORD controlCode)
 {
	// the init: 	
	 if (controlCode == 0)
	 {
		 gServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
		 gServiceStatus.dwCurrentState = SERVICE_RUNNING;
		 gServiceStatus.dwControlsAccepted = 0;
	 }
	
	 // same status, then don't notify the SCM:
	 else if (gServiceStatus.dwCurrentState == controlCode)
		 return;

	 // change the status:
	 else
		 gServiceStatus.dwCurrentState = controlCode;

	 // notify the SCM:
	 SetServiceStatus(gHandleService, &gServiceStatus);

 }

 DWORD WINAPI ThreadProc(LPVOID parameter)
 {
	 OutputDebugString(L"NOW ENTERING THE THREAD +++");

	 PDATA_FROM_KERNEL dataFromKernel = NULL;
	 BUFFER_DATA Buffer = { 0 };
	 bool fFlag = false;
	 bool pFlag = false;
	 BOOL result;
	 BOOLEAN isInfected;

	 std::vector<MEMORY_BASIC_INFORMATION> MemBasicInfo;

	 PTHREAD_PARAMETERS threadPar = { 0 };
	 HANDLE hProcess;
	 int procID;
	 DWORD outSize;
	 ULONG_PTR key;
	 LPOVERLAPPED lpOverlapped;



	 if (parameter == NULL)
	 {
		 DbgMsg("Error while creating the pipe line, exiting. error code %d", GetLastError());
		 return 0;
	 }
	
	 threadPar = (PTHREAD_PARAMETERS)parameter;
	
	 OutputDebugString(L"NOW WE ACCEPTED THE DATA +++");

	 while (true)
	 {
		 result = GetQueuedCompletionStatus(threadPar->hCompletionRoutine, &outSize, &key, &lpOverlapped, INFINITE);

		 dataFromKernel = CONTAINING_RECORD(lpOverlapped, DATA_FROM_KERNEL, Overlapped);

		 if (!result)
		 {
			 fprintf_s(pLogFile, "[-] ERROR: while queing the completion routine.\n");
		 }

		 Buffer = dataFromKernel->BufferData;



		 if (Buffer.type == 0)
		 { 
			 fFlag = true;
			 OutputDebugString(L"ITS A FILE SCANNING ***");
		 }
		 else
		 {
			 OutputDebugString(L"ITS A PROCESS SCANNING ***");

			 pFlag = true;
		 }

		 if (fFlag)
		 {
			OutputDebugString(L"NOW SCANNING THE FILE :::");
			 // now scan the target file:
			const char* fileName = Buffer.buffer;

			fprintf_s(pLogFile, "[+] SCANNING FILE : %s***\n", fileName);

			OutputDebugStringA(fileName);
			 if ((yara.ScanFile(fileName)) != ERROR_SUCCESS)
				 fprintf_s(pLogFile, "error while scanning the file. error code %d\n", GetLastError());

			OutputDebugStringA("the file name is");
			OutputDebugStringA(Buffer.buffer);

			if (ruleMatchedFile == 0)
			{ 
				isInfected = FALSE;
				
				fprintf_s(pLogFile, "[+] THE FILE IS CLEAN ***\n");
			}
			else
			{
				isInfected = TRUE;

				fprintf_s(pLogFile, "[**] THE FILE IS NOT CLEAN...\n");
			}

			result = WriteFile(threadPar->hPipe, &isInfected, 1, nullptr, nullptr);

			if (!result)
				fprintf_s(pLogFile, "[-] ERROR: while sending the data to the controller. error code : %d.\n", GetLastError());

			else
				fprintf_s(pLogFile, "[+] SUCCESS: while sending the data to the controller.\n");

			 fprintf_s(pLogFile, "[+] THE FILE SCAN HAS FINISHED ***\n");

			 //restart the state..
			ruleMatchedFile = 0;

		 }

		 else if (pFlag)
	 {
		 // get the pid came from the user
		 procID = atoi(Buffer.buffer);
		 DbgMsg("the pid is : %d", procID);
		 DbgMsg("and from the buffer value is : %s", Buffer.buffer);

		 fprintf_s(pLogFile, "[+] SCANNING FOR PROCESS WITH PID : %d***\n", procID);

		 // a try to use ReadProcessMemory() api::
		 hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, procID);
		 if (hProcess == NULL)
		 {
			 DbgMsg("ERROR WHILE GETTING A HANDLE TO THE PORCESS FROM ITS PID. error code %d", GetLastError());
			 return -1;
		 }

		 // read the memory
		 MemBasicInfo = YaraNS::GetProcRegions(hProcess);


		 for (auto Inst : MemBasicInfo)
		 {
			 // read memory for every region
			 std::vector<byte> buffer = YaraNS::ReadMemory(hProcess, Inst.BaseAddress, Inst.RegionSize);

			 if (buffer.empty())
				 continue;

			 // now scan it:
			 yara.ScanMemory(buffer, &Inst);
		 }

		 CloseHandle(hProcess);
		 if (ruleMatchedProc == 0)
			fprintf_s(pLogFile, "[+] THE PROCESS IS CLEAN ***\n");

		 OutputDebugString(L"the scan has finished.");

	 }

		 else
			 OutputDebugString(L"THE PFLAG AND FFLAG BOTH ARE NOT SET !!!!!!!!!");

		 OutputDebugString(L"The thread has finished");

		 fprintf_s(pLogFile, "\n\n======================================================\n");
		 fprintf_s(pLogFile, "======================================================\n");
		 fprintf_s(pLogFile, "======================================================\n\n");
		
		 result = ReadFile(threadPar->hPipe, dataFromKernel, sizeof(DATA_FROM_KERNEL), NULL, &dataFromKernel->Overlapped);

		 if ((GetLastError()) != ERROR_IO_PENDING)
		 {
			 fprintf_s(pLogFile, "[-]ERROR: the state is not pending IN THE THREAD PROCEDURE!.\n");
			 break;
		 }

	 }

	 if (!result) {

		 fprintf_s(pLogFile, "[-]ERROR: the result error after thread terminate is : %d\n", GetLastError());


		 }
		 else {

			 fprintf_s(pLogFile, "[+]THREAD terminated correctly.\n");
		 }
	 

	 return 0;

 }


 void DbgMsg(const char* zcFormat, ...)
 {
	 // initialize use of the variable argument array
	 va_list vaArgs;
	 va_start(vaArgs, zcFormat);

	 // reliably acquire the size
	 // from a copy of the variable argument array
	 // and a functionally reliable call to mock the formatting
	 va_list vaArgsCopy;
	 va_copy(vaArgsCopy, vaArgs);
	 const int iLen = std::vsnprintf(NULL, 0, zcFormat, vaArgsCopy);
	 va_end(vaArgsCopy);

	 // return a formatted string without risking memory mismanagement
	 // and without assuming any compiler or platform specific behavior
	 std::vector<char> zc(iLen + 1);
	 std::vsnprintf(zc.data(), zc.size(), zcFormat, vaArgs);
	 va_end(vaArgs);
	 std::string strText(zc.data(), iLen);

	 OutputDebugStringA(strText.c_str());
 }

 void InitLogFile()
 {
	// first try
	 int errorCode;
	 if ((errorCode = fopen_s(&pLogFile, LOG_FILE_PATH, "a")) != 0)
	{
		DbgMsg("error while opening the log file ");
		ChangeServStatus(SERVICE_STOPPED);
	}

	DbgMsg("The Log file %s openned succesfully.", LOG_FILE_PATH);
 }


 /*
	WHAT I NEED TO DO:
	(DONE)	1) make it scans for the whole modules.
			=  
	(DONE)	2) give more details about the infected data regions, don't just say that if it's infected or not.
			- note: show only the identifier of the matched strings, not the value.

	(DONE)	*) add the  scanning of the directory to get all yara files
		3) do some error checking (not mandatory at this moment).
	(DONE)	4) clean your fucken cooodddeee.
		(DONE) 5) make it run as a service.
 */


 /*
	ALSO PROGRAMMING NOTE:
	FROM WHICH BASE SHOULD YOU SAY THAT BEFORE USING ANY POINTER, YOU SHOULD ALLOCATE A HEAP SPACE FOR IT?
	I THINK IS WHEN IT WILL JUST HAVE AN ADDRESS TO ALREADY ALLOCATED SPACE, YOU DON'T NEED TO ALLOCATE A SPACE FOR IT,
	BUT WHEN YOU HAVE DATA AND NO SPACE AND YOU WANT TO MAKE THIS POINTER POINTS TO THAT DATA, THEN AT THIS MOMENT YOU NEED TO
	ALLOCATE SPACE FOR THIS POINTER.
 */