#pragma once
#include <msxml.h>    
#include <atomic>
#include <mutex>
#include <Windows.h>
#include <TlHelp32.h>
#include <cstdint>
#include <vector>
#include <random>
#include <memoryapi.h>
#include <string>
#include <thread>
#include <chrono>
#include <iostream>
#include "driver.h"
typedef struct _copy_memory
{
	BOOLEAN called;
	BOOLEAN read;
	BOOLEAN readString;
	void* buffer_address;
	UINT_PTR  address;
	ULONGLONG size;
	void* output;

	BOOLEAN   write;
	BOOLEAN writeString;

	BOOLEAN  get_base;
	ULONG64 base_address;
	const char* module_name;

	BOOLEAN get_pid;
	const char* process_name;
	ULONG pid_of_source;

	BOOLEAN alloc_memory;
	ULONG	alloc_type;

	BOOLEAN		changeProtection;
	ULONG		protection;
	ULONG		protection_old;

	BOOLEAN getThread_context;
	BOOLEAN setThread_context;

	BOOLEAN end;

	HWND window_handle;
	UINT_PTR thread_context;
}copy_memory;