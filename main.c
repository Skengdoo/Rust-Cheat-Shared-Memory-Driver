#include <ntifs.h>
#include "imports.h"
#include "Hooks/hk.h"
#include "SharedMEM/helpers.h"
#include "SharedMEM/ThreadContext.hpp"

HANDLE pid;
PEPROCESS process;
ULONG64 base_addy = NULL;
ULONG64 base_addy_two = NULL;

char(*original_event)(PVOID a1);

char hooked_event(PVOID a1)
{
	static BOOLEAN do_once = TRUE;
	if (do_once)
	{
		DbgPrintEx(0, 0, "[Shared MEM] Hook Called");
		do_once = FALSE;
	}

	if (!NT_SUCCESS(read_shared_memory()))
		return "";

	if (!shared_section)
		return "";

	copy_memory* m = (copy_memory*)shared_section;
	if (!m)
		return "";

	

	if (m->get_pid != FALSE)
		GetPid(&pid, m->process_name);
	else if (m->change_protection != FALSE)
		protect_virtual_memory(process, (PVOID)m->address, m->size, m->protection, m->protection_old);
	else if (m->get_base != FALSE)
	{
		ANSI_STRING AS;
		UNICODE_STRING ModuleNAme;

		RtlInitAnsiString(&AS, m->module_name);
		RtlAnsiStringToUnicodeString(&ModuleNAme, &AS, TRUE);

		PsLookupProcessByProcessId((HANDLE)pid, &process);
		if (!base_addy)
		{
			base_addy = get_module_base_x64(process, ModuleNAme);
			DbgPrintEx(0, 0, "\nBase of %wZ aquired: %p", ModuleNAme, base_addy);
			m->base_address = base_addy;
		}
		else
		{
			base_addy_two = get_module_base_x64(process, ModuleNAme);
			DbgPrintEx(0, 0, "\nBase of %wZ aquired: %p", ModuleNAme, base_addy_two);
			m->base_address = base_addy_two;
		}

		RtlFreeUnicodeString(&ModuleNAme);

		if (memcpy(shared_section, m, sizeof(copy_memory)) == 0)
			DbgPrintEx(0, 0, "Sending copy_memory back failed\n");

		//static DWORD old;
		//if (!old)
		//{
		//	protect_virtual_memory(pid, base_addy + 0x5AE06F0, sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &old);
		//}
	}
	else if (m->write != FALSE) 
	{
		PVOID kernelBuff = ExAllocatePool(NonPagedPool, m->size);

		if (!kernelBuff)
			return "";

		if (!memcpy(kernelBuff, m->buffer_address, m->size))
			return "";

		write_kernel_memory(process, m->address, kernelBuff, m->size);
		ExFreePool(kernelBuff);
	}
	else if (m->read != FALSE)
	{
		read_kernel_memory(process, m->address, m->output, m->size);
	}
	else if (m->read_string != FALSE) 
	{
		PVOID kernelBuffer = ExAllocatePool(NonPagedPool, m->size);

		if (!kernelBuffer)
			return "";

		if (!memcpy(kernelBuffer, m->buffer_address, m->size))
			return "";

		read_kernel_memory(process, m->address, kernelBuffer, m->size);

		RtlZeroMemory(m->buffer_address, m->size);

		if (!memcpy(m->buffer_address, kernelBuffer, m->size))
			return "";

		DbgPrintEx(0, 0, "String read: %s", (const char*)kernelBuffer);

		ExFreePool(kernelBuffer);
	}
	else if (m->write_string != FALSE) 
	{
		PVOID kernelBuffer1 = ExAllocatePool(NonPagedPool, m->size);

		if (!kernelBuffer1)
			return "";

		if (!memcpy(kernelBuffer1, m->buffer_address, m->size))
			return "";

		write_kernel_memory(process, m->address, kernelBuffer1, m->size);

		ExFreePool(kernelBuffer1);
	}
	else if (m->alloc_memory != FALSE)
	{
		PVOID AllocatedMemory = virtual_alloc(m->address, MEM_COMMIT, m->alloc_type, m->size, process);
		m->output = AllocatedMemory;
		if (memcpy(shared_section, m, sizeof(copy_memory)) == 0)
			DbgPrintEx(0, 0, "Sending copy_memory back failed\n");

		DbgPrintEx(0, 0, "\nAllocated at: %p\n", AllocatedMemory);
	}	
	else if (m->get_thread_context != FALSE)
		getThreadContext(m);
	else if (m->set_thread_context != FALSE)
		setThreadContext(m);
	else if (m->end != FALSE)
	{
		if (shared_section)
			ZwUnmapViewOfSection(NtCurrentProcess(), shared_section);
		if (g_Section)
			ZwClose(g_Section);
	}

	return "";
}
PWORK_QUEUE_ITEM WorkItem;
#define MEMORYTAG "MEMTag"
void creatSharedMemoryWorkItem()
{
	if (!NT_SUCCESS(create_shared_memory()))
	{
		DbgPrintEx(0, 0, "[Shared MEM] failed to create SharedMemory\n");
		return;
	}	
	HkDetourFunction(get_system_module_export("\\SystemRoot\\System32\\drivers\\watchdog.sys", "WdLogEvent5_WdError"), (PVOID)hooked_event, 16, (PVOID*)&original_event);
	ExFreePoolWithTag(WorkItem, MEMORYTAG);
	return;
}

void Initialize()
{
	DbgPrintEx(0, 0, "[Shared MEM] Entry Called.");
	KeEnterGuardedRegion();
	WorkItem = (PWORK_QUEUE_ITEM)ExAllocatePoolWithTag(NonPagedPool, sizeof(PWORK_QUEUE_ITEM), MEMORYTAG);
	ExInitializeWorkItem(WorkItem, creatSharedMemoryWorkItem, WorkItem);
	ExQueueWorkItem(WorkItem, DelayedWorkQueue);
	KeLeaveGuardedRegion();
	DbgPrintEx(0, 0, "[Shared MEM] Hooks Initiated!");
	
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObj, _In_ PUNICODE_STRING RegistryPath)
{
	DbgPrintEx(0, 0, "Driver Initialized.\n");

	// Fix Paramms
	UNREFERENCED_PARAMETER(RegistryPath);
	UNREFERENCED_PARAMETER(DriverObj);

	Initialize();
	
	return STATUS_SUCCESS;
}
