#pragma once
#include "imports.h"
#include <Windows.h>
#include <cstdint>
#include <vector>
#include <map>
#include <string>
#include <mutex>

static std::mutex mtx;

static void call_hook()
{
	static void* control_function = GetProcAddress(LoadLibrary("win32u.dll"), "NtDxgkCreateTrackedWorkload");
	static const auto control = static_cast<uint64_t(__stdcall*)()>(control_function);
	control();
}

extern HANDLE memoryRead, memoryWrite;

namespace driver
{
	static inline void close_handles()
	{
		CloseHandle(memoryRead);
		CloseHandle(memoryWrite);
		return;
	}


	static std::string GetLastErrorAsString()
	{
		//Get the error message, if any.
		DWORD errorMessageID = ::GetLastError();
		if (errorMessageID == 0)
			return std::string(); //No error message has been recorded

		LPSTR messageBuffer = nullptr;
		size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

		std::string message(messageBuffer, size);

		//Free the buffer.
		LocalFree(messageBuffer);

		return message;
	}

	static bool openMemoryHandle()
	{
		// Get Handle Read To Map
		memoryRead = OpenFileMapping(FILE_MAP_READ, FALSE, "Global\\SharedMEM");
		if (memoryRead == INVALID_HANDLE_VALUE || !memoryRead)
			return false;

		memoryWrite = OpenFileMapping(FILE_MAP_WRITE, FALSE, "Global\\SharedMEM");
		if (memoryWrite == INVALID_HANDLE_VALUE || !memoryWrite)
			return false;

		return true;
	}

	static void clearMap(copy_memory* map)
	{
		copy_memory m{ 0 };
		RtlCopyMemory(map, &m, sizeof(m));
	}
	//what u this do?
	static bool end(bool esp_driver = false)
	{
		copy_memory m = { 0 };
		m.called = TRUE;
		m.end = TRUE;
		m.get_pid = FALSE;
		m.get_base = FALSE;
		m.read = FALSE;
		m.readString = FALSE;
		m.write = FALSE;
		m.writeString = FALSE;
		m.changeProtection = FALSE;
		m.alloc_memory = FALSE;
		m.getThread_context = FALSE;
		m.setThread_context = FALSE;

		auto map_view = (copy_memory*)MapViewOfFile(memoryWrite, FILE_MAP_WRITE, 0, 0, 4096);
		if (!map_view)
		{
			std::cout << "[!] map_view failed" << std::endl;
			return false;
		}

		RtlCopyMemory(map_view, &m, sizeof(m));

		call_hook();
		clearMap(map_view);
		UnmapViewOfFile(map_view);
		return true;
		printf("Driver Closing...\nClosing Renderer...");
	}

	static bool getProcessID(const char* process_name)
	{
		copy_memory m = { 0 };
		m.called = TRUE;
		m.get_pid = TRUE;
		m.process_name = process_name;
		m.get_base = FALSE;
		m.read = FALSE;
		m.readString = FALSE;
		m.write = FALSE;
		m.writeString = FALSE;
		m.changeProtection = FALSE;
		m.alloc_memory = FALSE;
		m.getThread_context = FALSE;
		m.setThread_context = FALSE;

		auto map_view = (copy_memory*)MapViewOfFile(memoryWrite, FILE_MAP_WRITE, 0, 0, 4096);
		if (!map_view)
		{
			std::cout << "[!] map_view failed" << std::endl;
			return false;
		}

		RtlCopyMemory(map_view, &m, sizeof(m));

		call_hook();
		clearMap(map_view);
		UnmapViewOfFile(map_view);
		return true;
	}

	static void changeProtection(uint64_t address, uint32_t page_protection, std::size_t size)
	{
		if (!address)
			return;

		mtx.lock();
		copy_memory m = { 0 };
		m.called = TRUE;
		m.address = address;
		m.protection = page_protection;
		m.size = size;
		m.changeProtection = TRUE;
		m.get_pid = FALSE;
		m.get_base = FALSE;
		m.read = FALSE;
		m.readString = FALSE;
		m.write = FALSE;
		m.writeString = FALSE;
		m.alloc_memory = FALSE;
		m.protection_old = 0;
		m.getThread_context = FALSE;
		m.setThread_context = FALSE;

		auto map_view = (copy_memory*)MapViewOfFile(memoryWrite, FILE_MAP_WRITE, 0, 0, 4096);
		if (!map_view)
		{
			std::cout << "[!] map_view failed" << std::endl;
			return;
		}

		RtlCopyMemory(map_view, &m, sizeof(m));
		call_hook();

		clearMap(map_view);
		UnmapViewOfFile(map_view);
		mtx.unlock();
	}

	static ULONG64 getModuleBase(const char* module_name)
	{
		copy_memory m = { 0 };
		m.called = TRUE;

		m.get_base = TRUE;
		m.read = FALSE;
		m.get_pid = FALSE;
		m.readString = FALSE;
		m.write = FALSE;
		m.writeString = FALSE;
		m.module_name = module_name;
		m.changeProtection = FALSE;
		m.alloc_memory = FALSE;
		m.getThread_context = FALSE;
		m.setThread_context = FALSE;

		auto map_view = (copy_memory*)MapViewOfFile(memoryWrite, FILE_MAP_WRITE, 0, 0, 4096);
		if (!map_view)
		{
			std::cout << "[!] map_view failed" << std::endl;
			return NULL;
		}

		RtlCopyMemory(map_view, &m, sizeof(m));
		call_hook();

		auto received = (copy_memory*)MapViewOfFile(memoryRead, FILE_MAP_READ, 0, 0, sizeof(copy_memory));
		if (!received)
		{
			std::cout << "[!] failed to read received" << std::endl;
			return NULL;
		}

		auto temp = received->base_address;
		UnmapViewOfFile(received);
		clearMap(map_view);
		UnmapViewOfFile(map_view);
		return temp;
	}

	template <class T>
	T read(UINT_PTR ReadAddress, bool esp_driver = false)
	{
		if (!ReadAddress)
			return T{};
		//auto clockStart = std::chrono::high_resolution_clock::now();
		mtx.lock();
		//auto clockEnd = std::chrono::high_resolution_clock::now();
		//float fps =  (clockEnd - clockStart).count();
		//std::cout << std::fixed << fps << std::endl;
		T response{};

		copy_memory m;
		m.called = TRUE;
		m.size = sizeof(T);
		m.address = ReadAddress;
		m.read = TRUE;
		m.get_pid = FALSE;
		m.readString = FALSE;
		m.writeString = FALSE;
		m.write = FALSE;
		m.get_base = FALSE;
		m.changeProtection = FALSE;
		m.alloc_memory = FALSE;
		m.output = &response;
		m.getThread_context = FALSE;
		m.setThread_context = FALSE;

		auto map_view = (copy_memory*)MapViewOfFile(memoryWrite, FILE_MAP_WRITE, 0, 0, 4096);

		if (!map_view)
		{
			std::cout << "[!] map_view failed: " << GetLastErrorAsString() << std::endl;
			return T{};
		}

		RtlCopyMemory(map_view, &m, sizeof(m));

		call_hook();
		clearMap(map_view);
		//UnmapViewOfFile(map_view);

		auto temp = response;
		mtx.unlock();
		return temp;
	}

	static void read(UINT_PTR ReadAddress, void* buffer, uintptr_t size, bool esp_driver = false)
	{
		if (!ReadAddress)
			return;

		mtx.lock();

		copy_memory m;
		m.called = TRUE;
		m.size = size;
		m.address = ReadAddress;
		m.read = TRUE;
		m.get_pid = FALSE;
		m.readString = FALSE;
		m.writeString = FALSE;
		m.write = FALSE;
		m.get_base = FALSE;
		m.changeProtection = FALSE;
		m.alloc_memory = FALSE;
		m.output = buffer;
		m.getThread_context = FALSE;
		m.setThread_context = FALSE;

		auto map_view = (copy_memory*)MapViewOfFile(memoryWrite, FILE_MAP_WRITE, 0, 0, 4096);

		if (!map_view)
		{
			std::cout << "[!] map_view failed: " << GetLastErrorAsString() << std::endl;
			return;
		}

		RtlCopyMemory(map_view, &m, sizeof(m));

		call_hook();
		clearMap(map_view);
		//UnmapViewOfFile(map_view);
		mtx.unlock();
	}

	static bool WriteVirtualMemoryRaw(UINT_PTR WriteAddress, UINT_PTR SourceAddress, SIZE_T WriteSize);

	template<typename S>
	bool write(UINT_PTR WriteAddress, const S& value)
	{
		if (!WriteAddress)
			return false;

		return WriteVirtualMemoryRaw(WriteAddress, (UINT_PTR)&value, sizeof(S));
	}
	bool WriteVirtualMemoryRaw(UINT_PTR WriteAddress, UINT_PTR SourceAddress, SIZE_T WriteSize)
	{
		mtx.lock();
		copy_memory m;
		m.called = TRUE;
		m.address = WriteAddress;
		m.pid_of_source = GetCurrentProcessId();
		m.write = TRUE;
		m.get_pid = FALSE;
		m.read = FALSE;
		m.readString = FALSE;
		m.get_base = FALSE;
		m.writeString = FALSE;
		m.changeProtection = FALSE;
		m.buffer_address = (void*)SourceAddress;
		m.size = WriteSize;
		m.alloc_memory = FALSE;
		m.getThread_context = FALSE;
		m.setThread_context = FALSE;

		auto map_view = (copy_memory*)MapViewOfFile(memoryWrite, FILE_MAP_WRITE, 0, 0, 4096);
		if (!map_view)
		{
			std::cout << "[!] map_view failed" << std::endl;
			return false;
		}

		RtlCopyMemory(map_view, &m, sizeof(m));

		call_hook();
		clearMap(map_view);
		//UnmapViewOfFile(map_view);

		mtx.unlock();
		return true;
	}

	static std::string readString(UINT_PTR String_address, SIZE_T size, bool esp_driver = false)
	{
		std::unique_ptr<char[]> buffer(new char[size]);
		read(String_address, buffer.get(), size);
		return std::string(buffer.get());
	}

	static std::wstring ReadUnicode(uint64_t address)
	{
		// Allocate our buffer with string size
		wchar_t buffer[1024 * sizeof(wchar_t)];

		// Read the string at address into the buffer
		read(address, &buffer, 1024 * sizeof(wchar_t));

		// Convert the buffer to a std::wstring and return
		return std::wstring(buffer);
	}

	static std::wstring read_wstring(UINT_PTR String_address, SIZE_T size)
	{
		const auto buffer = std::make_unique<wchar_t[]>(size);
		read(String_address, buffer.get(), size * 2);
		return std::wstring(buffer.get());
	}

	static bool writeString(UINT_PTR String_address, void* buffer, SIZE_T size)
	{
		if (!String_address)
			return false;

		mtx.lock();
		copy_memory m;
		m.called = TRUE;
		m.writeString = TRUE;
		m.read = FALSE;
		m.get_pid = FALSE;
		m.readString = FALSE;
		m.get_base = FALSE;
		m.write = FALSE;
		m.address = String_address;
		m.buffer_address = buffer;
		m.size = size;
		m.changeProtection = FALSE;
		m.alloc_memory = FALSE;
		m.getThread_context = FALSE;
		m.setThread_context = FALSE;

		auto map_view = (copy_memory*)MapViewOfFile(memoryWrite, FILE_MAP_WRITE, 0, 0, 4096);
		if (!map_view)
		{
			std::cout << "[!] map_view failed" << std::endl;
			return false;
		}

		RtlCopyMemory(map_view, &m, sizeof(m));

		call_hook();
		clearMap(map_view);
		UnmapViewOfFile(map_view);

		mtx.unlock();
		return true;
	}

	static UINT_PTR virtualAlloc(UINT_PTR ReadAddress, ULONG alloc_type, SIZE_T size)
	{
		if (!ReadAddress)
			return false;

		mtx.lock();
		copy_memory m;
		m.called = TRUE;
		m.address = ReadAddress;
		m.read = FALSE;
		m.get_pid = FALSE;
		m.readString = FALSE;
		m.writeString = FALSE;
		m.write = FALSE;
		m.get_base = FALSE;
		m.changeProtection = FALSE;
		m.alloc_memory = TRUE;
		m.alloc_type = alloc_type;
		m.size = size;
		m.getThread_context = FALSE;
		m.setThread_context = FALSE;

		auto map_view = (copy_memory*)MapViewOfFile(memoryWrite, FILE_MAP_WRITE, 0, 0, 4096);
		if (!map_view)
		{
			std::cout << "[!] map_view failed" << std::endl;
			return false;
		}

		RtlCopyMemory(map_view, &m, sizeof(m));

		call_hook();

		auto received = (copy_memory*)MapViewOfFile(memoryRead, FILE_MAP_READ, 0, 0, sizeof(copy_memory));
		if (!received)
		{
			std::cout << "[!] failed to read received" << std::endl;
			return NULL;
		}

		auto temp = received->output;
		UnmapViewOfFile(received);
		clearMap(map_view);
		UnmapViewOfFile(map_view);

		mtx.unlock();
		return *(UINT_PTR*)&temp;
	}

	static bool getThread(HWND window_handle, uint64_t* thread_context)
	{
		mtx.lock();
		copy_memory m;
		m.called = TRUE;
		m.read = FALSE;
		m.get_pid = FALSE;
		m.readString = FALSE;
		m.writeString = FALSE;
		m.write = FALSE;
		m.get_base = FALSE;
		m.changeProtection = FALSE;
		m.alloc_memory = FALSE;
		m.getThread_context = TRUE;
		m.setThread_context = FALSE;
		m.window_handle = window_handle;

		auto map_view = (copy_memory*)MapViewOfFile(memoryWrite, FILE_MAP_WRITE, 0, 0, 4096);
		if (!map_view)
		{
			std::cout << "[!] map_view failed" << std::endl;
			return false;
		}

		RtlCopyMemory(map_view, &m, sizeof(m));

		call_hook();

		auto received = (copy_memory*)MapViewOfFile(memoryRead, FILE_MAP_READ, 0, 0, sizeof(copy_memory));
		if (!received)
		{
			std::cout << "[!] failed to read received" << std::endl;
			return false;
		}

		*thread_context = *(UINT_PTR*)&received->output;
		UnmapViewOfFile(received);
		clearMap(map_view);
		UnmapViewOfFile(map_view);

		mtx.unlock();
		return true;
	}

	static bool setThread(HWND window_handle, uint64_t thread_context)
	{
		mtx.lock();
		copy_memory m;
		m.called = TRUE;
		m.read = FALSE;
		m.get_pid = FALSE;
		m.readString = FALSE;
		m.writeString = FALSE;
		m.write = FALSE;
		m.get_base = FALSE;
		m.changeProtection = FALSE;
		m.alloc_memory = FALSE;
		m.getThread_context = FALSE;
		m.setThread_context = TRUE;
		m.window_handle = window_handle;
		m.thread_context = thread_context;

		auto map_view = (copy_memory*)MapViewOfFile(memoryWrite, FILE_MAP_WRITE, 0, 0, 4096);
		if (!map_view)
		{
			std::cout << "[!] map_view failed" << std::endl;
			return false;
		}

		RtlCopyMemory(map_view, &m, sizeof(m));

		call_hook();
		clearMap(map_view);
		UnmapViewOfFile(map_view);

		mtx.unlock();
		return true;
	}
	template<typename Type>
	static Type readChain(uintptr_t address, std::vector<uintptr_t> chain)
	{
		uintptr_t current = address;
		for (int i = 0; i < chain.size() - 1; i++)
		{
			current = driver::read<uintptr_t>(current + chain[i]);
		}
		return driver::read<Type>(current + chain[chain.size() - 1]);
	}
}

