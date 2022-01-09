//author https://github.com/frshy
#pragma once
#include <windows.h>
#include <TlHelp32.h>
#include <cstdint>

//settings
#define internal 1
#define use_namespace 0

#if use_namespace
namespace memory {
#endif

#if internal
	auto get_module_base_address( const char* module_name ) -> uintptr_t {
		return ( uintptr_t )GetModuleHandleA( module_name );
	}

	template <typename T>
	auto wpm( const uintptr_t address, const T value ) -> void {
		*( T* )address = value;
	}

	template <typename T>
	auto rpm( const uintptr_t address, const T value ) -> T {
		return *( T* )address;
	}

	auto patch( const uintptr_t address, const BYTE* bytes, const uint16_t size ) -> void {
		DWORD old_protection;
		VirtualProtect( ( void* )address, size, PAGE_EXECUTE_READWRITE, &old_protection );
		memcpy( ( void* )address, bytes, size );
		VirtualProtect( ( void* )address, size, old_protection, &old_protection );
	}

	auto nop( const uintptr_t address, const uint16_t size ) -> void {
		DWORD old_protection;
		VirtualProtect( ( void* )address, size, PAGE_EXECUTE_READWRITE, &old_protection );
		memset( ( void* )address, 0x90, size );
		VirtualProtect( ( void* )address, size, old_protection, &old_protection );
	}
#else
	auto get_process_id( const char* process_name ) -> DWORD {
		DWORD proc_id;
		PROCESSENTRY32 entry;
		entry.dwSize = sizeof( PROCESSENTRY32 );
		auto snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, NULL );
		if ( snapshot != INVALID_HANDLE_VALUE ) {
			if ( Process32First( snapshot, &entry ) == TRUE ) {
				do {
					if ( !strcmp( entry.szExeFile, process_name ) ) {
						proc_id = entry.th32ProcessID;
						break;
					}
				} while ( Process32Next( snapshot, &entry ) );
			}
		}

		CloseHandle( snapshot );
		return proc_id;
	}

	auto get_module_base_address( const DWORD proc_id, const char* module_name ) -> uintptr_t {
		uintptr_t module_base;
		auto snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, proc_id );

		if ( snapshot != INVALID_HANDLE_VALUE ) {
			MODULEENTRY32 module_entry;
			module_entry.dwSize = sizeof( module_entry );
			if ( Module32First( snapshot, &module_entry ) ) {
				do {
					if ( !strcmp( module_entry.szModule, module_name ) ) {
						module_base = (uintptr_t)module_entry.modBaseAddr;
						break;
					}
				} while ( Module32Next( snapshot, &module_entry ) );
			}
		}
		CloseHandle( snapshot );
		return module_base;
	}

	template <typename T>
	auto wpm( const HANDLE handle, const uintptr_t address, const T value) -> void {
		WriteProcessMemory( handle, ( void* )address, value, sizeof( value ), 0 );
	}

	template <typename T>
	auto rpm( const HANDLE handle, const uintptr_t address ) -> T {
		T value;
		ReadProcessMemory( handle, ( void* )address, &value, sizeof( value ), 0 );
		return value;
	}

	auto patch( const HANDLE handle, const uintptr_t address, const BYTE* bytes, const uint16_t size ) -> void {
		WriteProcessMemory( handle, ( void* )address, bytes, size, 0 );
	}

	auto open_process_by_pid( const DWORD proc_id ) -> HANDLE {
		return OpenProcess( PROCESS_ALL_ACCESS, 0, proc_id);
	}

	auto open_process_by_name( const char* process_name ) -> HANDLE {
		return OpenProcess( PROCESS_ALL_ACCESS, 0, get_process_id( process_name ) );
	}
#endif
	
#if use_namespace
}
#endif
