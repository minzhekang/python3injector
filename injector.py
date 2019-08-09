# Coded by Min Zhe implemented in Python3
import platform
import colorama
from colorama import Fore, Back, Style
import win32com.client

import ctypes
from ctypes import wintypes
from ctypes.wintypes import BOOL
from ctypes.wintypes import DWORD
from ctypes.wintypes import HANDLE
from ctypes.wintypes import LPVOID
from ctypes.wintypes import LPCVOID
from ctypes.wintypes import LPCWSTR
from ctypes.wintypes import LPDWORD

import tkinter as tk
from tkinter import filedialog

colorama.init()
kernel32 = ctypes.WinDLL('Kernel32', use_last_error=True)
### C Parameters ###############################################################################################################################
SIZE_T = ctypes.c_size_t
LPSIZE_T = ctypes.POINTER(SIZE_T)
WCHAR_SIZE = ctypes.sizeof(wintypes.WCHAR)
LPSECURITY_ATTRIBUTES = wintypes.LPVOID
LPTHREAD_START_ROUTINE = wintypes.LPVOID

OpenProcess = kernel32.OpenProcess
OpenProcess.restype = HANDLE
OpenProcess.argtypes = (DWORD, BOOL, DWORD)

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.restype = LPVOID
VirtualAllocEx.argtypes = (HANDLE, LPVOID, SIZE_T, DWORD, DWORD)

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.restype = BOOL
WriteProcessMemory.argtypes = (HANDLE, LPVOID, LPCVOID, SIZE_T, LPSIZE_T)

CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.restype = HANDLE
CreateRemoteThread.argtypes = (HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T , LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD)


# https://www.aldeid.com/wiki/Process-Security-and-Access-Rights
PROCESS_VM_READ = 0x0010 # Required to read memory in a process using ReadProcessMemory. 
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008 # Required to write to memory in a process using WriteProcessMemory. 
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_CREATE_THREAD = 0x0002
PROCESS_ALL_ACCESS = (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD) #0x1F0FFF
################################################################################################################################################################

print(Fore.RED + 'Retrieving PIDs...')
print("[!] WARNING")
print("Your current python version is %s. Please use %s python to inject into %s processes." % (platform.architecture()[0],platform.architecture()[0],platform.architecture()[0] ))
WMI= win32com.client.GetObject('winmgmts:')
processes = WMI.ExecQuery('SELECT * from win32_process')
print(Fore.GREEN)
process_list = [i.Properties_('ProcessId').Value for i in processes] # list of available processes
for process in processes:
    print(process.Properties_('ProcessId').Value , " - " , process.Properties_('Name').Value)

PID = int(input('Enter the PID of the process '))

# https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, PID) # creating the handle
if not process_handle:
    print ("Couldn't acquire a handle to PID: %s" % PID)

root = tk.Tk()
root.withdraw()
dlladdr = filedialog.askopenfilename(title = "Select dll file",filetypes = (("dll files","*.dll"),("all files","*.*")))
size = (len(dlladdr) + 1) * WCHAR_SIZE # The size in bytes must be big enough for the injected dll. 

# https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
memory_alloc = kernel32.VirtualAllocEx(process_handle, None, size, (0x1000 | 0x2000), 0x40) # allocating memory to the process.
if not memory_alloc:
    print(ctypes.get_last_error())
# https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
write = kernel32.WriteProcessMemory(process_handle, memory_alloc, dlladdr, size, None) # writing memory to the process.
if not write:
    print(ctypes.get_last_error())
if not kernel32.CreateRemoteThread(process_handle, None, 0, kernel32.LoadLibraryW, memory_alloc, 0, None):
    print(ctypes.get_last_error())
    print("Failed injection...")

print("Process handle : ", process_handle)
print("VirtualAllocEx : ",memory_alloc)
print("WriteProcessMemory : ",write)
print("Successful injection!")
print(Fore.RED)
print("[!] WARNING")
print("Your current python version is %s. Please use %s python to inject into %s processes." % (platform.architecture()[0],platform.architecture()[0],platform.architecture()[0] ))
