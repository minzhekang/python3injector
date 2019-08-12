# Assault cube trainer by Min Zhe
import win32com.client
import ctypes
from ctypes import wintypes
from ctypes import WinError
import sys
WMI = win32com.client.GetObject('winmgmts:')
processes = WMI.ExecQuery('SELECT * from win32_process')

names = []
ids = []
for process in processes:
    names.append(process.Properties_('Name').Value)
    ids.append(process.Properties_('ProcessId').Value)
if "ac_client.exe" in names:
    PID = ids[(names.index('ac_client.exe'))]
    print("PID is ", PID)
    print("ac_client.exe found!")
else:
    print("ac_client.exe not found!")
    print("exiting now...")
    sys.exit(0)

# Parameters for access rights.

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

# defining handles.

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

OpenProcess = kernel32.OpenProcess
OpenProcess.restype = wintypes.HANDLE
OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.restype = wintypes.BOOL
WriteProcessMemory.argtypes = (wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t , ctypes.POINTER( ctypes.c_size_t ))

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.restype = wintypes.BOOL # LPCVOID A pointer to a CONSTANT of any type.
ReadProcessMemory.argtypes = (wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t , ctypes.POINTER( ctypes.c_size_t ))

CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.restype = wintypes.HANDLE
CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)



class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [ ( 'dwSize' , ctypes.c_uint ) , 
                 ( 'cntUsage' , ctypes.c_uint) ,
                 ( 'th32ProcessID' , ctypes.c_uint) ,
                 ( 'th32DefaultHeapID' , ctypes.c_uint) ,
                 ( 'th32ModuleID' , ctypes.c_uint) ,
                 ( 'cntThreads' , ctypes.c_uint) ,
                 ( 'th32ParentProcessID' , ctypes.c_uint) ,
                 ( 'pcPriClassBase' , ctypes.c_long) ,
                 ( 'dwFlags' , ctypes.c_uint) ,
                 ( 'szExeFile' , ctypes.c_char * 260 ) , 
                 ( 'th32MemoryBase' , ctypes.c_long) ,
                 ( 'th32AccessKey' , ctypes.c_long ) ]

class MODULEENTRY32(ctypes.Structure):
    _fields_ = [( 'dwSize' , wintypes.DWORD ) , 
                ( 'th32ModuleID' ,  wintypes.DWORD ),
                ( 'th32ProcessID' ,  wintypes.DWORD ),
                ( 'GlblcntUsage' ,  wintypes.DWORD ),
                ( 'ProccntUsage' ,  wintypes.DWORD ) ,
                ( 'modBaseAddr' , ctypes.POINTER( wintypes.BYTE) ) ,
                ( 'modBaseSize' ,  wintypes.DWORD ) , 
                ( 'hModule' ,  wintypes.HMODULE ) ,
                ( 'szModule' , ctypes.c_char * 256 ),
                ( 'szExePath' , ctypes.c_char * 260 ) ]


def OpenProcessFunc(dwProcessId): # Open a handle to the process
    dwDesiredAccess = (PROCESS_QUERY_INFORMATION |
                           PROCESS_VM_OPERATION |
                           PROCESS_VM_READ | PROCESS_VM_WRITE)
    bInheritHandle = False
    hProcess = OpenProcess(
                            dwDesiredAccess,
                            bInheritHandle,
                            dwProcessId
                            )
    if not hProcess:
        raise WinError(ctypes.get_last_error())
    
    return hProcess

def ReadProcessMemoryFunc(hProcess, lpBaseAddress): 
 
    lpBaseAddress = lpBaseAddress # Reading the ammo's address
    ReadBuffer = ctypes.c_uint()
    lpBuffer = ctypes.byref(ReadBuffer)
    nSize = ctypes.sizeof(ReadBuffer)
    lpNumberOfBytesRead = None

    ReadProcMemory = ReadProcessMemory(
                        hProcess,
                        lpBaseAddress,
                        lpBuffer,
                        nSize,
                        lpNumberOfBytesRead
                        );       

    if not ReadProcMemory:
        kernel32.CloseHandle(hProcess)
        raise WinError(ctypes.get_last_error())

    
    return ReadBuffer.value, hex(lpBaseAddress)


def WriteProcessMemoryFunc(hProcess, lpBaseAddress, Value):
    
    lpBaseAddress = lpBaseAddress
    Value = Value
    WriteBuffer = ctypes.c_uint(Value)
    lpBuffer = ctypes.byref(WriteBuffer) # byref gives the pointer to the value.
    nSize = ctypes.sizeof(WriteBuffer)
    lpNumberOfBytesWritten = None

    WriteProcMemory = WriteProcessMemory(
                                        hProcess,
                                        lpBaseAddress,
                                        lpBuffer,
                                        nSize,
                                        lpNumberOfBytesWritten
                                        );
    
    if not WriteProcMemory:
        kernel32.CloseHandle(hProcess)
        raise WinError(ctypes.get_last_error())
    

def getBasePointer(hProcess, lpBaseAddress, offsets):
    value, address = ReadProcessMemoryFunc(hProcess, lpBaseAddress)
    
    if offsets == None:
        return lpBaseAddress
    elif len(offsets) == 1:
        onelevelvalue = int(str(value), 0) + int(str(offsets[0]), 0)
        return onelevelvalue
    else:
        count = len(offsets)
        for i in offsets:
            count -= 1
            temp = int(str(value), 0) + int(str(i), 0)
            value, address  = ReadProcessMemoryFunc(hProcess, temp)
        
        return value, int(str(address), 0) # this is to return it in hexadecimal form


def GetModuleBaseAddrFunc(PID, modName):

    me32 = MODULEENTRY32()
    me32.dwSize = ctypes.sizeof(MODULEENTRY32)
    hSnap = CreateToolhelp32Snapshot( (TH32CS_SNAPMODULE| TH32CS_SNAPMODULE32), PID )
    mod = kernel32.Module32First(hSnap, ctypes.byref(me32)) #returns True if successful

    if mod == 0:
        print("Error getting {} base address".format(modName), ctypes.get_last_error())
        kernel32.CloseHandle(hSnap)
        return False
    while mod:
        if me32.szModule.decode() == modName:
            kernel32.CloseHandle(hSnap)
            #print(hex(id(me32.modBaseAddr))) # WARNING THIS RETURNS THE MEMORY OF LP_c_byte object! not the process!
            # https://stackoverflow.com/questions/32700886/convert-memory-address-from-pointerbyte-type-to-hex
            print(hex(ctypes.addressof(me32.modBaseAddr.contents))) # this returns the memory of the process :)
            return me32.modBaseAddr
        else:
            mod = kernel32.Module32Next(hSnap, ctypes.byref(me32))

# GetModuleHandle(None)) Only works if the DLL is loaded in the process.
# Usage for GetModuleBaseAddrFunc is - print(GetModuleBaseAddrFunc(PID, 'ac_client.exe'))


# Main body of trainer
hProcess = OpenProcessFunc(PID)
ammo, ammoaddress = getBasePointer(hProcess, 0x00509B74, [0x384,0x14,0x0]) # add in offsets
WriteProcessMemoryFunc(hProcess, ammoaddress, 100) # Last value is the ammo value in integer
print("Current value ammo is: ", ammo)
print("Current address of ammo is: ", hex(ammoaddress))
# Tested and working on 12/8/19 