# python3injector
A python3 injector made with ctypes, DLL file is obtained from https://github.com/carterjones/hello-world-dll

Tested and working on python 3.6.8 (64bit).

![working example](https://media.giphy.com/media/Lo6yGQm9CiFCUjxCWy/giphy.gif)

This was done for educational purposes to learn more about ctypes. Please do not use this for malicious intentions.
[!] Note that injection will not work on same apps such as (calc.exe) in windows vista and above because of session separation because of the usage of "CreateRemoteThread", "NtCreateThreadEx" is preferred in this case.
