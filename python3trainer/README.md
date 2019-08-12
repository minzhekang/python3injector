![trainer](https://media.giphy.com/media/l0phAXbyTJ9hdFIPos/giphy.gif)

Trainer made for assault cube using the lessons learnt from writing an injector. Approach is slightly different here where I didn't 
use `LoadLibraryW` to fire up the dll file within the process. Instead, the multi-level pointer was found using Cheat Engine and the
address variables were passed into the python application using ctypes. `WriteProcessMemory` and `ReadProcessMemory` is then used to
read the memory of the game files and then write to it accordingly.

This was done in revision to the things that I've learnt when i was meddling around with `vb.net` and `.NET` framework when i was 14.
Lessons learnt were solely for educational purposes in efforts to increase my knowledge in `C++` and `ctypes`. Please do not use this for malicious
causes.
