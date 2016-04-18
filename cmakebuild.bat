mkdir ..\wsbuild
cd ..\wsbuild
cmake -G "Visual Studio 12 Win64" ..\wireshark
msbuild /m /p:Configuration=RelWithDebInfo Wireshark.sln
