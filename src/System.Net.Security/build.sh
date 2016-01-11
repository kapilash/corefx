#!/usr/bin/env bash

__scriptpath=/Users/kapilash/src/corefx
__packageroot=$__scriptpath/packages
__sourceroot=$__scriptpath/src
__nugetpath=$__packageroot/NuGet.exe
__nugetconfig=$__sourceroot/NuGet.Config
__msbuildpackageid="Microsoft.Build.Mono.Debug"
__msbuildpackageversion="14.1.0.0-prerelease"
__msbuildpath=$__packageroot/$__msbuildpackageid.$__msbuildpackageversion/lib/MSBuild.exe

if [ $(uname) == "Linux" ]; then
    __monoroot=/usr
elif [ $(uname) == "FreeBSD" ]; then
    __monoroot=/usr/local
else
    __monoroot=/Library/Frameworks/Mono.framework/Versions/Current
fi

__referenceassemblyroot=$__monoroot/lib/mono/xbuild-frameworks


__monoversion=$(mono --version | grep "version 4.[1-9]")



if [ $(uname) == "Linux" ]; then
    __osgroup=Linux
elif [ $(uname) == "FreeBSD" ]; then
    __osgroup=FreeBSD
else
    __osgroup=OSX
fi

MONO29679=1 ReferenceAssemblyRoot=$__referenceassemblyroot mono $__msbuildpath "$__buildproj" /nologo /verbosity:minimal "/fileloggerparameters:Verbosity=normal;LogFile=build.log" /t:Build /p:OSGroup=$__osgroup /p:UseRoslynCompiler=true /p:COMPUTERNAME=$(hostname) /p:USERNAME=$(id -un) "$@"

BUILDERRORLEVEL=$?

echo

# Pull the build summary from the log file
tail -n 4 "build.log"
echo Build Exit Code = $BUILDERRORLEVEL

if [ $BUILDERRORLEVEL -eq 0 ]; then
    echo "Build succeeded. Copying the file"
    cp $HOME/src/corefx/bin/OSX.AnyCPU.Debug/System.Net.Security/System.Net.Security.exe $HOME/net/net-demo/beta8/.
    echo "done"
else
    exit $BUILDERRORLEVEL
fi

echo "building native"

$HOME/src/corefx/build.sh native

BUILDERRORLEVEL=$?

if [ $BUILDERRORLEVEL -eq 0 ]; then
    echo "Build succeeded. Copying the file"
    cp $HOME/src/corefx/bin/OSX.x64.Debug/Native/System.Net.Security.Native.dylib $HOME/net/net-demo/beta8/.
fi
exit $BUILDERRORLEVEL
