This document describes how to compile openGalaxy for Windows 7 SP1 and higher.
-------------------------------------------------------------------------------

openGalaxy uses the MSYS2 platform to build the Windows executables.
MSYS2 may be downloaded from sourceforge.

http://sourceforge.net/projects/msys2/

Install in the default location (C:\msys32 or C:\msys64)
(I have not tested any other location with openGalaxy)


To build openGalaxy you need the following software in addition to MSYS2:
-------------------------------------------------------------------------

- libmysqlclient

  Download and install MySQL Connector/C 6.1 from:
  http://dev.mysql.com/downloads/connector/c/
  (Download the Microsoft Windows (x86, 32/64-bit) MSI Installer).

  openGalaxy expects the default installation path,
  but this may be changed by using the --with-mysql option
  to openGalaxy's configure script. Under windows the
  argument to this option should point to the base directory
  of the MYSQL Connector installation (not to the mysql_config
  tool which does not exist for the windows installation), ie:
  --with-mysql="C:/ProgramFiles(x86)/MySQL/MySQL Connector C 6.1"

  You can disable this dependency with the --without-mysql-plugin
  to openGalaxy's configure script.


- Nullsoft Scriptable Install System 3.x (NSIS)

  This software may be downloaded from sourceforge at:
  http://sourceforge.net/projects/nsis/

  Make sure that you download version 3.x and that
  makensis.exe can be found on the PATH

  To add 'makensis' to the PATH, install NSIS in the directory C:\NSIS
  then add the following to your ~/.bash_profile :

  PATH="${PATH}:/c/NSIS/Bin"


Configuring MSYS2 [32bit]:
--------------------------

- open the 'MSYS2 Shell' and run:

pacman -Sy
pacman -Su

  To update the system.
  When it is finished exit the shell with CRTL+D (or by closing the
  window directly if instructed by pacman).

With MSYS2 32bit:

  - Start msys2 with 'MinGw-w64 Win32 Shell' and install these packages:

  pacman -S mingw-w64-i686-gcc mingw-w64-i686-gdb mingw-w64-i686-gtk3 mingw-w64-i686-cmake mingw-w64-i686-ghostscript
  pacman -S mc make vim pkg-config tar xz diffutils autoconf automake libtool upx man wget patch git

With MSYS2 64bit:

  - Start msys2 with 'MinGw-w64 Win64 Shell' and install these packages:

pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-gdb mingw-w64-x86_64-gtk3 mingw-w64-x86_64-cmake mingw-w64-x86_64-ghostscript
pacman -S mc make vim pkg-config tar xz diffutils autoconf automake libtool upx man wget patch git



Building the openGalaxy installer package:
------------------------------------------

  Place the zipped sourcecode to openGalaxy in your MSYS2 home directory,
  start a MinGW64 32bit or 64bit shell and execute the commands:

tar xf galaxy-[version].tar.gz
cd galaxy-[version]
mkdir build && cd build
../mingw-build ..

  When the build script is finished you should end up with the installable
  openGalaxy package in the current directory.

