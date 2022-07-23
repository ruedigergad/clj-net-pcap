This library is taken from WpdPack 4.1.2, unzipped into this directory.

The mingw-w64 toolchain has a bug, where it will link properly during compile 
against the provided wpcap.lib file, but will fail against the runtime .dll
file found in \windows\syswow64 directory. Here is a work around the
mingw-w64 developers gave me to generate a libwpcap.a file that g++ can link
instead that will generate the proper jnetpcap.dll file.

Take the x64 version of your wpcap.dll, do:
gendef wpcap.dll

... then run:
dlltool --as-flags=--64 -m i386:x86-64 -k --output-lib libwpcap.a --input-def wpcap.def

.. and use the generated libwpcap.a for the linkage.

Here is a link to the entire discussion:

http://sourceforge.net/projects/mingw-w64/forums/forum/723797/topic/3882579

So instead of actually doing this everytime, I have decided to just check in the fixed
up libwpcap.a file along with the real wpcap dev libraries. This readme servers as
instructions as how to regenerate the library for future wpd libraries. Hopefully
binutils will be fixed soon or winpcap folks will include the x64/libwpcap.a file in
future releases like they do for the 32-bit libraries.

Cheers,
mark...
2010-10-06