jNetPcap OS version 1.5.r1500 is the latest quick release.

* Release date: 2021-05-18

* Project website: http://jnetpcap.com
  - Community Support: http://jnetpcap.com/forum/support
  - Dedicated Support (with contract): http://support.slytechs.com
  
* Authors: Sly Technologies Inc

* Company information:
  Sly Technologies� Inc. specializes in native and "Java" middle-ware platforms 
  for working with network communication protocols and data.
  
  - Sales: sales@slytechs.com or  (888) 789-6499 ext 1

* License: LGPL v3

* The distro provides packages for the following architectures:
  - Windows 32-bit - Windows XP or higher
  - Windows 64-bit - Windows 7 or higher
  - Linux 32-bit - Any Linux kernel 2.4 or higher
  - Linux 64-bit - Any Linux kernel 2.4 or higher
  - RHEL5 64-bit - RHEL 5 and RHEL 6
  - Other: jNetPcap OS can be compiled for many other architectures from source:
  	+ AIX
  	+ Solaris (Intel/Sparc)
  	+ Android OS
  	+ OS X
  	+ HP/UX
  	+ ARM

+ Note: Source and javadoc packages are also provided with full reference documentation 
        and source

* To install
  - Unpack the package to a private directory
  - Install WinPcap/Libpcap pre-requisites 
  
* Documentation
  - Userguide: http://jnetpcap.com/userguide
  - Examples:  http://jnetpcap.com/examples
  - Tutorials: http://jnetpcap.com/tutorial

* Changes: == Release 1.5.r1500 (2021-05-18) ==
  - Upgrades JRE support to Java 9+
  - Added module-info.java and exports
  - Updated build scripts to support latest Linux
  - Updated build script to use 'javac' instead of deprecated 'javah' for JNI headers
  - Fixed up java classes with native calls for new 'javac' requirements 

* Bug fixes: == Release 1.4.r1425 (2013-08-19) ==

Bug #133	Wrong assumption about multiplicity of headers
Bug #132	BufferUnderFlowException caused by hard-coded offset
Bug #131	org.jnetpcap.nio.JMemory.tranferFrom uses incorrect value for dstOffset
Bug #130	JRegistry.toDebugString throw null pointer exception
Bug #129	Exception in thread "DisposableGC" java.lang.Error: Maximum
Bug #128	PcapSockAddr.toString() should use standard IPv6
Bug #125	FormatUtils.asStringIp6 prepends byte values < 0 with zeros
Bug #124	AnnotatedMethod permission issue
Bug #122	Maximum permit count exceeded, semaphores
Bug #119	Wrong path to pcap library
Bug #118	DTMF RTP payload is not supported
Bug #117	FormatUtils.asStringIp6() causes an OutOfMemoryException
Bug #115	Ip6 header class is missing field setters
Bug #114	ICMP Echo lacks id and sequence setter methods
Bug #113	QinQ not working
Bug #112	Icmp protocol types and description
Bug #111	TcpOptions missing @HeaderLength method
Bug #110	Rtcp SDES and BYE message issue
Bug #109	DisposableGC g0 - exception
Bug #108	Out of memory exception in multi-threaded env
Bug #107	Reflection exception in mutli-threaded setup

