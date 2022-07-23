#
#   RPM package specification for JNETPCAP
#
# Note: It is critical to use underscore in physical top level directory
#       of jnetpcap when checking out from SVN. If a dash is used, rpmbuild
#       tool converts the dash ('-') to an underscore ('_') causing major build
#       problems since the build directory might reside under 
#       /home/user/jnp-1.3/build/rpm while the rpm build tool creates a new
#       working directory and assumes underscores /home/user/jnp_1.3/build/rpm 
#       which is of course a different directory entirely causing files not to
#       be found and failure of the rpm build
#       
 
%define VERSION		@pkg.version@
%define PKG_RELEASE	@pkg.release@
%define OPERATING_SYS	@platform.os.name@
%define JNETPCAP	jnetpcap-%{VERSION}
%define RELEASE		%{PKG_RELEASE}.%{OPERATING_SYS}

Summary: A libpcap java wrapper
Name: jnetpcap
Version: %{VERSION}
Release: %{RELEASE}
License: LGPL
Group: Development/Java
Packager: Sly Technologies, Inc. <http://www.slytechs.com>
Vendor: Sly Technologies, Inc <http://www.slytechs.com>
Distribution: jnetpcap <http://jnetpcap.org>
Requires: libpcap >= 0.8.0
Provides: java-libpcap, java-packet-capture


%description
jNetPcap is a java wrapper around libpcap. It provides all of the same methods
using similar style of API as the native counter part. All the native libpcap
structures and methods are tightly and accurately peered with each other,
providing entire libpcap environment under java.

%prep

%files
%doc LICENSE.txt RELEASE_NOTES.txt CHANGE_LOG.txt
/usr/lib/libjnetpcap.so.%{VERSION}
/usr/share/java/%{JNETPCAP}.jar

%post
ln -s /usr/lib/libjnetpcap.so.%{VERSION} /usr/lib/libjnetpcap.so
ln -s /usr/share/java/jnetpcap-%{VERSION}.jar /usr/share/java/jnetpcap.jar

%postun
rm -f /usr/lib/libjnetpcap.so
rm -f /usr/share/java/jnetpcap.jar
