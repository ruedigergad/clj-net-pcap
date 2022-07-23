#
#   RPM package specification for JNETPCAP TESTS
#
%define VERSION @pkg.version@
%define RELEASE @platform.os.name@
%define JNETPCAP jnetpcap-tests-%{VERSION}

Summary: jUnit test cases for jNetPcap libpcap wrapper
Name: jnetpcap-tests
Version: %{VERSION}
Release: %{RELEASE}
License: LGPL
Group: Development/Java
Packager: Sly Technologies, Inc. <http://www.slytechs.com>
Vendor: Sly Technologies, Inc <http://www.slytechs.com>
Distribution: jnetpcap <http://jnetpcap.org>
PreReq: jnetpcap == %{VERSION}


%description
jUnit test cases for jNetpcap java libpcap wrapper. This package provides test
cases and sample capture files used in testing of the library functionality.


%prep

%build
pwd

%install

%files
%doc 
