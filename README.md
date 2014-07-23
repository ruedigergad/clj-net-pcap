# clj-net-pcap
clj-net-pcap is a wrapper/adapter/facade (No matter how you want to call it.) around [jNetPcap](http://jnetpcap.com/) that enables and eases packet capturing with [Clojure](http://clojure.org/).

## Requirements/Dependencies
clj-net-pcap is currently available for Linux and Windows for both x86 and x86_64 architecture.

Please note that clj-net-pcap requires native packet capturing libraries.
For Linux, this is the [libpcap](http://www.tcpdump.org/) library.
For Windows, this is the [winpcap](http://www.winpcap.org/) library.
Typically, these libraries have to be installed separately.
On Linux, this is usually done via the packet manager of the respective distribution.

When using clj-net-pcap via Leiningen or Maven, all Java/Clojure related dependencies should be resolved and pulled in automatically.

Additionally, please note that on Linux clj-net-pcap expects the libpcap library to be named "libpcap.so".
If this is not the case this can be fixed by, e.g., adding a symbolic link like shown for Fedora below:

    sudo ln -s /usr/lib64/libpcap.so.1 /usr/lib64/libpcap.so

## API Docs
API docs are available:

http://ruedigergad.github.io/clj-net-pcap/doc/

## CI
[![Build Status](https://travis-ci.org/ruedigergad/clj-net-pcap.png?branch=master)](https://travis-ci.org/ruedigergad/clj-net-pcap)

## Test Results
[![Coverage Status](https://img.shields.io/coveralls/ruedigergad/clj-net-pcap.svg)](https://coveralls.io/r/ruedigergad/clj-net-pcap?branch=master)

Detailed results of unit tests are available:

http://ruedigergad.github.io/clj-net-pcap/test-results/html/

## Usage
clj-net-pcap is primarily intended as a library that is used by other applications.
However, it can be run as sample stand-alone command line application as follows:

java -jar clj-net-pcap-standalone-jar-file.jar

For more information about the available options use the "-h" or "--help" option.

## Building etc.
clj-net-pcap uses Leiningen.
Please note that Leiningen version 2.x is used.

## License
Copyright (C) 2012, 2013, 2014 Ruediger Gad

clj-net-pcap is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License (LGPL) as 
published by the Free Software Foundation, either version 3 of the License, 
or (at your option) any later version.

clj-net-pcap is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License (LGPL) for more details.

You should have received a copy of the GNU Lesser General Public License (LGPL)
along with clj-net-pcap.  If not, see <http://www.gnu.org/licenses/>.

