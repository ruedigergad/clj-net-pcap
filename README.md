# clj-net-pcap
clj-net-pcap is a wrapper/adapter/facade (No matter how you wanna call it.)
around jNetPcap that enables and eases packet capturing with Clojure.

## Requirements
clj-net-pcap requires libpcap.

Please note:
clj-net-pcap expects the libpcap library to be named "libpcap.so".
If this is not the case this can be fixed by adding a symlink like shown for Fedora below:
sudo ln -s /usr/lib64/libpcap.so.1 /usr/lib64/libpcap.so

## API Docs
Automatically generated API docs are available:

http://ruedigergad.github.io/clj-net-pcap/doc/

## CI
[![Build Status](https://travis-ci.org/ruedigergad/clj-net-pcap.png?branch=master)](https://travis-ci.org/ruedigergad/clj-net-pcap)

## Test Results
clj-net-pcap is developed following the test-driven development paradigm.
Test results are available here:

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
Copyright (C) 2012, 2013 Ruediger Gad

This file is part of clj-net-pcap.

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

