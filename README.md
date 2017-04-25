# clj-net-pcap
clj-net-pcap is a wrapper/adapter/facade (No matter how you want to call it.) around [jNetPcap](http://jnetpcap.com/) that enables and eases packet capturing with [Clojure](http://clojure.org/).

[![Clojars Project](https://img.shields.io/clojars/v/clj-net-pcap.svg)](http://clojars.org/clj-net-pcap)
[![Build Status](https://travis-ci.org/ruedigergad/clj-net-pcap.png?branch=master)](https://travis-ci.org/ruedigergad/clj-net-pcap)
[![Build Status CircleCI](https://circleci.com/gh/ruedigergad/clj-net-pcap.svg?style=shield&circle-token=:circle-token)](https://circleci.com/gh/ruedigergad/clj-net-pcap.svg?style=shield&circle-token=:circle-token)
[![Coverage Status](https://img.shields.io/coveralls/ruedigergad/clj-net-pcap.svg)](https://coveralls.io/r/ruedigergad/clj-net-pcap?branch=master)

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

## Usage
clj-net-pcap is primarily intended as a library that is used by other applications.
However, it can be run as sample stand-alone command line application as follows:

java -jar clj-net-pcap-standalone-jar-file.jar

For more information about the available options use the "-h" or "--help" option.

### API Docs
API docs are available:

http://ruedigergad.github.io/clj-net-pcap/doc/

## Detailed Test Results
Detailed results of unit tests are available:

http://ruedigergad.github.io/clj-net-pcap/test-results/html/

## Publications
We published two papers in which we describe the clj-net-pcap architecture and implementation and assess the performance:

* Improving Network Traffic Acquisition and Processing with the Java Virtual Machine, Ruediger Gad, Martin Kappes, and Inmaculada Medina-Bulo, 20th IEEE ISCC 2015, in press
    * [The full text of the authors accepted version is available via ResearchGate.](https://www.researchgate.net/publication/289637876_Improving_Network_Traffic_Acquisition_and_Processing_with_the_Java_Virtual_Machine)
    * The link to the final published version on IEEEXplore will be added once it is available.
* [Bridging the Gap between Low-Level Network Traffic Data Acquisition and Higher-Level Frameworks](http://ieeexplore.ieee.org/xpl/articleDetails.jsp?tp=&arnumber=6903107), Ruediger Gad, Martin Kappes, and Inmaculada Medina-Bulo, 38th IEEE COMPSACW 2014.
    * [The full text of the authors accepted version is available via ResearchGate.](https://www.researchgate.net/publication/269095939_Bridging_the_Gap_between_Low-Level_Network_Traffic_Data_Acquisition_and_Higher-Level_Frameworks)
    * [The final published version is available via IEEEXplore.](http://ieeexplore.ieee.org/xpl/articleDetails.jsp?tp=&arnumber=6903107)

### Referencing
If you want to reference clj-net-pcap, you can refer to our paper, e.g., in LaTeX:

    @inproceedings{gad_improving_2015,
        title = {Improving {Network} {Traffic} {Acquisition} and {Processing} with the {Java} {Virtual} {Machine}},
        booktitle = {2015 20th {IEEE} {Symposium} on {Computers} and {Communications} ({ISCC})},
        author = {Gad, Ruediger and Kappes, Martin and Medina-Bulo, Immaculada},
        month = jul,
        year = {2015},
        note = {in press},
    }

    @INPROCEEDINGS{gad_bridging_2014,
        author={Gad, Ruediger and Kappes, Martin and Medina-Bulo, Inmaculada},
        booktitle={Computer Software and Applications Conference Workshops (COMPSACW), 2014 IEEE 38th International},
        title={Bridging the Gap between Low-Level Network Traffic Data Acquisition and Higher-Level Frameworks},
        year={2014},
        month={July},
        pages={67-72},
        keywords={Data acquisition;Instruction sets;Java;Libraries;Pipelines;Prototypes;Surveillance;Java Virtual Machine;Networks;Packet Capturing;Performance},
        doi={10.1109/COMPSACW.2014.15},
    }

## Building etc.
clj-net-pcap uses Leiningen.
Please note that Leiningen version 2.x is used.

## History & Acknowledgements
clj-net-pcap was created and is still developed and maintained as a personal project.
However, I am in the fortunate situation that it showed after some time that clj-net-pcap could also be used for my PhD and research work.
While I did the actual development in my spare time, I worked on the scientific evaluation of clj-net-pcap and published these results in scientific papers in scope of my employment as PhD student and researcher.
Consequently, acknowledgements go to my employer the [Frankfurt University of Applied Sciences](http://frankfurt-university.de) and the [Universidad de Cádiz](http://uca.es) where I am currently enrolled as PhD student.

While the project name was initially "cljNetPcap", it was renamed to "clj-net-pcap" in order to adhere to common package naming conventions.
Furthermore, I decided to upload clj-net-pcap to [clojars.org](http://clojars.org) in order to ease its application.

## License
Copyright (C) 2012, 2013, 2014, 2015 Ruediger Gad


clj-net-pcap is licensed under the terms of either

- the GNU Lesser General Public License (LGPL) version 3 (http://www.gnu.org/licenses/lgpl-3.0.html) or later

or, at your option,

- the Eclipse Public License (EPL) 1.0 (http://opensource.org/licenses/eclipse-1.0.php).


By contributing to clj-net-pcap, you agree that your contribution will be licensed under both licenses
and that users of clj-net-pcap can chose any of these licenses.


### LGPL
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

### EPL
clj-net-pcap is is released under the terms of the Eclipse Public License
(EPL) 1.0. You can find a copy of the EPL at:
http://opensource.org/licenses/eclipse-1.0.php

