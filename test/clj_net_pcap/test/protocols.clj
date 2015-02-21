;;;
;;; Copyright (C) 2012 Ruediger Gad
;;;
;;; This file is part of clj-net-pcap.
;;;
;;; clj-net-pcap is free software: you can redistribute it and/or modify
;;; it under the terms of the GNU Lesser General Public License (LGPL) as
;;; published by the Free Software Foundation, either version 3 of the License,
;;; or (at your option any later version.
;;;
;;; clj-net-pcap is distributed in the hope that it will be useful,
;;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;; GNU Lesser General Public License (LGPL) for more details.
;;;
;;; You should have received a copy of the GNU Lesser General Public License (LGPL)
;;; along with clj-net-pcap.  If not, see <http://www.gnu.org/licenses/>.
;;;

(ns 
  ^{:author "Ruediger Gad",
    :doc "Tests for protocol parsing"}  
  clj-net-pcap.test.protocols
  (:use clojure.test
        clj-net-pcap.core
        clj-assorted-utils.util)
  (:import (clj_net_pcap PacketHeaderDataBean)))

(deftest test-extract-tcp-maps-from-pcap-file
  (let [my-maps (extract-maps-from-pcap-file "test/clj_net_pcap/test/data/tcp-syn-ack.pcap")]
    (is (= 1 (count my-maps)))
    (is (= {"ipVer" 4, "ipDst" "192.168.0.51", 
            "ipId" 0, "ipTtl" 48, "ipChecksum" 844,
            "ipSrc" "209.132.181.16", "ethDst" "74:DE:2B:08:78:09", 
            "ethSrc" "00:24:FE:B1:8F:DC", "ts" 1385804488699025000, "len" 74,
            "tcpSrc" 80, "tcpDst" 42229, "tcpFlags" 18,
            "tcpAck" 2657863316, "tcpSeq" 1606436657}
           (first my-maps)))))

(deftest test-extract-tcp-nested-maps-from-pcap-file
  (let [my-maps (extract-nested-maps-from-pcap-file "test/clj_net_pcap/test/data/tcp-syn-ack.pcap")]
    (is (= 1 (count my-maps)))
    (is (= {"PcapHeader" {"timestampInNanos" 1385804488699025000, "wirelen" 74},
            "DataLinkLayer" {"index" 0, "ProtocolType" "Ethernet",
                             "destination" "74:DE:2B:08:78:09", "source" "00:24:FE:B1:8F:DC", "next" 2},
            "NetworkLayer" {"index" 1, "ProtocolType" "Ip4", "destination" "192.168.0.51", "type" 6,
                            "source" "209.132.181.16", "id" 0, "tos" 0, "ttl" 48, "next" 4},
            "Tcp" {"index" 2, "destination" 42229, "source" 80, "ack" 2657863316, "seq" 1606436657,
                   "flags" #{"ACK" "SYN"}}}
           (first my-maps)))))

(deftest test-extract-http-nested-maps-from-pcap-file
  (let [my-maps (extract-nested-maps-from-pcap-file "test/clj_net_pcap/test/data/http-get.pcap")]
    (is (= 1 (count my-maps)))
    (is (= {"PcapHeader" {"timestampInNanos" 1424526893748322000, "wirelen" 203},
            "DataLinkLayer" {"index" 0, "ProtocolType" "Ethernet", "destination" "00:24:FE:B1:8F:DC",
                             "source" "74:DE:2B:08:78:09", "next" 2},
            "NetworkLayer" {"next" 4, "destination" "198.145.20.140", "index" 1, "ProtocolType" "Ip4",
                            "id" 37874, "source" "10.0.0.101", "type" 6, "ttl" 64, "tos" 0},
            "Tcp" {"index" 2, "destination" 80, "source" 53575, "ack" 438696410, "seq" 2996233046,
                   "flags" #{"PSH" "ACK"}, "next" 13},
            "Http" {"index" 3, "RequestUrl" "/", "RequestMethod" "GET", "RequestVersion" "HTTP/1.1"}}
           (first my-maps)))))

(deftest test-extract-tcp-nested-maps-from-pcap-file-dns
  (let [my-maps (extract-nested-maps-from-pcap-file "test/clj_net_pcap/test/data/dns-query-response.pcap")]
    (is (= 2 (count my-maps)))
    (is (= {"PcapHeader" {"timestampInNanos" 1385804494276477000, "wirelen" 77},
            "DataLinkLayer" {"index" 0, "ProtocolType" "Ethernet", "destination" "00:24:FE:B1:8F:DC",
                             "source" "74:DE:2B:08:78:09", "next" 2},
            "NetworkLayer" {"next" 5, "destination" "192.168.0.1", "index" 1,
                            "ProtocolType" "Ip4", "id" 20831, "source" "192.168.0.51", "type" 17,
                            "ttl" 64, "tos" 0},
            "Udp" {"index" 2, "destination" 53, "source" 34904}}
           (first my-maps)))))

(deftest test-extract-tcp-nested-maps-from-pcap-file-icmpv6
  (let [my-maps (extract-nested-maps-from-pcap-file "test/clj_net_pcap/test/data/icmpv6-router-solicitation.pcap")]
    (is (= 1 (count my-maps)))
    (is (= {"PcapHeader" {"timestampInNanos" 1403685403642220000, "wirelen" 62},
            "DataLinkLayer" {"index" 0, "ProtocolType" "Ethernet", "destination" "33:33:00:00:00:02",
                             "source" "E8:9D:87:B1:45:2F", "next" 3},
            "NetworkLayer" {"index" 1, "ProtocolType" "Ip6", "destination" "FF02:0000:0000:0000:0000:0000:0000:0002",
                            "source" "FE80:0000:0000:0000:EA9D:87FF:FEB1:452F", "flowLabel" 0, "hopLimit" 255,
                            "trafficClass" 0, "next" 0}}
           (first my-maps)))))

(deftest test-extract-tcp-beans-from-pcap-file
  (let [my-beans (extract-beans-from-pcap-file "test/clj_net_pcap/test/data/tcp-syn-ack.pcap")
        expected (doto (PacketHeaderDataBean.)
                   (.setTs 1385804488699025000) (.setLen 74)
                   (.setEthDst "74:DE:2B:08:78:09") (.setEthSrc "00:24:FE:B1:8F:DC")
                   (.setIpDst "192.168.0.51") (.setIpSrc "209.132.181.16")
                   (.setIpId 0) (.setIpTtl 48) (.setIpChecksum 844)
                   (.setIpVer 4) (.setTcpSrc 80) (.setTcpDst 42229) (.setTcpFlags 18)
                   (.setTcpAck 2657863316) (.setTcpSeq 1606436657))]
    (is (= 1 (count my-beans)))
    (is (= expected
           (first my-beans)))))

(deftest test-extract-udp-maps-from-pcap-file
  (let [my-maps (extract-maps-from-pcap-file "test/clj_net_pcap/test/data/dns-query-response.pcap")]
    (is (= 2 (count my-maps)))
    (is (= {"ipVer" 4, "ipDst" "192.168.0.1", 
            "ipSrc" "192.168.0.51", "ethDst" "00:24:FE:B1:8F:DC", 
            "ipId" 20831, "ipTtl" 64, "ipChecksum" 26570,
            "ethSrc" "74:DE:2B:08:78:09", "ts" 1385804494276477000, "len" 77,
            "udpSrc" 34904, "udpDst" 53}
           (first my-maps)))))

(deftest test-extract-udp-beans-from-pcap-file
  (let [my-beans (extract-beans-from-pcap-file "test/clj_net_pcap/test/data/dns-query-response.pcap")
        expected (doto (PacketHeaderDataBean.)
                   (.setTs 1385804494276477000) (.setLen 77)
                   (.setEthDst "00:24:FE:B1:8F:DC") (.setEthSrc "74:DE:2B:08:78:09")
                   (.setIpDst "192.168.0.1") (.setIpSrc "192.168.0.51")
                   (.setIpId 20831) (.setIpTtl 64) (.setIpChecksum 26570)
                   (.setIpVer 4) (.setUdpSrc 34904) (.setUdpDst 53))]
    (is (= 2 (count my-beans)))
    (is (= expected
           (first my-beans)))))

(deftest test-extract-arp-maps-from-pcap-file
  (let [my-maps (extract-maps-from-pcap-file "test/clj_net_pcap/test/data/arp-request-reply.pcap")]
    (is (= 2 (count my-maps)))
    (is (= {"ethSrc" "E8:9D:87:B1:45:2F", "ethDst" "FF:FF:FF:FF:FF:FF",
            "ts" 1403685403524575000, "len" 42,
            "arpOpDesc" "REQUEST", "arpTargetMac" "00:00:00:00:00:00", "arpTargetIp" "10.1.1.21",
            "arpSourceMac" "E8:9D:87:B1:45:2F", "arpSourceIp" "10.1.1.42"}
           (first my-maps)))))

(deftest test-extract-arp-nested-maps-from-pcap-file
  (let [my-maps (extract-nested-maps-from-pcap-file "test/clj_net_pcap/test/data/arp-request-reply.pcap")]
    (is (= 2 (count my-maps)))
    (is (= {"PcapHeader" {"timestampInNanos" 1403685403524575000, "wirelen" 42},
            "DataLinkLayer" {"index" 0, "ProtocolType" "Ethernet",
                             "destination" "FF:FF:FF:FF:FF:FF", "source" "E8:9D:87:B1:45:2F", "next" 16},
            "Arp" {"operationDescription" "REQUEST", "targetMac" "00:00:00:00:00:00", "targetIp" "10.1.1.21",
                   "sourceMac" "E8:9D:87:B1:45:2F", "sourceIp" "10.1.1.42", "index" 1}}
           (first my-maps)))))

(deftest test-extract-arp-beans-from-pcap-file
  (let [my-beans (extract-beans-from-pcap-file "test/clj_net_pcap/test/data/arp-request-reply.pcap")
        expected (doto (PacketHeaderDataBean.)
                   (.setTs 1403685403524575000) (.setLen 42)
                   (.setEthDst "FF:FF:FF:FF:FF:FF") (.setEthSrc "E8:9D:87:B1:45:2F")
                   (.setArpOpDesc "REQUEST") (.setArpTargetMac "00:00:00:00:00:00") (.setArpTargetIp "10.1.1.21")
                   (.setArpSourceMac "E8:9D:87:B1:45:2F") (.setArpSourceIp "10.1.1.42"))]
    (is (= 2 (count my-beans)))
    (is (= expected
           (first my-beans)))))

(deftest test-extract-icmpv6-router-solicitation-maps-from-pcap-file
  (let [my-maps (extract-maps-from-pcap-file "test/clj_net_pcap/test/data/icmpv6-router-solicitation.pcap")]
    (is (= 1 (count my-maps)))
    (is (= {"ipVer" 6,
            "ipDst" "FF02:0000:0000:0000:0000:0000:0000:0002", "ipSrc" "FE80:0000:0000:0000:EA9D:87FF:FEB1:452F",
            "ethSrc" "E8:9D:87:B1:45:2F", "ethDst" "33:33:00:00:00:02",
            "ts" 1403685403642220000, "len" 62}
           (first my-maps)))))

(deftest test-extract-icmpv6-router-solicitation-beans-from-pcap-file
  (let [my-beans (extract-beans-from-pcap-file "test/clj_net_pcap/test/data/icmpv6-router-solicitation.pcap")
        expected (doto (PacketHeaderDataBean.)
                   (.setTs 1403685403642220000) (.setLen 62)
                   (.setEthDst "33:33:00:00:00:02") (.setEthSrc "E8:9D:87:B1:45:2F")
                   (.setIpDst "FF02:0000:0000:0000:0000:0000:0000:0002") (.setIpSrc "FE80:0000:0000:0000:EA9D:87FF:FEB1:452F")
                   (.setIpVer 6))]
    (is (= 1 (count my-beans)))
    (is (= expected
           (first my-beans)))))
