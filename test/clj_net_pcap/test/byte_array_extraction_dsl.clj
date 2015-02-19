;;;
;;; Copyright (C) 2015 Ruediger Gad
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
    :doc "Tests for extracting data from byte arrays via a DSL."}
  clj-net-pcap.test.byte-array-extraction-dsl
  (:use clojure.test
        clj-net-pcap.byte-array-extraction-dsl
        clj-net-pcap.core
        clj-net-pcap.pcap-data
        clj-assorted-utils.util)
  (:import (clj_net_pcap PacketHeaderDataBeanIpv4UdpOnly)))

(deftest simple-hardcoded-offsets-dsl-test
  (let [expected-map {"udpSrc" 2048, "udpDst" 4096}
        dsl-expression [{:offset 50 :transformation :int16 :name :udpSrc}
                        {:offset 52 :transformation :int16 :name :udpDst}]
        pkt-raw-vec [-5 -106 -57 84   15 -54 14 0   77 0 0 0   77 0 0 0    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extraction-fn (create-extraction-fn dsl-expression)
        extracted-map (extraction-fn pkt-ba 0)]
    (is (= expected-map extracted-map))))

(deftest simple-packet-offsets-name-dsl-test
  (let [expected-map {"udpSrc" 2048, "udpDst" 4096}
        dsl-expression [{:offset :udp-src :transformation :int16 :name :udpSrc}
                        {:offset :udp-dst :transformation :int16 :name :udpDst}]
        pkt-raw-vec [-5 -106 -57 84   15 -54 14 0   77 0 0 0   77 0 0 0    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extraction-fn (create-extraction-fn dsl-expression)
        extracted-map (extraction-fn pkt-ba 0)]
    (is (= expected-map extracted-map))))

(deftest extended-packet-offsets-name-dsl-be-test
  (let [expected-map {"ipId" 3, "ipTtl" 7, "ipChecksum" 29639,
                      "udpSrc" 2048, "udpDst" 4096, "len" 77}
        dsl-expression [{:offset 12 :transformation :int32be :name :len}
                        {:offset :ipv4-id :transformation :int16 :name :ipId}
                        {:offset :ipv4-ttl :transformation :int8 :name :ipTtl}
                        {:offset :ipv4-checksum :transformation :int16 :name :ipChecksum}
                        {:offset :udp-src :transformation :int16 :name :udpSrc}
                        {:offset :udp-dst :transformation :int16 :name :udpDst}]
        pkt-raw-vec [-5 -106 -57 84   15 -54 14 0   77 0 0 0   77 0 0 0    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extraction-fn (create-extraction-fn dsl-expression)
        extracted-map (extraction-fn pkt-ba 0)]
    (is (= expected-map extracted-map))))

(deftest extended-packet-offsets-name-dsl-le-test
  (let [expected-map {"ipId" 3, "ipTtl" 7, "ipChecksum" 29639,
                      "udpSrc" 2048, "udpDst" 4096, "len" 77}
        dsl-expression [{:offset 12 :transformation :int32 :name :len}
                        {:offset :ipv4-id :transformation :int16 :name :ipId}
                        {:offset :ipv4-ttl :transformation :int8 :name :ipTtl}
                        {:offset :ipv4-checksum :transformation :int16 :name :ipChecksum}
                        {:offset :udp-src :transformation :int16 :name :udpSrc}
                        {:offset :udp-dst :transformation :int16 :name :udpDst}]
        pkt-raw-vec [84 -57 -106 -5   0 14 -54 15   0 0 0 77   0 0 0 77    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extraction-fn (create-extraction-fn dsl-expression)
        extracted-map (extraction-fn pkt-ba 0)]
    (is (= expected-map extracted-map))))

(deftest extended-packet-offsets-name-dsl-le-strings-test
  (let [expected-map {"ipId" 3, "ipTtl" 7, "ipChecksum" 29639,
                      "udpSrc" 2048, "udpDst" 4096, "len" 77}
        dsl-expression [{:offset 12 :transformation "int32" :name "len"}
                        {:offset "ipv4-id" :transformation "int16" :name "ipId"}
                        {:offset "ipv4-ttl" :transformation "int8" :name "ipTtl"}
                        {:offset "ipv4-checksum" :transformation "int16" :name "ipChecksum"}
                        {:offset "udp-src" :transformation "int16" :name "udpSrc"}
                        {:offset "udp-dst" :transformation "int16" :name "udpDst"}]
        pkt-raw-vec [84 -57 -106 -5   0 14 -54 15   0 0 0 77   0 0 0 77    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extraction-fn (create-extraction-fn dsl-expression)
        extracted-map (extraction-fn pkt-ba 0)]
    (is (= expected-map extracted-map))))

(deftest timestamp-extraction-le-test
  (let [expected-map {"ipId" 3, "ipTtl" 7, "ipChecksum" 29639,
                      "udpSrc" 2048, "udpDst" 4096, "len" 77, "ts" 1422366459969231000}
        dsl-expression [{:offset 0 :transformation "timestamp" :name "ts"}
                        {:offset 12 :transformation "int32" :name "len"}
                        {:offset "ipv4-id" :transformation "int16" :name "ipId"}
                        {:offset "ipv4-ttl" :transformation "int8" :name "ipTtl"}
                        {:offset "ipv4-checksum" :transformation "int16" :name "ipChecksum"}
                        {:offset "udp-src" :transformation "int16" :name "udpSrc"}
                        {:offset "udp-dst" :transformation "int16" :name "udpDst"}]
        pkt-raw-vec [84 -57 -106 -5   0 14 -54 15   0 0 0 77   0 0 0 77    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extraction-fn (create-extraction-fn dsl-expression)
        extracted-map (extraction-fn pkt-ba 0)]
    (is (= expected-map extracted-map))))

(deftest timestamp-extraction-be-test
  (let [expected-map {"ipId" 3, "ipTtl" 7, "ipChecksum" 29639,
                      "udpSrc" 2048, "udpDst" 4096, "len" 77, "ts" 1422366459969231000}
        dsl-expression [{:offset 0 :transformation "timestamp-be" :name "ts"}
                        {:offset 12 :transformation "int32be" :name "len"}
                        {:offset "ipv4-id" :transformation "int16" :name "ipId"}
                        {:offset "ipv4-ttl" :transformation "int8" :name "ipTtl"}
                        {:offset "ipv4-checksum" :transformation "int16" :name "ipChecksum"}
                        {:offset "udp-src" :transformation "int16" :name "udpSrc"}
                        {:offset "udp-dst" :transformation "int16" :name "udpDst"}]
        pkt-raw-vec [-5 -106 -57 84   15 -54 14 0   77 0 0 0   77 0 0 0    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extraction-fn (create-extraction-fn dsl-expression)
        extracted-map (extraction-fn pkt-ba 0)]
    (is (= expected-map extracted-map))))

(deftest ethernet-address-extraction-test
  (let [expected-map {"ethSrc" "01:02:03:04:05:06", "ethDst" "FF:FE:FD:F2:F1:F0",
                      "ipId" 3, "ipTtl" 7, "ipChecksum" 29639,
                      "udpSrc" 2048, "udpDst" 4096, "len" 77, "ts" 1422366459969231000}
        dsl-expression [{:offset 0 :transformation "timestamp-be" :name "ts"}
                        {:offset 12 :transformation "int32be" :name "len"}
                        {:offset "eth-dst" :transformation "ethernet-address" :name "ethDst"}
                        {:offset "eth-src" :transformation "ethernet-address" :name "ethSrc"}
                        {:offset "ipv4-id" :transformation "int16" :name "ipId"}
                        {:offset "ipv4-ttl" :transformation "int8" :name "ipTtl"}
                        {:offset "ipv4-checksum" :transformation "int16" :name "ipChecksum"}
                        {:offset "udp-src" :transformation "int16" :name "udpSrc"}
                        {:offset "udp-dst" :transformation "int16" :name "udpDst"}]
        pkt-raw-vec [-5 -106 -57 84   15 -54 14 0   77 0 0 0   77 0 0 0    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extraction-fn (create-extraction-fn dsl-expression)
        extracted-map (extraction-fn pkt-ba 0)]
    (is (= expected-map extracted-map))))

(deftest ipv4-address-extraction-test
  (let [expected-map {"ethSrc" "01:02:03:04:05:06", "ethDst" "FF:FE:FD:F2:F1:F0",
                      "ipId" 3, "ipTtl" 7, "ipChecksum" 29639,
                      "ipDst" "252.253.254.255", "ipSrc" "1.2.3.4",
                      "udpSrc" 2048, "udpDst" 4096, "len" 77, "ts" 1422366459969231000}
        dsl-expression [{:offset 0 :transformation "timestamp-be" :name "ts"}
                        {:offset 12 :transformation "int32be" :name "len"}
                        {:offset "eth-dst" :transformation "ethernet-address" :name "ethDst"}
                        {:offset "eth-src" :transformation "ethernet-address" :name "ethSrc"}
                        {:offset "ipv4-dst" :transformation "ipv4-address" :name "ipDst"}
                        {:offset "ipv4-src" :transformation "ipv4-address" :name "ipSrc"}
                        {:offset "ipv4-id" :transformation "int16" :name "ipId"}
                        {:offset "ipv4-ttl" :transformation "int8" :name "ipTtl"}
                        {:offset "ipv4-checksum" :transformation "int16" :name "ipChecksum"}
                        {:offset "udp-src" :transformation "int16" :name "udpSrc"}
                        {:offset "udp-dst" :transformation "int16" :name "udpDst"}]
        pkt-raw-vec [-5 -106 -57 84   15 -54 14 0   77 0 0 0   77 0 0 0    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extraction-fn (create-extraction-fn dsl-expression)
        extracted-map (extraction-fn pkt-ba 0)]
    (is (= expected-map extracted-map))))

(deftest ipv4-version-extraction-test
  (let [expected-map {"ethSrc" "01:02:03:04:05:06", "ethDst" "FF:FE:FD:F2:F1:F0",
                      "ipId" 3, "ipTtl" 7, "ipChecksum" 29639, "ipVer" 4,
                      "ipDst" "252.253.254.255", "ipSrc" "1.2.3.4",
                      "udpSrc" 2048, "udpDst" 4096, "len" 77, "ts" 1422366459969231000}
        dsl-expression [{:offset 0 :transformation "timestamp-be" :name "ts"}
                        {:offset 12 :transformation "int32be" :name "len"}
                        {:offset "eth-dst" :transformation "ethernet-address" :name "ethDst"}
                        {:offset "eth-src" :transformation "ethernet-address" :name "ethSrc"}
                        {:offset "ipv4-dst" :transformation "ipv4-address" :name "ipDst"}
                        {:offset "ipv4-src" :transformation "ipv4-address" :name "ipSrc"}
                        {:offset "ipv4-id" :transformation "int16" :name "ipId"}
                        {:offset "ipv4-ttl" :transformation "int8" :name "ipTtl"}
                        {:offset "ipv4-checksum" :transformation "int16" :name "ipChecksum"}
                        {:offset "ipv4-version" :transformation "int4high" :name "ipVer"}
                        {:offset "udp-src" :transformation "int16" :name "udpSrc"}
                        {:offset "udp-dst" :transformation "int16" :name "udpDst"}]
        pkt-raw-vec [-5 -106 -57 84   15 -54 14 0   77 0 0 0   77 0 0 0    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extraction-fn (create-extraction-fn dsl-expression)
        extracted-map (extraction-fn pkt-ba 0)]
    (is (= expected-map extracted-map))))

(deftest full-ipv4-udp-dsl-be-test
  (let [expected-map {"ethSrc" "01:02:03:04:05:06", "ethDst" "FF:FE:FD:F2:F1:F0",
                      "ipId" 3, "ipTtl" 7, "ipChecksum" 29639, "ipVer" 4,
                      "ipDst" "252.253.254.255", "ipSrc" "1.2.3.4",
                      "udpSrc" 2048, "udpDst" 4096, "len" 77, "ts" 1422366459969231000}
        pkt-raw-vec [-5 -106 -57 84   15 -54 14 0   77 0 0 0   77 0 0 0    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extraction-fn (create-extraction-fn ipv4-udp-be-dsl-expression)
        extracted-map (extraction-fn pkt-ba 0)]
    (is (= expected-map extracted-map))))

(deftest full-ipv4-udp-dsl-le-test
  (let [expected-map {"ethSrc" "01:02:03:04:05:06", "ethDst" "FF:FE:FD:F2:F1:F0",
                      "ipId" 3, "ipTtl" 7, "ipChecksum" 29639, "ipVer" 4,
                      "ipDst" "252.253.254.255", "ipSrc" "1.2.3.4",
                      "udpSrc" 2048, "udpDst" 4096, "len" 77, "ts" 1422366459969231000}
        pkt-raw-vec [84 -57 -106 -5   0 14 -54 15   0 0 0 77   0 0 0 77    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extraction-fn (create-extraction-fn ipv4-udp-le-dsl-expression)
        extracted-map (extraction-fn pkt-ba 0)]
    (is (= expected-map extracted-map))))

(deftest dsl-with-type-java-map-test
  (let [expected-map {"udpSrc" 2048, "udpDst" 4096}
        dsl-expression {:type :java-map
                        :rules [{:offset :udp-src :transformation :int16 :name :udpSrc}
                                {:offset :udp-dst :transformation :int16 :name :udpDst}]}
        pkt-raw-vec [-5 -106 -57 84   15 -54 14 0   77 0 0 0   77 0 0 0    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extraction-fn (create-extraction-fn dsl-expression)
        extracted-map (extraction-fn pkt-ba 0)]
    (is (= java.util.HashMap (type extracted-map)))
    (is (= expected-map extracted-map))))

(deftest dsl-default-to-java-map-type-test
  (let [expected-map {"udpSrc" 2048, "udpDst" 4096}
        dsl-expression {:type :invalid-type-name
                        :rules [{:offset :udp-src :transformation :int16 :name :udpSrc}
                                {:offset :udp-dst :transformation :int16 :name :udpDst}]}
        pkt-raw-vec [-5 -106 -57 84   15 -54 14 0   77 0 0 0   77 0 0 0    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extraction-fn (create-extraction-fn dsl-expression)
        extracted-map (extraction-fn pkt-ba 0)]
    (is (= java.util.HashMap (type extracted-map)))
    (is (= expected-map extracted-map))))

(deftest dsl-with-type-clj-map-test
  (let [expected-map {"udpSrc" 2048, "udpDst" 4096}
        dsl-expression {:type :clj-map
                        :rules [{:offset :udp-src :transformation :int16 :name :udpSrc}
                                {:offset :udp-dst :transformation :int16 :name :udpDst}]}
        pkt-raw-vec [-5 -106 -57 84   15 -54 14 0   77 0 0 0   77 0 0 0    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extraction-fn (create-extraction-fn dsl-expression)
        extracted-map (extraction-fn pkt-ba 0)]
    (is (map? extracted-map))
    (is (= expected-map extracted-map))))

(deftest dsl-with-type-csv-str-test
  (let [expected-str "2048,4096"
        dsl-expression {:type :csv-str
                        :rules [{:offset :udp-src :transformation :int16 :name :udpSrc}
                                {:offset :udp-dst :transformation :int16 :name :udpDst}]}
        pkt-raw-vec [-5 -106 -57 84   15 -54 14 0   77 0 0 0   77 0 0 0    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extraction-fn (create-extraction-fn dsl-expression)
        extracted-str (extraction-fn pkt-ba 0)]
    (is (= expected-str extracted-str))))

(deftest dsl-with-type-json-str-test
  (let [expected-str "{\"udpSrc\":2048,\"udpDst\":4096}"
        dsl-expression {:type :json-str
                        :rules [{:offset :udp-src :transformation :int16 :name :udpSrc}
                                {:offset :udp-dst :transformation :int16 :name :udpDst}]}
        pkt-raw-vec [-5 -106 -57 84   15 -54 14 0   77 0 0 0   77 0 0 0    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extraction-fn (create-extraction-fn dsl-expression)
        extracted-str (extraction-fn pkt-ba 0)]
    (is (= expected-str extracted-str))))

(deftest dsl-with-type-csv-str-test-2
  (let [expected-str "77,3,7,29639,2048,4096"
        dsl-expression {:type :csv-str
                        :rules [{:offset 12 :transformation :int32be :name :len}
                                {:offset :ipv4-id :transformation :int16 :name :ipId}
                                {:offset :ipv4-ttl :transformation :int8 :name :ipTtl}
                                {:offset :ipv4-checksum :transformation :int16 :name :ipChecksum}
                                {:offset :udp-src :transformation :int16 :name :udpSrc}
                                {:offset :udp-dst :transformation :int16 :name :udpDst}]}
        pkt-raw-vec [-5 -106 -57 84   15 -54 14 0   77 0 0 0   77 0 0 0    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extraction-fn (create-extraction-fn dsl-expression)
        extracted-str (extraction-fn pkt-ba 0)]
    (is (= expected-str extracted-str))))

(deftest dsl-with-type-json-str-test-2
  (let [expected-str "{\"len\":77,\"ipId\":3,\"ipTtl\":7,\"ipChecksum\":29639,\"udpSrc\":2048,\"udpDst\":4096}"
        dsl-expression {:type :json-str
                        :rules [{:offset 12 :transformation :int32be :name :len}
                                {:offset :ipv4-id :transformation :int16 :name :ipId}
                                {:offset :ipv4-ttl :transformation :int8 :name :ipTtl}
                                {:offset :ipv4-checksum :transformation :int16 :name :ipChecksum}
                                {:offset :udp-src :transformation :int16 :name :udpSrc}
                                {:offset :udp-dst :transformation :int16 :name :udpDst}]}
        pkt-raw-vec [-5 -106 -57 84   15 -54 14 0   77 0 0 0   77 0 0 0    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extraction-fn (create-extraction-fn dsl-expression)
        extracted-str (extraction-fn pkt-ba 0)]
    (is (= expected-str extracted-str))))

(deftest dsl-with-type-json-str-test-3
  (let [expected-str (str "{\"len\":77,\"ipId\":3,\"ipTtl\":7,\"ipChecksum\":29639,"
                          "\"ipDst\":\"252.253.254.255\",\"ipSrc\":\"1.2.3.4\",\"udpSrc\":2048,\"udpDst\":4096}")
        dsl-expression {:type :json-str
                        :rules [{:offset 12 :transformation :int32be :name :len}
                                {:offset :ipv4-id :transformation :int16 :name :ipId}
                                {:offset :ipv4-ttl :transformation :int8 :name :ipTtl}
                                {:offset :ipv4-checksum :transformation :int16 :name :ipChecksum}
                                {:offset :ipv4-dst :transformation :ipv4-address :name :ipDst}
                                {:offset :ipv4-src :transformation :ipv4-address :name :ipSrc}
                                {:offset :udp-src :transformation :int16 :name :udpSrc}
                                {:offset :udp-dst :transformation :int16 :name :udpDst}]}
        pkt-raw-vec [-5 -106 -57 84   15 -54 14 0   77 0 0 0   77 0 0 0    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extraction-fn (create-extraction-fn dsl-expression)
        extracted-str (extraction-fn pkt-ba 0)]
    (is (= expected-str extracted-str))))

