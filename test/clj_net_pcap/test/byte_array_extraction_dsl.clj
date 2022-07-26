;;;
;;; Copyright (C) 2015 Ruediger Gad
;;;
;;; This file is part of clj-net-pcap.
;;; clj-net-pcap is licensed under the terms of either
;;; - the GNU Lesser General Public License (LGPL) version 3 or later
;;;   http://www.gnu.org/licenses/lgpl-3.0.html
;;; or, at your option,
;;; - the Eclipse Public License (EPL) 1.0.
;;;   http://opensource.org/licenses/eclipse-1.0.php
;;;
;;; By contributing to clj-net-pcap, you agree that your contribution will be licensed under both licenses
;;; and that users of clj-net-pcap can chose any of these licenses.
;;;

(ns 
  ^{:author "Ruediger Gad",
    :doc "Tests for extracting data from byte arrays via a DSL."}
  clj-net-pcap.test.byte-array-extraction-dsl
  (:require
   (clojure [test :as test]))
  (:use
        clj-net-pcap.byte-array-extraction-dsl
        clj-net-pcap.core
        clj-net-pcap.dsl.transformation
        clj-net-pcap.pcap-data
        clj-assorted-utils.util))

(test/deftest simple-hardcoded-offsets-dsl-test
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
    (test/is (= expected-map extracted-map))))

(test/deftest simple-packet-offsets-name-dsl-test
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
    (test/is (= expected-map extracted-map))))

(test/deftest extended-packet-offsets-name-dsl-be-test
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
    (test/is (= expected-map extracted-map))))

(test/deftest extended-packet-offsets-name-dsl-le-test
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
    (test/is (= expected-map extracted-map))))

(test/deftest extended-packet-offsets-name-dsl-le-strings-test
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
    (test/is (= expected-map extracted-map))))

(test/deftest timestamp-extraction-le-test
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
    (test/is (= expected-map extracted-map))))

(test/deftest timestamp-extraction-be-test
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
    (test/is (= expected-map extracted-map))))

(test/deftest ethernet-address-extraction-test
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
    (test/is (= expected-map extracted-map))))

(test/deftest ipv4-address-extraction-test
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
    (test/is (= expected-map extracted-map))))

(test/deftest ipv4-version-extraction-test
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
    (test/is (= expected-map extracted-map))))

(test/deftest full-ipv4-udp-dsl-be-test
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
    (test/is (= expected-map extracted-map))))

(test/deftest full-ipv4-udp-dsl-le-test
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
    (test/is (= expected-map extracted-map))))

(test/deftest dsl-with-type-java-map-test
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
    (test/is (= java.util.HashMap (type extracted-map)))
    (test/is (= expected-map extracted-map))))

(test/deftest dsl-default-to-java-map-type-test
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
    (test/is (= java.util.HashMap (type extracted-map)))
    (test/is (= expected-map extracted-map))))

(test/deftest dsl-with-type-clj-map-test
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
    (test/is (map? extracted-map))
    (test/is (= expected-map extracted-map))))

(test/deftest dsl-with-type-csv-str-test
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
    (test/is (= expected-str extracted-str))))

(test/deftest dsl-with-type-json-str-test
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
    (test/is (= expected-str extracted-str))))

(test/deftest dsl-with-type-csv-str-test-2
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
    (test/is (= expected-str extracted-str))))

(test/deftest dsl-with-type-json-str-test-2
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
    (test/is (= expected-str extracted-str))))

(test/deftest dsl-with-type-csv-str-test-3
  (let [expected-str "77,3,7,29639,\"252.253.254.255\",\"1.2.3.4\",2048,4096"
        dsl-expression {:type :csv-str
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
    (test/is (= expected-str extracted-str))))

(test/deftest dsl-with-type-json-str-test-3
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
    (test/is (= expected-str extracted-str))))



;;; ARFF File Format Output Tests
;;; http://weka.wikispaces.com/ARFF+%28stable+version%29

(test/deftest get-arff-string-type-test
  (test/is (= "STRING" (get-arff-type-for-transformation-fn ipv4-address))))

(test/deftest get-arff-numeric-type-test
  (test/is (= "NUMERIC" (get-arff-type-for-transformation-fn int32))))

(test/deftest get-arff-numeric-type-test-2
  (test/is (= "NUMERIC" (get-arff-type-for-transformation-fn timestamp))))

(test/deftest get-arff-type-header-test
  (let [expected-str (str "@ATTRIBUTE ts NUMERIC\n"
                          "@ATTRIBUTE ipTtl NUMERIC\n"
                          "@ATTRIBUTE ipDst STRING\n"
                          "@ATTRIBUTE udpSrc NUMERIC\n")
        dsl-expression {:type :json-str
                        :rules [{:offset 0 :transformation :timestamp :name :ts}
                                {:offset :ipv4-ttl :transformation :int8 :name :ipTtl}
                                {:offset :ipv4-dst :transformation :ipv4-address :name :ipDst}
                                {:offset :udp-src :transformation :int16 :name :udpSrc}]}]
    (test/is (= expected-str (get-arff-type-header dsl-expression)))))

(test/deftest get-arff-header-test
  (let [expected-str (str "% Packet Capture\n"
                          "% Created with clj-net-pcap:\n"
                          "% https://github.com/ruedigergad/clj-net-pcap\n"
                          "%\n"
                          "@RELATION pcap\n\n"
                          "@ATTRIBUTE ts NUMERIC\n"
                          "@ATTRIBUTE ipTtl NUMERIC\n"
                          "@ATTRIBUTE ipDst STRING\n"
                          "@ATTRIBUTE udpSrc NUMERIC\n\n"
                          "@DATA\n")
        dsl-expression {:type :json-str
                        :rules [{:offset 0 :transformation :timestamp :name :ts}
                                {:offset :ipv4-ttl :transformation :int8 :name :ipTtl}
                                {:offset :ipv4-dst :transformation :ipv4-address :name :ipDst}
                                {:offset :udp-src :transformation :int16 :name :udpSrc}]}]
    (test/is (= expected-str (get-arff-header dsl-expression)))))

(test/deftest get-arff-type-header-new-dsl-test
  (let [expected-str (str "@ATTRIBUTE ts NUMERIC\n"
                          "@ATTRIBUTE ipTtl NUMERIC\n"
                          "@ATTRIBUTE ipDst STRING\n"
                          "@ATTRIBUTE udpSrc NUMERIC\n")
        dsl-expression {:type :json-str
                        :rules [['ts '(timestamp 0)]
                                ['ipTtl '(int8 ipv4-ttl)]
                                ['ipDst '(ipv4-address ipv4-dst)]
                                ['udpSrc '(int16 udp-src)]]}]
    (test/is (= expected-str (get-arff-type-header dsl-expression)))))



;;;
;;; Tests for new DSL approach
;;;

(test/deftest resolve-transf-fn-old-syntax-test
  (test/is (= (resolve 'clj-net-pcap.dsl.transformation/int16)
         (resolve-transf-fn {:offset :udp-src :transformation :int16 :name :udpSrc}))))

(test/deftest new-dsl-with-type-java-map-test
  (let [expected-map {"udpSrc" 2048, "udpDst" 4096}
        dsl-expression {:type :java-map
                        :rules [['udpSrc '(int16 udp-src)]
                                ['udpDst '(int16 udp-dst)]]}
        pkt-raw-vec [-5 -106 -57 84   15 -54 14 0   77 0 0 0   77 0 0 0    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extraction-fn (create-extraction-fn dsl-expression)
        extracted-map (extraction-fn pkt-ba 0)]
    (test/is (= java.util.HashMap (type extracted-map)))
    (test/is (= expected-map extracted-map))))

(test/deftest new-dsl-with-type-java-map-and-operation-test
  (let [expected-map {"udpSrc" 4096, "udpDst" 8192}
        dsl-expression {:type :java-map
                        :rules [['udpSrc '(* 2 (int16 udp-src))]
                                ['udpDst '(* 2 (int16 udp-dst))]]}
        pkt-raw-vec [-5 -106 -57 84   15 -54 14 0   77 0 0 0   77 0 0 0    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extraction-fn (create-extraction-fn dsl-expression)
        extracted-map (extraction-fn pkt-ba 0)]
    (test/is (= java.util.HashMap (type extracted-map)))
    (test/is (= expected-map extracted-map))))

(test/deftest new-dsl-with-type-java-map-and-operation-test-2
  (let [expected-map {"udpSrc" 1024, "udpDst" 2048}
        dsl-expression {:type :java-map
                        :rules [['udpSrc '(/ (int16 udp-src) 2)]
                                ['udpDst '(/ (int16 udp-dst) 2)]]}
        pkt-raw-vec [-5 -106 -57 84   15 -54 14 0   77 0 0 0   77 0 0 0    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extraction-fn (create-extraction-fn dsl-expression)
        extracted-map (extraction-fn pkt-ba 0)]
    (test/is (= java.util.HashMap (type extracted-map)))
    (test/is (= expected-map extracted-map))))

(test/deftest new-dsl-with-type-java-map-and-operation-test-3
  (let [expected-map {"udpSrc" (float 0.031250477), "udpDst" (float 0.06250095)}
        dsl-expression {:type :java-map
                        :rules [['udpSrc '(float (/ (int16 udp-src) 65535))]
                                ['udpDst '(float (/ (int16 udp-dst) 65535))]]}
        pkt-raw-vec [-5 -106 -57 84   15 -54 14 0   77 0 0 0   77 0 0 0    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extraction-fn (create-extraction-fn dsl-expression)
        extracted-map (extraction-fn pkt-ba 0)]
    (test/is (= java.util.HashMap (type extracted-map)))
    (test/is (= expected-map extracted-map))))


(test/deftest new-dsl-with-type-clj-map-test
  (let [expected-map {"udpSrc" (float 0.031250477), "udpDst" (float 0.06250095)}
        dsl-expression {:type :clj-map
                        :rules [['udpSrc '(float (/ (int16 udp-src) 65535))]
                                ['udpDst '(float (/ (int16 udp-dst) 65535))]]}
        pkt-raw-vec [-5 -106 -57 84   15 -54 14 0   77 0 0 0   77 0 0 0    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extraction-fn (create-extraction-fn dsl-expression)
        extracted-map (extraction-fn pkt-ba 0)]
    (test/is (map? extracted-map))
    (test/is (= expected-map extracted-map))))

(test/deftest new-dsl-with-type-csv-str-test
  (let [expected-str "0.031250477,0.06250095"
        dsl-expression {:type :csv-str
                        :rules [['udpSrc '(float (/ (int16 udp-src) 65535))]
                                ['udpDst '(float (/ (int16 udp-dst) 65535))]]}
        pkt-raw-vec [-5 -106 -57 84   15 -54 14 0   77 0 0 0   77 0 0 0    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extraction-fn (create-extraction-fn dsl-expression)
        extracted-str (extraction-fn pkt-ba 0)]
    (test/is (= expected-str extracted-str))))

(test/deftest new-dsl-with-type-json-str-test
  (let [expected-str "{\"udpSrc\":0.031250477,\"udpDst\":0.06250095}"
        dsl-expression {:type :json-str
                        :rules [['udpSrc '(float (/ (int16 udp-src) 65535))]
                                ['udpDst '(float (/ (int16 udp-dst) 65535))]]}
        pkt-raw-vec [-5 -106 -57 84   15 -54 14 0   77 0 0 0   77 0 0 0    ; 16 byte pcap header
                     -1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        extraction-fn (create-extraction-fn dsl-expression)
        extracted-str (extraction-fn pkt-ba 0)]
    (test/is (= expected-str extracted-str))))
