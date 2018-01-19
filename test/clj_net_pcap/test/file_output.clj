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
    :doc "Tests for writing data to a file."}
  clj-net-pcap.test.file-output
  (:use clojure.test
        clj-net-pcap.byte-array-extraction-dsl
        clj-net-pcap.core
        clj-net-pcap.pcap
        clj-net-pcap.pcap-data
        clj-assorted-utils.util)
  (:import (clj_net_pcap PacketHeaderDataBeanIpv4UdpOnly)))



(def test-out-file "file-out.test.file")

(defn- create-test-cljnetpcap-single
  [dsl-expr file-out-forwarder]
  (binding [clj-net-pcap.core/*bulk-size* 1
            clj-net-pcap.core/*emit-raw-data* true
            clj-net-pcap.core/*forward-exceptions* true
            clj-net-pcap.pcap/*snap-len* 64]
    (create-and-start-online-cljnetpcap
      #(file-out-forwarder ((partial process-packet-byte-buffer (create-extraction-fn dsl-expr)) %))
      lo
      "udp and (src port 2048) and (dst port 4096)")))

(defn- create-test-cljnetpcap-bs2
  [dsl-expr file-out-forwarder]
  (binding [clj-net-pcap.core/*bulk-size* 2
            clj-net-pcap.core/*emit-raw-data* true
            clj-net-pcap.core/*forward-exceptions* true
            clj-net-pcap.pcap/*snap-len* 64]
    (create-and-start-online-cljnetpcap
      #(file-out-forwarder ((partial process-packet-byte-buffer-bulk (create-extraction-fn dsl-expr)) %))
      lo
      "udp and (src port 2048) and (dst port 4096)")))

(defn stdout-formatter-fixture [f]
  (f)
  (rm test-out-file))
(use-fixtures :each stdout-formatter-fixture)



(deftest csv-str-to-file-online-test
  (let [expected-str "46,3,7,29639,2048,4096\n"
        dsl-expression {:type :csv-str
                        :rules [{:offset 12 :transformation :int32be :name :len}
                                {:offset :ipv4-id :transformation :int16 :name :ipId}
                                {:offset :ipv4-ttl :transformation :int8 :name :ipTtl}
                                {:offset :ipv4-checksum :transformation :int16 :name :ipChecksum}
                                {:offset :udp-src :transformation :int16 :name :udpSrc}
                                {:offset :udp-dst :transformation :int16 :name :udpDst}]}
        pkt-raw-vec [-1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        file-out-forwarder (create-file-out-forwarder test-out-file)
        cljnetpcap (create-test-cljnetpcap-single dsl-expression file-out-forwarder)]
    (sleep 1000)
    (cljnetpcap :send-bytes-packet pkt-ba)
    (sleep 1000)
    (file-out-forwarder)
    (is (= expected-str (slurp test-out-file)))
    (stop-cljnetpcap cljnetpcap)))

(deftest json-str-to-file-online-test
  (let [expected-str "{\"len\":46,\"ipId\":3,\"ipTtl\":7,\"ipChecksum\":29639,\"udpSrc\":2048,\"udpDst\":4096}\n"
        dsl-expression {:type :json-str
                        :rules [{:offset 12 :transformation :int32be :name :len}
                                {:offset :ipv4-id :transformation :int16 :name :ipId}
                                {:offset :ipv4-ttl :transformation :int8 :name :ipTtl}
                                {:offset :ipv4-checksum :transformation :int16 :name :ipChecksum}
                                {:offset :udp-src :transformation :int16 :name :udpSrc}
                                {:offset :udp-dst :transformation :int16 :name :udpDst}]}
        pkt-raw-vec [-1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        file-out-forwarder (create-file-out-forwarder test-out-file)
        cljnetpcap (create-test-cljnetpcap-single dsl-expression file-out-forwarder)]
    (sleep 1000)
    (cljnetpcap :send-bytes-packet pkt-ba)
    (sleep 1000)
    (file-out-forwarder)
    (is (= expected-str (slurp test-out-file)))
    (stop-cljnetpcap cljnetpcap)))

(deftest csv-str-to-file-online-three-packets-test
  (let [expected-str "46,3,7,29639,2048,4096\n46,3,7,29639,2048,4096\n46,3,7,29639,2048,4096\n"
        dsl-expression {:type :csv-str
                        :rules [{:offset 12 :transformation :int32be :name :len}
                                {:offset :ipv4-id :transformation :int16 :name :ipId}
                                {:offset :ipv4-ttl :transformation :int8 :name :ipTtl}
                                {:offset :ipv4-checksum :transformation :int16 :name :ipChecksum}
                                {:offset :udp-src :transformation :int16 :name :udpSrc}
                                {:offset :udp-dst :transformation :int16 :name :udpDst}]}
        pkt-raw-vec [-1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        file-out-forwarder (create-file-out-forwarder test-out-file)
        cljnetpcap (create-test-cljnetpcap-single dsl-expression file-out-forwarder)]
    (sleep 1000)
    (cljnetpcap :send-bytes-packet pkt-ba)
    (cljnetpcap :send-bytes-packet pkt-ba)
    (cljnetpcap :send-bytes-packet pkt-ba)
    (sleep 1000)
    (file-out-forwarder)
    (is (= expected-str (slurp test-out-file)))
    (stop-cljnetpcap cljnetpcap)))

(deftest json-str-to-file-online-three-packets-test
  (let [expected-str (str
                       "{\"len\":46,\"ipId\":3,\"ipTtl\":7,\"ipChecksum\":29639,\"udpSrc\":2048,\"udpDst\":4096}\n"
                       "{\"len\":46,\"ipId\":3,\"ipTtl\":7,\"ipChecksum\":29639,\"udpSrc\":2048,\"udpDst\":4096}\n"
                       "{\"len\":46,\"ipId\":3,\"ipTtl\":7,\"ipChecksum\":29639,\"udpSrc\":2048,\"udpDst\":4096}\n")
        dsl-expression {:type :json-str
                        :rules [{:offset 12 :transformation :int32be :name :len}
                                {:offset :ipv4-id :transformation :int16 :name :ipId}
                                {:offset :ipv4-ttl :transformation :int8 :name :ipTtl}
                                {:offset :ipv4-checksum :transformation :int16 :name :ipChecksum}
                                {:offset :udp-src :transformation :int16 :name :udpSrc}
                                {:offset :udp-dst :transformation :int16 :name :udpDst}]}
        pkt-raw-vec [-1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        file-out-forwarder (create-file-out-forwarder test-out-file)
        cljnetpcap (create-test-cljnetpcap-single dsl-expression file-out-forwarder)]
    (sleep 1000)
    (cljnetpcap :send-bytes-packet pkt-ba)
    (cljnetpcap :send-bytes-packet pkt-ba)
    (cljnetpcap :send-bytes-packet pkt-ba)
    (sleep 1000)
    (file-out-forwarder)
    (is (= expected-str (slurp test-out-file)))
    (stop-cljnetpcap cljnetpcap)))

(deftest csv-str-to-file-online-bs2-test
  (let [expected-str "46,3,7,29639,2048,4096\n46,3,7,29639,2048,4096\n"
        dsl-expression {:type :csv-str
                        :rules [{:offset 12 :transformation :int32be :name :len}
                                {:offset :ipv4-id :transformation :int16 :name :ipId}
                                {:offset :ipv4-ttl :transformation :int8 :name :ipTtl}
                                {:offset :ipv4-checksum :transformation :int16 :name :ipChecksum}
                                {:offset :udp-src :transformation :int16 :name :udpSrc}
                                {:offset :udp-dst :transformation :int16 :name :udpDst}]}
        pkt-raw-vec [-1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0                  ; 14 byte Ethernet header
                     69 0 0 32 0 3 64 0 7 17 115 -57 1 2 3 4 -4 -3 -2 -1   ; 20 byte IP header
                     8 0 16 0 0 4 -25 -26                                  ; 8 byte UDP header
                     97 98 99 100]                                         ; 4 byte data "abcd"
        pkt-ba (byte-array (map byte pkt-raw-vec))
        file-out-forwarder (create-file-out-forwarder test-out-file true)
        cljnetpcap (create-test-cljnetpcap-bs2 dsl-expression file-out-forwarder)]
    (sleep 1000)
    (cljnetpcap :send-bytes-packet pkt-ba)
    (cljnetpcap :send-bytes-packet pkt-ba)
    (sleep 1000)
    (file-out-forwarder)
    (is (= expected-str (slurp test-out-file)))
    (stop-cljnetpcap cljnetpcap)))

