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
    :doc "Tests for sending packets via pcap."}
  clj-net-pcap.test.pcap-send
  (:use clojure.test
        clj-assorted-utils.util
        clj-net-pcap.core
        clj-net-pcap.packet-gen
        clj-net-pcap.pcap
        clj-net-pcap.pcap-data
        clj-net-pcap.sniffer)
  (:import (java.util Arrays)
           (java.nio ByteBuffer)))

(def test-pkt-bytes [-1 -2 -3 -14 -15 -16 1 2 3 4 5 6 8 0
                     69 0 0 40 0 3 64 0 7 1 115 -49 1 2 3 4 -4 -3 -2 -1
                     8 0 50 -78 0 123 0 12 0 0 0 0 0 0 0 0 97 98 99 100])

(def test-pkt-descr-map {"len" 54, "ethSrc" "01:02:03:04:05:06", "ethDst" "FF:FE:FD:F2:F1:F0",
                         "ipVer" 4, "ipDst" "252.253.254.255", "ipId" 3, "ipType" 1,
                         "ipTtl" 7, "ipSrc" "1.2.3.4",
                         "icmpType" 8, "icmpEchoSeq" "bar",
                         "icmpId" 123, "icmpSeqNo" 12, "data" "abcd"})



(deftest naive-pcap-send-byte-array-test
  (let [ba (byte-array (map byte test-pkt-bytes))
        pcap (create-and-activate-online-pcap lo)]
    (pcap :send-bytes-packet ba)
    (close-pcap pcap)))

(deftest pcap-send-and-sniff-byte-array-test
  (let [ba (byte-array (map byte test-pkt-bytes))
        bb (ByteBuffer/allocate (alength ba))
        pcap (create-and-activate-online-pcap lo)
        flag (prepare-flag)
        handler (fn [ph buf _]
                  (doto bb
                    (.put buf)
                    (.flip))
                  (set-flag flag))
        sniffer (create-and-start-sniffer pcap handler)]
    ; Give the sniffer a little time to start before we actually send the packet.
    (sleep 100)
    (pcap :send-bytes-packet ba)
    (await-flag flag)
    (is (flag-set? flag))
    (is (Arrays/equals ba (.array bb)))
    (stop-sniffer sniffer)))

(deftest cljnetpcap-send-and-receive-bytes-packet-raw-test
  (let [ba (byte-array (map byte test-pkt-bytes))
        bb (ByteBuffer/allocate (+ (alength ba) 16))
        flag (prepare-flag)
        forwarder-fn (fn [data]
                       (doto bb
                         (.put data)
                         (.flip))
                       (set-flag flag))
        cljnetpcap (binding [*emit-raw-data* true
                             *queue-size* 1]
                     (create-and-start-online-cljnetpcap forwarder-fn lo))
        _ (add-filter cljnetpcap "icmp and (dst host 252.253.254.255) and (src host 1.2.3.4)")]
    (sleep 100)
    (cljnetpcap :send-bytes-packet ba)
    (await-flag flag)
    (is (flag-set? flag))
    (is (= (vec ba) (subvec (vec (.array bb)) 16)))
    (stop-cljnetpcap cljnetpcap)))

(deftest cljnetpcap-send-and-receive-bytes-packet-maps-test
  (let [ba (byte-array (map byte test-pkt-bytes))
        expected {"len" 54, "ethSrc" "01:02:03:04:05:06", "ethDst" "FF:FE:FD:F2:F1:F0",
                  "ipVer" 4, "ipDst" "252.253.254.255", "ipId" 3,
                  "ipTtl" 7, "ipSrc" "1.2.3.4", "ipChecksum" 29647,
                  "icmpEchoSeq" 12, "icmpType" "echo request"}
        received (ref nil)
        flag (prepare-flag)
        forwarder-fn (fn [data]
                       (dosync (ref-set received (pcap-packet-to-map data)))
                       (set-flag flag))
        cljnetpcap (binding [*emit-raw-data* false
                             *queue-size* 1]
                     (create-and-start-online-cljnetpcap forwarder-fn lo))
        _ (add-filter cljnetpcap "icmp and (dst host 252.253.254.255) and (src host 1.2.3.4)")]
    (sleep 100)
    (cljnetpcap :send-bytes-packet ba)
    (await-flag flag)
    (is (flag-set? flag))
    (is (= expected (dissoc (merge {} @received) "ts")))
    (stop-cljnetpcap cljnetpcap)))

(deftest cljnetpcap-send-and-receive-bytes-packet-count-test
  (let [ba (byte-array (map byte test-pkt-bytes))
        cntr (counter)
        forwarder-fn (fn [_]
                       (cntr inc))
        cljnetpcap (create-and-start-online-cljnetpcap forwarder-fn lo)
        _ (add-filter cljnetpcap "icmp and (dst host 252.253.254.255) and (src host 1.2.3.4)")]
    (sleep 100)
    (doseq [_ (repeat 10 1)]
      (sleep 10)
      (cljnetpcap :send-bytes-packet ba))
    (sleep 300)
    (is (= 10 (cntr)))
    (stop-cljnetpcap cljnetpcap)))

(deftest cljnetpcap-send-and-receive-bytes-packet-with-count-and-delay-test
  (let [ba (byte-array (map byte test-pkt-bytes))
        cntr (counter)
        forwarder-fn (fn [_]
                       (cntr inc))
        cljnetpcap (create-and-start-online-cljnetpcap forwarder-fn lo)
        _ (add-filter cljnetpcap "icmp and (dst host 252.253.254.255) and (src host 1.2.3.4)")]
    (sleep 100)
    (cljnetpcap :send-bytes-packet ba 10 10)
    (sleep 300)
    (is (= 10 (cntr)))
    (stop-cljnetpcap cljnetpcap)))

(deftest cljnetpcap-send-and-receive-bytes-packet-with-count-test
  (let [ba (byte-array (map byte test-pkt-bytes))
        cntr (counter)
        forwarder-fn (fn [_]
                       (cntr inc))
        cljnetpcap (create-and-start-online-cljnetpcap forwarder-fn lo)
        _ (add-filter cljnetpcap "icmp and (dst host 252.253.254.255) and (src host 1.2.3.4)")]
    (sleep 100)
    (cljnetpcap :send-bytes-packet ba 10)
    (sleep 300)
    (is (= 10 (cntr)))
    (stop-cljnetpcap cljnetpcap)))

(deftest cljnetpcap-send-and-receive-bytes-packet-maps-test
  (let [expected {"len" 54, "ethSrc" "01:02:03:04:05:06", "ethDst" "FF:FE:FD:F2:F1:F0",
                  "ipVer" 4, "ipDst" "252.253.254.255", "ipId" 3,
                  "ipTtl" 7, "ipSrc" "1.2.3.4", "ipChecksum" 29647,
                  "icmpEchoSeq" 12, "icmpType" "echo request"}
        received (ref nil)
        flag (prepare-flag)
        forwarder-fn (fn [data]
                       (dosync (ref-set received (pcap-packet-to-map data)))
                       (set-flag flag))
        cljnetpcap (binding [*emit-raw-data* false
                             *queue-size* 1]
                     (create-and-start-online-cljnetpcap forwarder-fn lo))
        _ (add-filter cljnetpcap "icmp and (dst host 252.253.254.255) and (src host 1.2.3.4)")]
    (sleep 100)
    (cljnetpcap :send-packet-map test-pkt-descr-map)
    (await-flag flag)
    (is (flag-set? flag))
    (is (= expected (dissoc (merge {} @received) "ts")))
    (stop-cljnetpcap cljnetpcap)))

(deftest cljnetpcap-send-and-receive-packet-from-description-map-count-test
  (let [cntr (counter)
        forwarder-fn (fn [_]
                       (cntr inc))
        cljnetpcap (create-and-start-online-cljnetpcap forwarder-fn lo)
        _ (add-filter cljnetpcap "icmp and (dst host 252.253.254.255) and (src host 1.2.3.4)")]
    (sleep 100)
    (doseq [_ (repeat 10 1)]
      (sleep 10)
      (cljnetpcap :send-packet-map test-pkt-descr-map))
    (sleep 300)
    (is (= 10 (cntr)))
    (stop-cljnetpcap cljnetpcap)))

(deftest cljnetpcap-send-and-receive-packet-from-description-map-with-count-and-delay-test
  (let [cntr (counter)
        forwarder-fn (fn [_]
                       (cntr inc))
        cljnetpcap (create-and-start-online-cljnetpcap forwarder-fn lo)
        _ (add-filter cljnetpcap "icmp and (dst host 252.253.254.255) and (src host 1.2.3.4)")]
    (sleep 100)
    (cljnetpcap :send-packet-map test-pkt-descr-map 10 10)
    (sleep 300)
    (is (= 10 (cntr)))
    (stop-cljnetpcap cljnetpcap)))

(deftest cljnetpcap-send-and-receive-packet-from-description-map-with-count-test
  (let [cntr (counter)
        forwarder-fn (fn [_]
                       (cntr inc))
        cljnetpcap (create-and-start-online-cljnetpcap forwarder-fn lo)
        _ (add-filter cljnetpcap "icmp and (dst host 252.253.254.255) and (src host 1.2.3.4)")]
    (sleep 100)
    (cljnetpcap :send-packet-map test-pkt-descr-map 10)
    (sleep 300)
    (is (= 10 (cntr)))
    (stop-cljnetpcap cljnetpcap)))

