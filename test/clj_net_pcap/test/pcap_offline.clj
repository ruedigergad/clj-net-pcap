;;;
;;; Copyright (C) 2013 Ruediger Gad
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
    :doc "Clojure tests for reading from pcap files."}
  clj-net-pcap.test.pcap-offline
  (:require
   (clojure [test :as test])
   (clj-assorted-utils [util :as utils])
   (clj-net-pcap [core :as core])
   (clj-net-pcap [pcap :as pcap])
   (clj-net-pcap [pcap-data :as pcap-data]))
  (:import (org.jnetpcap.packet PcapPacketHandler)
           (clj_net_pcap PacketHeaderDataBean)))

(def test-file "test/clj_net_pcap/test/data/offline-test.pcap")

(test/deftest test-create-pcap-from-file-error
  (let [_ (println "Please note: this test is supposed to emit an error message.\n"
                   "The error message should complain about the file 'this.file.does-not-exist' not being there.")
        flag (utils/prepare-flag)
        pcap (try
               (pcap/create-pcap-from-file "this.file.does-not-exist")
               (catch Exception _
                 (utils/set-flag flag)
                 nil))]
    (test/is (utils/flag-set? flag))
    (test/is (nil? pcap))))

(test/deftest test-create-pcap-from-file
  (let [pcap (pcap/create-pcap-from-file test-file)]
    (test/is (not (nil? pcap)))))

; The use of .dispatch with pcap files is deprecated.
; Use core/process-pcap-file for processing pcap files.
;(test/deftest test-create-pcap-from-file-and-dispatch
;  (let [pcap (pcap/create-pcap-from-file test-file)
;        my-counter (utils/prepare-counter)
;        packet-handler (proxy [PcapPacketHandler] []
;                         (nextPacket [p u] (utils/inc-counter my-counter)))]
;    (test/is (= 0 @my-counter))
;    (.dispatch pcap -1 packet-handler nil)
;    (utils/sleep 200)
;    (test/is (= 6 @my-counter))))

(test/deftest test-process-pcap-file
  (let [my-counter (utils/counter)
        handler-fn (fn [_] (my-counter inc))]
    (test/is (= 0 (my-counter)))
    (core/process-pcap-file test-file handler-fn)
    (utils/sleep 1000)
    (test/is (= 6 (my-counter)))))

(test/deftest test-process-pcap-file-as-nested-maps
  (let [my-map (ref {})
        handler-fn (fn [m]
                     (dosync (ref-set my-map m)))]
    (test/is (= {} @my-map))
    (core/process-pcap-file
      "test/clj_net_pcap/test/data/icmp-echo-request.pcap"
      #(handler-fn (pcap-data/pcap-packet-to-nested-maps %)))
; FIXME: The destination netmask and bits are wrong.
    (test/is (= {"PcapHeader" {"timestampInNanos" 1365516583196346000, "wirelen" 98},
            "DataLinkLayer" {"index" 0, "ProtocolType" "Ethernet", "destination" "E0:CB:4E:E3:38:46", "source" "90:E6:BA:3C:9A:47", "next" 2},
            "NetworkLayer" {
;              "destinationNetmaskBits" 24, "destinationNetwork" "192.168.20.0", "sourceNetwork" "192.168.20.0", "sourceNetmaskBits" 24,
              "ttl" 64, "destination" "173.194.69.94", "index" 1, "ProtocolType" "Ip4", "id" 0, "next" 12, "tos" 0, "type" 1, "source" "192.168.20.126"
            },
            "Icmp" {"index" 2, "typeDescription" "echo request", "next" 0}}
           @my-map))))

(test/deftest test-extract-nested-maps-from-pcap-file
  (let [my-maps (core/extract-nested-maps-from-pcap-file "test/clj_net_pcap/test/data/icmp-echo-request.pcap")]
    (test/is (= 1 (count my-maps)))
    (test/is (= {"PcapHeader" {"timestampInNanos" 1365516583196346000, "wirelen" 98},
            "DataLinkLayer" {"index" 0, "ProtocolType" "Ethernet", "destination" "E0:CB:4E:E3:38:46", "source" "90:E6:BA:3C:9A:47", "next" 2},
            "NetworkLayer" {
;              "destinationNetmaskBits" 24, "destinationNetwork" "192.168.20.0", "sourceNetwork" "192.168.20.0", "sourceNetmaskBits" 24,
              "ttl" 64, "destination" "173.194.69.94", "index" 1, "ProtocolType" "Ip4", "next" 12, "tos" 0, "type" 1, "source" "192.168.20.126", "id" 0
            },
            "Icmp" {"index" 2, "typeDescription" "echo request", "next" 0}}
            (first my-maps)))))

(test/deftest test-extract-maps-from-pcap-file
  (let [my-maps (core/extract-maps-from-pcap-file "test/clj_net_pcap/test/data/icmp-echo-request.pcap")]
    (test/is (= 1 (count my-maps)))
    (test/is (= {"ts" 1365516583196346000, "len" 98,
            "ethDst" "E0:CB:4E:E3:38:46", "ethSrc" "90:E6:BA:3C:9A:47",
            "ipDst" "173.194.69.94", "ipSrc" "192.168.20.126", "ipVer" 4,
            "ipId" 0, "ipTtl" 64, "ipChecksum" 29282,
            "icmpType" "echo request", "icmpEchoSeq" 21}
            (first my-maps)))))

(test/deftest test-extract-beans-from-pcap-file
  (let [my-beans (core/extract-beans-from-pcap-file "test/clj_net_pcap/test/data/icmp-echo-request.pcap")
        expected (doto (PacketHeaderDataBean.)
                   (.setTs 1365516583196346000) (.setLen 98)
                   (.setEthDst "E0:CB:4E:E3:38:46") (.setEthSrc "90:E6:BA:3C:9A:47")
                   (.setIpDst "173.194.69.94") (.setIpSrc "192.168.20.126")
                   (.setIpId 0) (.setIpTtl 64) (.setIpChecksum 29282)
                   (.setIpVer 4) (.setIcmpType "echo request") (.setIcmpEchoSeq 21))]
    (test/is (= 1 (count my-beans)))
    (test/is (= expected
           (first my-beans)))))

(test/deftest test-extract-byte-arrays-raw-data-from-pcap-file
  (let [my-raw-data (core/extract-byte-arrays-from-pcap-file test-file)]
    (test/is (= 6 (count my-raw-data)))
    (test/is (vector? my-raw-data))
    (test/is (= utils/byte-array-type (type (my-raw-data 0))))))
