;;;
;;; Copyright (C) 2013 Ruediger Gad
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
    :doc "Clojure tests for reading from pcap files."} 
  clj-net-pcap.test.pcap-offline
  (:use clojure.test
        clj-net-pcap.core
        clj-net-pcap.pcap
        clj-assorted-utils.util)
  (:import (org.jnetpcap.packet PcapPacketHandler)))

(def test-file "test/clj_net_pcap/test/data/offline-test.pcap")

(deftest test-create-pcap-from-file-error
  (let [_ (println "Please note: this test is supposed to emit an error message.\n"
                   "The error message should complain about the file 'this.file.does-not-exist' not being there.")
        flag (prepare-flag)
        pcap (try
               (create-pcap-from-file "this.file.does-not-exist")
               (catch Exception e
                 (set-flag flag)
                 nil))]
    (is (flag-set? flag))
    (is (nil? pcap))))

(deftest test-create-pcap-from-file
  (let [pcap (create-pcap-from-file test-file)]
    (is (not (nil? pcap)))))

(deftest test-create-pcap-from-file-and-dispatch
  (let [pcap (create-pcap-from-file test-file)
        my-counter (prepare-counter)
        packet-handler (proxy [PcapPacketHandler] []
                         (nextPacket [p u] (inc-counter my-counter)))]
    (is (= 0 @my-counter))
    (.dispatch pcap -1 packet-handler nil)
    (sleep 200)
    (is (= 6 @my-counter))))

(deftest test-process-pcap-file
  (let [my-counter (prepare-counter)
        handler-fn (fn [_ _] (inc-counter my-counter))]
    (is (= 0 @my-counter))
    (process-pcap-file test-file handler-fn)
    (is (= 6 @my-counter))))

(deftest test-process-pcap-file-as-maps
  (let [my-map (ref {})
        handler-fn (fn [m]
                     (dosync (ref-set my-map m)))]
    (is (= {} @my-map))
    (process-pcap-file-as-maps "test/clj_net_pcap/test/data/icmp-echo-request.pcap" handler-fn)
    (is (= {"PcapHeader" {"timestampInNanos" 1365516583196346000, "wirelen" 98},
            "DataLinkLayer" {"index" 0, "ProtocolType" "Ethernet", "destination" "E0:CB:4E:E3:38:46", "source" "90:E6:BA:3C:9A:47", "next" 2},
            "NetworkLayer" {"ttl" 64, "destination" "173.194.69.94", "index" 1, "ProtocolType" "Ip4", "next" 12, "tos" 0, "type" 1, "source" "192.168.20.126", "id" 0},
            "Icmp" {"index" 2, "typeDescription" "echo request", "next" 0}}
           @my-map))))

(deftest test-extract-maps-from-pcap-file
  (let [my-map (extract-maps-from-pcap-file "test/clj_net_pcap/test/data/icmp-echo-request.pcap")]
    (is (= 1 (count my-map)))
    (is (= {"PcapHeader" {"timestampInNanos" 1365516583196346000, "wirelen" 98},
            "DataLinkLayer" {"index" 0, "ProtocolType" "Ethernet", "destination" "E0:CB:4E:E3:38:46", "source" "90:E6:BA:3C:9A:47", "next" 2},
            "NetworkLayer" {"ttl" 64, "destination" "173.194.69.94", "index" 1, "ProtocolType" "Ip4", "next" 12, "tos" 0, "type" 1, "source" "192.168.20.126", "id" 0},
            "Icmp" {"index" 2, "typeDescription" "echo request", "next" 0}}
            (first my-map)))))

