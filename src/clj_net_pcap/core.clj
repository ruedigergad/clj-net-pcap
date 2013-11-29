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
    :doc "clj-net-pcap is a wrapper/adapter/facade (whatever) around jNetPcap that 
          enables and eases packet capturing with Clojure."}  
  clj-net-pcap.core
  (:use clojure.pprint 
        clj-net-pcap.native
        clj-net-pcap.pcap
        clj-net-pcap.pcap-data
        clj-net-pcap.sniffer
        clj-assorted-utils.util)
  (:import (java.util.concurrent LinkedBlockingQueue)
           (org.jnetpcap Pcap)
           (org.jnetpcap.packet PcapPacket PcapPacketHandler)))


(def ^:dynamic *trace-handler-fn* false)


(defmacro insert-counter-tracing
  [cntr txt]
  (if *trace-handler-fn*
	  `(do
	     (~cntr inc)
	     (if (= 0 (mod (~cntr) 1000))
	       (println ~txt 
	                (~cntr))))))

(defn create-and-start-cljnetpcap
  "Convenience function for creating and starting packet capturing.
   forwarder-fn will be called for each captured packet.
   Capturing can be influenced via the optional device and filter-expression arguments.
   By default the 'any' device is used for capturing with no filter being applied.
   Please note that the returned handle should be stored as it is needed for stopping the capture."
  ([forwarder-fn]
    (create-and-start-cljnetpcap forwarder-fn any))
  ([forwarder-fn device]
    (create-and-start-cljnetpcap forwarder-fn device ""))
  ([forwarder-fn device filter-expression]
    (let [queue (LinkedBlockingQueue.)
          forwarder (create-and-start-forwarder queue forwarder-fn)
          pcap (create-and-activate-pcap device)
          _ (create-and-set-filter pcap filter-expression)
          handler-fn-invocation-counter (counter)
          handler-fn-packet-counter (counter)
          handler-fn (fn [p _]
                       (insert-counter-tracing handler-fn-invocation-counter 
                                               "handler-fn-invocations:")
                       (when-not (nil? p)
                         (insert-counter-tracing handler-fn-packet-counter 
                                               "handler-fn-packets:")
                         (.offer queue (clone-packet p))))
          sniffer (create-and-start-sniffer pcap handler-fn)
          stat-fn (create-stat-fn pcap)
          stat-print-fn #(print-err-ln (str "pcap-stats," (stat-fn) ",queue_size," (.size queue)))]
      (fn [k]
        (condp = k
          :stat (stat-print-fn)
          :stop (do
                  (stop-sniffer sniffer)
                  (stop-forwarder forwarder)))))))

(defn print-stat-cljnetpcap
  "Given a handle as returned by, e.g., create-and-start-cljnetpcap,
   this prints statistical output about the capture process."
  [cljnetpcap] 
  (cljnetpcap :stat))

(defn stop-cljnetpcap
  "Stops a running capture. Argument is the handle as returned by create-and-start-cljnetpcap."
  [cljnetpcap]
  (cljnetpcap :stop))

(defn process-pcap-file
  "Convenience function to process data stored in pcap files.
   Arguments are the file-name of the pcap file, the handler-fn that is executed for each read packet, and optional user data.
   handler-fn takes two arguments, the first is the org.jnetpcap.packet.PcapPacket instance, the second is the user data.
   By default nil is used as user data."
  ([file-name handler-fn]
    (process-pcap-file file-name handler-fn nil))
  ([file-name handler-fn user-data]
    (let [^Pcap pcap (create-pcap-from-file file-name)
          packet-handler (proxy [PcapPacketHandler] []
                           (nextPacket [p u] (handler-fn p u)))]
      (.dispatch pcap -1 packet-handler user-data))))

(defn process-pcap-file-as-nested-maps
  "Convenience function to read a pcap file and process the packets in map format."
  [file-name handler-fn]
    (process-pcap-file 
      file-name
      (fn [p _]
        (handler-fn (pcap-packet-to-nested-maps p)))))

(defn extract-nested-maps-from-pcap-file
  "Convenience function to extract the data from a pcap file in map format.
   Please note that all data will be stored in memory.
   So this is not suited for large amounts of data.
   Returns a vector that contains the extracted maps."
  [file-name]
    (let [extracted-data (ref [])]
      (process-pcap-file-as-nested-maps file-name
                                 #(dosync (alter extracted-data conj %)))
      @extracted-data))

