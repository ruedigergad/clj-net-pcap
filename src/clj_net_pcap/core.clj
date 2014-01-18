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
          enables and eases packet capturing with Clojure.

          The core namespace contains the external API. For most use-cases the 
          functionality provided in core should be sufficient."}  
  clj-net-pcap.core
  (:use clojure.pprint 
        [clojure.string :only [join]]
        clj-net-pcap.native
        clj-net-pcap.pcap
        clj-net-pcap.pcap-data
        clj-net-pcap.sniffer
        clj-assorted-utils.util)
  (:import (clj_net_pcap Counter InfiniteLoop)
           (java.nio ByteBuffer)
           (java.util ArrayList)
           (java.util.concurrent ArrayBlockingQueue LinkedBlockingQueue)
           (org.jnetpcap Pcap PcapDLT PcapHeader)
           (org.jnetpcap.nio JBuffer JMemory JMemory$Type)
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

(defrecord ByteBufferRecord
  [cl wl s us bb])

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
  ([forwarder-fn device filter-expr]
    (let [buffer-queue-size 3000
          packet-queue-size 300000
          running (ref true)
          byte-buffer-drop-counter (Counter.)
          byte-buffer-queued-counter (Counter.)
          byte-buffer-queue (ArrayBlockingQueue. buffer-queue-size)
          handler-fn (fn [^PcapHeader ph ^ByteBuffer bb ^Object _]
                       (if (and 
                             (< (.size byte-buffer-queue) (- buffer-queue-size 1))
                             (not (nil? bb)))
                         (if (.offer byte-buffer-queue
                                         (ByteBufferRecord. (.caplen ph) (.wirelen ph) (.hdr_sec ph) (.hdr_usec ph) bb))
                           (.inc byte-buffer-queued-counter)
                           (.inc byte-buffer-drop-counter))
                         (.inc byte-buffer-drop-counter)))
          packet-drop-counter (Counter.)
          packet-queued-counter (Counter.)
          packet-queue (ArrayBlockingQueue. packet-queue-size)
          ^ArrayList tmp-list (ArrayList. 100)
          byte-buffer-processor (fn [] 
                                  (try
                                    (.drainTo byte-buffer-queue tmp-list 100)
                                    (doseq [^ByteBufferRecord bbrec tmp-list]
                                      (if (and
                                            (< (.size packet-queue) (- packet-queue-size 1))
                                            (not (nil? bbrec))
                                            (> (:cl bbrec) 0)
                                            (> (:wl bbrec) 0))
                                        (let [^ByteBuffer bb (:bb bbrec)
                                              ^PcapHeader ph (PcapHeader. (:cl bbrec) (:wl bbrec) (:s bbrec) (:us bbrec))
                                              bb-buf (JBuffer. bb)
                                              ^PcapPacket pkt (PcapPacket. JMemory$Type/POINTER)]
                                          (.peer pkt ph bb-buf)
                                          (.scan pkt (.value (PcapDLT/EN10MB)))
                                          (if (.offer packet-queue (PcapPacket. pkt))
                                            (.inc packet-queued-counter)
                                            (.inc packet-drop-counter)))
                                        (.inc packet-drop-counter)))
                                    (.clear tmp-list)
                                    (catch Exception e
                                      (if @running
                                        (println e)))))
          byte-buffer-processor-thread (doto 
                                         (InfiniteLoop. byte-buffer-processor)
                                         (.setName "ByteBufferProcessor")
                                         (.setDaemon true)
                                         (.start))
          pcap (create-and-activate-pcap device)
          filter-expressions (ref [])
          _ (if (and 
                  filter-expr 
                  (not= "" filter-expr))
              (dosync (alter filter-expressions conj filter-expr)))
          _ (create-and-set-filter pcap filter-expr)
          forwarder (create-and-start-forwarder packet-queue forwarder-fn)
          sniffer (create-and-start-sniffer pcap handler-fn)
          stat-fn (create-stat-fn pcap)
          stat-print-fn #(print-err-ln
                           (str "pcap_stats," (stat-fn)
                                ",byte_buffer_queue_size," (.size byte-buffer-queue)
                                ",byte_buffer_queued," (.value byte-buffer-queued-counter)
                                ",byte_buffer_drop," (.value byte-buffer-drop-counter)
                                ",packet_queue_size," (.size packet-queue)
                                ",packet_queued," (.value packet-queued-counter)
                                ",packet_drop," (.value packet-drop-counter)))]
      (fn 
        ([k]
          (condp = k
            :stat (stat-print-fn)
            :stop (do
                    (dosync (ref-set running false))
                    (.stop byte-buffer-processor-thread)
                    (stop-sniffer sniffer)
                    (stop-forwarder forwarder))
            :get-filters @filter-expressions
            :remove-last-filter (do
                                  (dosync
                                    (alter filter-expressions pop))
                                  (create-and-set-filter pcap (join " " @filter-expressions)))
            :default (throw (RuntimeException. (str "Unsupported operation: " k)))))
        ([k arg]
          (condp = k
            :add-filter (when (and arg (not= arg ""))
                          (dosync
                            (alter filter-expressions conj arg))
                          (create-and-set-filter pcap (join " " @filter-expressions)))
            :remove-filter (do (dosync
                                 (alter filter-expressions (fn [fe] (vec (filter #(not= arg %) fe)))))
                               (create-and-set-filter pcap (join " " @filter-expressions)))
            :default (throw (RuntimeException. (str "Unsupported operation: " k)))))))))

(defn print-stat-cljnetpcap
  "Given a handle as returned by, e.g., create-and-start-cljnetpcap,
   this prints statistical output about the capture process."
  [cljnetpcap] 
  (cljnetpcap :stat))

(defn stop-cljnetpcap
  "Stops a running capture. Argument is the handle as returned by create-and-start-cljnetpcap."
  [cljnetpcap]
  (cljnetpcap :stop))

(defn get-filters
  "Returns the vector containing all currently applied filter sub-expressions."
  [cljnetpcap]
  (cljnetpcap :get-filters))

(defn add-filter
  "Add filter to a running pcap instance."
  [cljnetpcap filter-expr]
  (cljnetpcap :add-filter filter-expr))

(defn remove-last-filter
  "Remove the last filter expression."
  [cljnetpcap]
  (cljnetpcap :remove-last-filter))

(defn remove-filter
  "Remove the matching filter."
  [cljnetpcap filter-expr]
  (cljnetpcap :remove-filter filter-expr))

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
                           (nextPacket [^PcapPacket p ^Object u] (handler-fn p u)))]
      (.dispatch pcap -1 packet-handler user-data))))

(defn process-pcap-file-with-extraction-fn
  "Convenience function to read a pcap file and process the packets in map format."
  [file-name handler-fn extraction-fn]
    (process-pcap-file 
      file-name
      (fn [p _]
        (handler-fn (extraction-fn p)))))

(defn extract-data-from-pcap-file
  "Function to extract the data from a pcap file.
   The data will be formatted with format-fn.
   Please note that all data will be stored in memory.
   So this is not suited for large amounts of data.
   Returns a vector that contains the extracted maps.

   See also:
   extract-nested-maps-from-pcap-file
   extract-maps-from-pcap-file
   extract-maps-from-pcap-file"
  [file-name format-fn]
    (let [extracted-data (ref [])]
      (process-pcap-file-with-extraction-fn 
        file-name
        #(dosync (alter extracted-data conj %))
        format-fn)
      @extracted-data))

(defn extract-nested-maps-from-pcap-file
  "Convenience function to extract the data from a pcap file in nested map format.
   Please note that all data will be stored in memory.
   So this is not suited for large amounts of data.
   Returns a vector that contains the extracted maps."
  [file-name]
  (extract-data-from-pcap-file file-name pcap-packet-to-nested-maps))

(defn extract-maps-from-pcap-file
  "Convenience function to extract the data from a pcap file in flat map format.
   Please note that all data will be stored in memory.
   So this is not suited for large amounts of data.
   Returns a vector that contains the extracted maps."
  [file-name]
  (extract-data-from-pcap-file file-name pcap-packet-to-map))

(defn extract-beans-from-pcap-file
  "Convenience function to extract the data from a pcap file in bean format.
   Please note that all data will be stored in memory.
   So this is not suited for large amounts of data.
   Returns a vector that contains the extracted maps."
  [file-name]
  (extract-data-from-pcap-file file-name pcap-packet-to-bean))
