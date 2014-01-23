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
  (:import (clj_net_pcap Counter InfiniteLoop JBufferWrapper PcapPacketWrapper)
           (java.nio ByteBuffer)
           (java.util ArrayList)
           (java.util.concurrent ArrayBlockingQueue LinkedBlockingQueue)
           (org.jnetpcap Pcap PcapDLT PcapHeader)
           (org.jnetpcap.nio JBuffer JMemory JMemory$Type)
           (org.jnetpcap.packet PcapPacket PcapPacketHandler)))


(def ^:dynamic *copy-queue-size* 200000)
(def ^:dynamic *packet-queue-size* 100000)

(defrecord BufferRecord
  [cl wl s us buf])

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
    (create-and-start-cljnetpcap forwarder-fn device filter-expr false))
  ([forwarder-fn device filter-expr emit-raw-data]
    (let [running (ref true)
          copy-drop-counter (Counter.)
          copy-queued-counter (Counter.)
          copy-queue (ArrayBlockingQueue. *copy-queue-size*)
          handler-fn (fn [^PcapHeader ph ^ByteBuffer buf ^Object _]
                       (if (and 
                             (< (.size copy-queue) (- *copy-queue-size* 1))
                             (not (nil? buf)))
                         (if (.offer copy-queue
                               (BufferRecord. (.caplen ph) (.wirelen ph) (.hdr_sec ph) (.hdr_usec ph) buf))
                           (.inc copy-queued-counter)
                           (.inc copy-drop-counter))
                         (.inc copy-drop-counter)))
          out-drop-counter (Counter.)
          out-queued-counter (Counter.)
          out-queue (ArrayBlockingQueue. *packet-queue-size*)
          buffer-drop-counter (Counter.)
          buffer-queued-counter (Counter.)
          buffer-queue (ArrayBlockingQueue. *packet-queue-size*)
          copy-fn (fn []
                    (try
                      (let [^BufferRecord bufrec (.take copy-queue)
                            ^ByteBuffer buf (:buf bufrec)]
                        (if (and
                              (not (nil? bufrec))
                              (> (:cl bufrec) 0)
                              (> (:wl bufrec) 0))
                          (if (not emit-raw-data)
                            (if (< (.size buffer-queue) (- *packet-queue-size* 1))
                              (let [
                                    bb-copy (doto (ByteBuffer/allocate (+ (.remaining buf) 20))
                                              (.put buf)
                                              (.flip))
                                    buf-copy (BufferRecord.
                                               (:cl bufrec)
                                               (:wl bufrec)
                                               (:s bufrec)
                                               (:us bufrec)
                                               bb-copy)]
                                (if (.offer buffer-queue buf-copy)
                                  (.inc buffer-queued-counter)
                                  (.inc buffer-drop-counter)))
                              (.inc buffer-drop-counter))
                            (if (< (.size out-queue) (- *packet-queue-size* 1))
                              (let [data (doto (ByteBuffer/allocate (+ (.remaining buf) 20))
                                           (.putInt (:cl bufrec))
                                           (.putInt (:wl bufrec))
                                           (.putLong (:s bufrec))
                                           (.putInt (:us bufrec))
                                           (.put ^ByteBuffer (:buf bufrec))
                                           (.flip))]
                                (if (.offer out-queue data)
                                  (.inc out-queued-counter)
                                  (.inc out-drop-counter)))
                              (.inc out-drop-counter)))))
                      (catch Exception e
                        (if @running
                          (.printStackTrace e)))))
          copy-thread (doto 
                        (InfiniteLoop. copy-fn)
                          (.setName "CopyThread")
                          (.setDaemon true)
                          (.start))
          packet-scanner-drop-counter (Counter.)
          packet-scanner-queued-counter (Counter.)
          packet-scanner-queue (ArrayBlockingQueue. *packet-queue-size*)
          buffer-processor (fn [] 
                                  (try
                                    (if (< (.size packet-scanner-queue) (- *packet-queue-size* 1))
                                      (let [bufrec (.take buffer-queue)]
                                        (if (and
                                              (not (nil? bufrec))
                                              (> (:cl bufrec) 0)
                                              (> (:wl bufrec) 0))
                                          (let [^ByteBuffer buf (:buf bufrec)
                                                ^PcapHeader ph (PcapHeader. (:cl bufrec) (:wl bufrec) (:s bufrec) (:us bufrec))
                                                ^JBuffer pkt-buf (JBuffer. buf)
                                                ^PcapPacket pkt (doto (PcapPacket. JMemory$Type/POINTER)
                                                                  (.peer ph pkt-buf))]
                                            (if (.offer packet-scanner-queue pkt)
                                              (.inc packet-scanner-queued-counter)
                                              (.inc packet-scanner-drop-counter)))))
                                        (.inc packet-scanner-drop-counter))
                                    (catch Exception e
                                      (if @running
                                        (.printStackTrace e)))))
          buffer-processor-thread (doto 
                                         (InfiniteLoop. buffer-processor)
                                         (.setName "ByteBufferProcessor")
                                         (.setDaemon true)
                                         (.start))
          packet-cloner-drop-counter (Counter.)
          packet-cloner-queued-counter (Counter.)
          packet-cloner-queue (ArrayBlockingQueue. *packet-queue-size*)
          packet-scanner (fn []
                          (try
                            (let [^PcapPacket tmp-pkt (.take packet-scanner-queue)]
                              (if (< (.size packet-cloner-queue) (- *packet-queue-size* 1))
                                (let [_ (.scan tmp-pkt (.value (PcapDLT/EN10MB)))]
                                  (if (.offer out-queue tmp-pkt)
                                            (.inc out-queued-counter)
                                            (.inc out-drop-counter)))
                                (.inc out-drop-counter)))
                             (catch Exception e
                                      (if @running
                                        (.printStackTrace e)))))
          packet-scanner-thread (doto 
                                 (InfiniteLoop. packet-scanner)
                                 (.setName "PackerScanner")
                                 (.setDaemon true)
                                 (.start))
;          packet-cloner (fn []
;                          (try
;                            (let [^PcapPacket tmp-pkt (.take packet-cloner-queue)]
;                              (if (< (.size out-queue) (- *packet-queue-size* 1))
;                                (let [^PcapPacket pkt (PcapPacket. tmp-pkt)]
;                                  (if (.offer out-queue pkt)
;                                            (.inc out-queued-counter)
;                                            (.inc out-drop-counter)))
;                                (.inc out-drop-counter)))
;                             (catch Exception e
;                                      (if @running
;                                        (.printStackTrace e)))))
;          packet-cloner-thread (doto 
;                                 (InfiniteLoop. packet-cloner)
;                                 (.setName "PackerCloner")
;                                 (.setDaemon true)
;                                 (.start))
          pcap (create-and-activate-pcap device)
          filter-expressions (ref [])
          _ (if (and 
                  filter-expr 
                  (not= "" filter-expr))
              (dosync (alter filter-expressions conj filter-expr)))
          _ (create-and-set-filter pcap filter-expr)
          forwarder (create-and-start-forwarder out-queue forwarder-fn)
          sniffer (create-and-start-sniffer pcap handler-fn)
          stat-fn (create-stat-fn pcap)
          stat-print-fn #(print-err-ln
                           (str (stat-fn)
                                ",cpy_qsize," (.size copy-queue)
                                ",cpy_queued," (.value copy-queued-counter)
                                ",cpy_droped," (.value copy-drop-counter)
                                ",buf_qsize," (.size buffer-queue)
                                ",buf_queued," (.value buffer-queued-counter)
                                ",buf_droped," (.value buffer-drop-counter)
                                ",scanner_qsize," (.size packet-scanner-queue)
                                ",scanner_queued," (.value packet-scanner-queued-counter)
                                ",scanner_droped," (.value packet-scanner-drop-counter)
;                                ",cloner_qsize," (.size packet-cloner-queue)
;                                ",cloner_queued," (.value packet-cloner-queued-counter)
;                                ",cloner_droped," (.value packet-cloner-drop-counter)
                                ",out_qsize," (.size out-queue)
                                ",out_queued," (.value out-queued-counter)
                                ",out_droped," (.value out-drop-counter)))]
      (fn 
        ([k]
          (condp = k
            :stat (stat-print-fn)
            :stop (do
                    (dosync (ref-set running false))
                    (.stop copy-thread)
                    (.stop buffer-processor-thread)
                    (.stop packet-scanner-thread)
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
