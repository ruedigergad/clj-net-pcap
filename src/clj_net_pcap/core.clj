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
  (:import (clj_net_pcap Counter JBufferWrapper PcapPacketWrapper ProcessingLoop)
           (java.nio BufferUnderflowException ByteBuffer)
           (java.util ArrayList)
           (java.util.concurrent ArrayBlockingQueue)
           (org.jnetpcap Pcap PcapDLT PcapHeader)
           (org.jnetpcap.nio JBuffer JMemory JMemory$Type)
           (org.jnetpcap.packet PcapPacket PcapPacketHandler)))


(def ^:dynamic *emit-raw-data* false)
(def ^:dynamic *queue-size* 100000)


(def trace-level 1)


(defrecord BufferRecord
  [s us cl wl buf])

(defn deep-copy
  "Creates a deep-copy of the supplied data.
   We differentiate two cases:
   When only a ByteBuffer is supplied the content is copied to a directly allocated ByteBuffer.
   This copy is primarily intended for being directly peered with a PcapPacket instance.
   When a ByteBuffer and a PcapHeader is supplied the field values of the PcapHeader
   are prepended to the deep copy of the ByteBuffer.
   This is intended for being transferred as byte array."
  ([^ByteBuffer buf]
    (doto (ByteBuffer/allocateDirect (.remaining buf))
      (.put buf)
      (.flip)))
  ([^ByteBuffer buf ^PcapHeader ph]
    (doto (ByteBuffer/allocate (+ (.remaining buf) 16))
      (.putInt (int (.hdr_sec ph)))
      (.putInt (.hdr_usec ph))
      (.putInt (.caplen ph))
      (.putInt (.wirelen ph))
      (.put buf)
      (.flip))))

(defn create-buffer-record
  "Create a BufferRecord.
   The BufferRecord contains the values of the PcapHeader and a directly allocated
   deep-copy of the ByteBuffer."
  [^ByteBuffer buf ^PcapHeader ph]
  (BufferRecord.
    (.hdr_sec ph)
    (.hdr_usec ph)
    (.caplen ph)
    (.wirelen ph)
    (deep-copy buf)))

(defn peer-packet
  "Create a new PcapPacket instance and fill/peer it with the data from the supplied BufferRecord."
  [^BufferRecord bufrec]
  (let [^ByteBuffer buf (:buf bufrec)
        ^PcapHeader ph (PcapHeader. (:cl bufrec) (:wl bufrec) (:s bufrec) (:us bufrec))
        ^PcapPacket pkt (doto (PcapPacket. JMemory$Type/POINTER)
                          (.peerHeaderAndData ph buf))]
    pkt))

(defn scan-packet
  "Scan the supplied packet and return it."
  [^PcapPacket pkt]
  (doto pkt (.scan (.value (PcapDLT/EN10MB)))))

(defmacro enqueue-data
  [queue op force-put queued-cntr dropped-cntr]
  (cond
    (>= trace-level 1) `(if ~force-put
                          (.put ~queue ~op)
                          (if (< (.size ~queue) *queue-size*)
                            (if (.offer ~queue ~op)
                              (.inc ~queued-cntr)
                              (.inc ~dropped-cntr))
                            (.inc ~dropped-cntr)))
    :default `(if ~force-put
                (.put ~queue ~op)
                (if (< (.size ~queue) *queue-size*)
                  (.offer ~queue ~op)))))

(defn create-raw-handler
  ""
  [^ArrayBlockingQueue out-queue ^Counter out-queued-counter ^Counter out-drop-counter force-put running]
  (fn
    ([]
      (fn [ph buf _]
        (if (not (nil? buf))
          (enqueue-data
            out-queue (deep-copy buf ph) force-put
            out-queued-counter out-drop-counter))))
    ([k]
      (condp = k
        :stats {"out-queued" (.value out-queued-counter) "out-dropped" (.value out-drop-counter)}
        nil))))

(defn create-packet-processing-handler
  ""
  [^ArrayBlockingQueue out-queue ^Counter out-queued-counter ^Counter out-drop-counter force-put running]
  (let [buffer-queue (ArrayBlockingQueue. *queue-size*)
        buffer-drop-counter (Counter.) buffer-queued-counter (Counter.)
        failed-counter (Counter.)
        scanner-queue (ArrayBlockingQueue. *queue-size*)
        scanner-drop-counter (Counter.) scanner-queued-counter (Counter.)
        buffer-processor #(try (let [bufrec (.take buffer-queue)]
                                 (enqueue-data
                                   scanner-queue (peer-packet bufrec) force-put
                                   scanner-queued-counter scanner-drop-counter))
                            (catch Exception e
                              (when @running
                                (.inc failed-counter)
                                (.printStackTrace e))))
        buffer-processor-thread (doto (ProcessingLoop. buffer-processor)
                                    (.setName "ByteBufferProcessor") (.setDaemon true) (.start))
        scanner #(try (let [^PcapPacket pkt (.take scanner-queue)]
                        (enqueue-data
                          out-queue (scan-packet pkt) force-put
                          out-queued-counter out-drop-counter))
                    (catch Exception e
                      (when @running
                        (.inc failed-counter)
                        (.printStackTrace e))))
        scanner-thread (doto (ProcessingLoop. scanner)
                           (.setName "PacketScanner") (.setDaemon true) (.start))]
    (fn
      ([]
        (fn [ph buf _]
          (if (not (nil? buf))
            (enqueue-data buffer-queue (create-buffer-record buf ph) force-put
                          buffer-queued-counter buffer-drop-counter))))
      ([k]
        (condp = k
          :stats {"buffer-queued" (.value buffer-queued-counter) "buffer-dropped" (.value buffer-drop-counter)
                  "scanner-queued" (.value scanner-queued-counter) "scanner-dropped" (.value scanner-drop-counter)
                  "out-queued" (.value out-queued-counter) "out-dropped" (.value out-drop-counter)
                  "handler-failed" (.value failed-counter)}
          :stop (do
                  (.stop ~'buffer-processor-thread)
                  (.stop ~'scanner-thread))
          :wait-for-completed (do
                                (while (or (> (.size buffer-queue) 0) (> (.size scanner-queue) 0))
                                  (sleep 100))))))))

(defn set-up-and-start-cljnetpcap
  "Takes a pcap instance, sets up the capture pipe line, and starts the capturing and processing.
   This is not intended to be used directly.
   It is recommended to use: create-and-start-online-cljnetpcap or process-pcap-file"
  [pcap forwarder-fn filter-expr force-put]
  (let [running (ref true)
        out-queue (ArrayBlockingQueue. *queue-size*)
        out-drop-counter (Counter.) out-queued-counter (Counter.)
        emit-raw-data *emit-raw-data*
        handler (if emit-raw-data
                  (create-raw-handler out-queue out-queued-counter out-drop-counter force-put running)
                  (create-packet-processing-handler out-queue out-queued-counter out-drop-counter force-put running))
        filter-expressions (ref [])
        _ (if (and (not (nil? filter-expr)) (not= "" filter-expr))
            (dosync (alter filter-expressions conj filter-expr)))
        _ (create-and-set-filter pcap filter-expr)
        failed-packet-counter (Counter.)
        forwarder (create-and-start-forwarder out-queue
                    #(try (forwarder-fn %)
                       (catch Exception e
                         (.inc failed-packet-counter))))
        sniffer (create-and-start-sniffer pcap (handler))
        stats-fn (create-stats-fn pcap)
        ]
    (fn 
      ([k]
        (condp = k
          :stats (merge (stats-fn) (handler :stats) {"forwarder-failed" (.value failed-packet-counter)})
          :stop (do
                  (dosync (ref-set running false))
                  (stop-sniffer sniffer)
                  (stop-forwarder forwarder))
          :get-filters @filter-expressions
          :remove-last-filter (do
                                (dosync (alter filter-expressions pop))
                                (create-and-set-filter pcap (join " " @filter-expressions)))
          :remove-all-filters (do
                                (dosync (alter filter-expressions (fn [_] [])))
                                (create-and-set-filter pcap (join " " @filter-expressions)))
          :wait-for-completed (do
                                (handler :wait-for-completed)
                                (while (or
                                       (> (.size out-queue) 0))
                                  (sleep 100))
                                ;;; TODO: 
                                ;;; Right now, we give it a little time to process the last data even when the queues are empty.
                                ;;; We should actually use other means to indicate that the entire processing has finished.
                                (sleep 100))
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
          :default (throw (RuntimeException. (str "Unsupported operation: " k " Args: " arg)))))
      ([k arg1 arg2]
        (condp = k
          :replace-filter (when (some #(= arg1 %) @filter-expressions)
                            (dosync
                              (alter filter-expressions #(replace {arg1 arg2} %)))
                            (create-and-set-filter pcap (join " " @filter-expressions)))
          :default (throw (RuntimeException. (str "Unsupported operation: " k " Args: " [arg1 arg2]))))))))

(defn create-and-start-online-cljnetpcap
  "Convenience function for performing live online capturing.
   forwarder-fn will be called for each captured packet.
   Capturing can be influenced via the optional device and filter-expression arguments.
   By default the 'any' device is used for capturing with no filter being applied.
   Please note that the returned handle should be stored as it is needed for stopping the capture."
  ([forwarder-fn]
    (create-and-start-online-cljnetpcap forwarder-fn any))
  ([forwarder-fn device]
    (create-and-start-online-cljnetpcap forwarder-fn device ""))
  ([forwarder-fn device filter-expr]
    (let [pcap (create-and-activate-online-pcap device)]
      (set-up-and-start-cljnetpcap pcap forwarder-fn filter-expr false))))

(defn cljnetpcap-stats
  "Given a handle as returned by, e.g., create-and-start-online-cljnetpcap or process-pcap-file,
   this function emits a map with statistical data about the capture process."
  [cljnetpcap] 
  (cljnetpcap :stats))

(defn stop-cljnetpcap
  "Stops a running capture. Argument is the handle as returned, e.g.,
   by create-and-start-online-cljnetpcap or process-pcap-file."
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

(defn remove-all-filters
  "Removes all filter expressions."
  [cljnetpcap]
  (cljnetpcap :remove-all-filters))

(defn remove-filter
  "Remove the matching filter."
  [cljnetpcap filter-expr]
  (cljnetpcap :remove-filter filter-expr))

(defn replace-filter
  "Replace old-filter expression with new-filter expression."
  [cljnetpcap old-filter new-filter]
  (cljnetpcap :replace-filter old-filter new-filter))

(defn process-pcap-file
  "Convenience function to process data stored in pcap files.
   Arguments are the file-name of the pcap file, the handler-fn that is executed for each read packet, and optional user data.
   handler-fn takes two arguments, the first is the org.jnetpcap.packet.PcapPacket instance, the second is the user data.
   By default nil is used as user data."
  ([file-name handler-fn]
    (process-pcap-file file-name handler-fn nil))
  ([file-name handler-fn user-data]
    (let [pcap (create-offline-pcap file-name)
          clj-net-pcap (set-up-and-start-cljnetpcap pcap handler-fn "" true)]
      (clj-net-pcap :wait-for-completed)
      (stop-cljnetpcap clj-net-pcap))))


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
      (process-pcap-file
        file-name
        #(dosync (alter extracted-data conj (format-fn %))))
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
   Returns a vector that contains the extracted beans."
  [file-name]
  (extract-data-from-pcap-file file-name pcap-packet-to-bean))

(defn extract-byte-arrays-from-pcap-file
  "Convenience function to extract the raw data from a pcap file as byte arrays.
   Please note that all data will be stored in memory.
   So this is not suited for large amounts of data.
   Returns a vector that contains the extracted raw-data."
  [file-name]
  (binding [*emit-raw-data* true]
    (extract-data-from-pcap-file file-name (fn [^ByteBuffer b] (.array b)))))
