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
           (java.nio BufferUnderflowException ByteBuffer)
           (java.util ArrayList)
           (java.util.concurrent ArrayBlockingQueue LinkedBlockingQueue)
           (org.jnetpcap Pcap PcapDLT PcapHeader)
           (org.jnetpcap.nio JBuffer JMemory JMemory$Type)
           (org.jnetpcap.packet PcapPacket PcapPacketHandler)))


(def ^:dynamic *emit-raw-data* false)
(def ^:dynamic *queue-size* 100000)


(def trace-level 1)


(defrecord BufferRecord
  [cl wl s us buf])

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
    (doto (ByteBuffer/allocate (+ (.remaining buf) 20))
      (.putInt (.hdr_usec ph))
      (.putLong (.hdr_sec ph))
      (.putInt (.caplen ph))
      (.putInt (.wirelen ph))
      (.put ^ByteBuffer buf)
      (.flip))))

(defn create-buffer-record
  "Create a BufferRecord.
   The BufferRecord contains the values of the PcapHeader and a directly allocated
   deep-copy of the ByteBuffer."
  [^ByteBuffer buf ^PcapHeader ph]
  (BufferRecord.
    (.caplen ph)
    (.wirelen ph)
    (.hdr_sec ph)
    (.hdr_usec ph)
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
  "Convenience macro for queueing data.
   This is not intended to be used directly."
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

(defn set-up-and-start-cljnetpcap
  "Takes a pcap instance, sets up the capture pipe line, and starts the capturing and processing.
   This is not intended to be used directly.
   It is recommended to use: create-and-start-online-cljnetpcap or process-pcap-file"
  [pcap fwd-1-fn fwd-2-fn filter-expr force-put]
    (let [; Simple local vars
          running (ref true)
          emit-raw-data *emit-raw-data*
          ; Queues and the associated counters
          buffer-queue (ArrayBlockingQueue. *queue-size*) buffer-drop-counter (Counter.) buffer-queued-counter (Counter.)
          scanner-queue (ArrayBlockingQueue. *queue-size*) scanner-drop-counter (Counter.) scanner-queued-counter (Counter.)
          fwd-1-queue (ArrayBlockingQueue. *queue-size*) fwd-1-drop-counter (Counter.) fwd-1-queued-counter (Counter.)
          fwd-2-queue (ArrayBlockingQueue. *queue-size*) fwd-2-drop-counter (Counter.) fwd-2-queued-counter (Counter.)
          failed-packet-counter (Counter.)
          ; Handler, processing fns, and associated threads
          handler-fn (fn [ph buf _]
                       (if (not (nil? buf))
                         (if emit-raw-data
                           (enqueue-data
                             fwd-1-queue (deep-copy buf ph) force-put
                             fwd-1-queued-counter fwd-1-drop-counter)
                           (enqueue-data buffer-queue (create-buffer-record buf ph) force-put
                                         buffer-queued-counter buffer-drop-counter))))
          buffer-processor #(try (let [bufrec (.take buffer-queue)]
                                   (enqueue-data
                                     scanner-queue (peer-packet bufrec) force-put
                                     scanner-queued-counter scanner-drop-counter))
                              (catch Exception e
                                (.inc failed-packet-counter)
                                (if @running (.printStackTrace e))))
          buffer-processor-thread (doto (InfiniteLoop. buffer-processor)
                                    (.setName "ByteBufferProcessor") (.setDaemon true) (.start))
          scanner #(try (let [^PcapPacket pkt (.take scanner-queue)]
                          (enqueue-data
                            fwd-1-queue (scan-packet pkt) force-put
                            fwd-1-queued-counter fwd-1-drop-counter))
                     (catch Exception e
                       (.inc failed-packet-counter)
                       (if @running (.printStackTrace e))))
          scanner-thread (doto (InfiniteLoop. scanner)
                           (.setName "PacketScanner") (.setDaemon true) (.start))
          fwd-1 #(try (let [obj (.take fwd-1-queue)]
                        (if (nil? fwd-2-fn)
                          (fwd-1-fn obj)
                          (enqueue-data
                            fwd-2-queue (fwd-1-fn obj) force-put
                            fwd-2-queued-counter fwd-2-drop-counter)))
                   (catch Exception e
                     (.inc failed-packet-counter)))
          fwd-1-thread (doto (InfiniteLoop. fwd-1)
                         (.setName "Forwarder_1") (.setDaemon true) (.start))
          fwd-2 #(try (let [obj (.take fwd-2-queue)]
                            (fwd-2-fn obj))
                   (catch Exception e
                     (.inc failed-packet-counter)))
          fwd-2-thread (if (not (nil? fwd-2-fn))
                         (doto (InfiniteLoop. fwd-2)
                           (.setName "Forwarder_2") (.setDaemon true) (.start)))
          ; Set up and start pcap.
          filter-expressions (ref [])
          _ (if (and (not (nil? filter-expr)) (not= "" filter-expr))
              (dosync (alter filter-expressions conj filter-expr)))
          _ (create-and-set-filter pcap filter-expr)
          sniffer (create-and-start-sniffer pcap handler-fn)
          ; Stats collection and output
          stat-fn (create-stat-fn pcap)
          header-output-counter (counter)
          delta-cntr (delta-counter)
          stat-print-fn (fn []
                          (if (= (header-output-counter) 0)
                            (print-err-ln
                              (str "r,dr,ifdr,rr,rdr,rifdr, ,"
                                   "b_q,b_qd,b_dr,b_rqd,b_rdr, ,"
                                   "s_q,s_qd,s_dr,s_rqd,s_rdr, ,"
                                   "f1_q,f1_qd,f1_dr,f1_rqd,f1_rdr, ,"
                                   "f2_q,f2_qd,f2_dr,f2_rqd,f2_rdr, ,"
                                   "fail,rfail")))
                          (let [pcap-stats (stat-fn)
                                recv (pcap-stats "recv") pdrop (pcap-stats "drop") ifdrop (pcap-stats "ifdrop")
                                buf-qd (.value buffer-queued-counter) buf-drop (.value buffer-drop-counter)
                                sc-qd (.value scanner-queued-counter) sc-drop (.value scanner-drop-counter)
                                f1-qd (.value fwd-1-queued-counter) f1-drop (.value fwd-1-drop-counter)
                                f2-qd (.value fwd-2-queued-counter) f2-drop (.value fwd-2-drop-counter)
                                failed (.value failed-packet-counter)]
                            (print-err-ln
                              (reduce #(str %1 "," %2)
                                [recv pdrop ifdrop (delta-cntr :recv recv) (delta-cntr :drop pdrop) (delta-cntr :ifdrop ifdrop) " "
                                 (.size buffer-queue) buf-qd buf-drop (delta-cntr :buf-qd buf-qd) (delta-cntr :buf-drop buf-drop) " "
                                 (.size scanner-queue) sc-qd sc-drop (delta-cntr :sc-qd sc-qd) (delta-cntr :sc-drop sc-drop) " "
                                 (.size fwd-1-queue) f1-qd f1-drop (delta-cntr :f1-qd f1-qd) (delta-cntr :f1-drop f1-drop) " "
                                 (.size fwd-2-queue) f2-qd f2-drop (delta-cntr :f2-qd f2-qd) (delta-cntr :f2-drop f2-drop) " "
                                 failed (delta-cntr :failed failed)]))
                            (if (>= (header-output-counter) 20)
                              (header-output-counter (fn [_] 0))
                              (header-output-counter inc))))]
      (fn 
        ([k]
          (condp = k
            :stat (stat-print-fn)
            :stop (do
                    (dosync (ref-set running false))
                    (.stop buffer-processor-thread)
                    (.stop scanner-thread)
                    (.stop fwd-1-thread)
                    (if (not (nil? fwd-2-thread))
                      (.stop fwd-2-thread))
                    (stop-sniffer sniffer))
            :get-filters @filter-expressions
            :remove-last-filter (do
                                  (dosync
                                    (alter filter-expressions pop))
                                  (create-and-set-filter pcap (join " " @filter-expressions)))
            :wait-for-completed (do
                                  (while (or
                                           (> (.size buffer-queue) 0)
                                           (> (.size scanner-queue) 0)
                                           (> (.size fwd-1-queue) 0)
                                           (> (.size fwd-2-queue) 0))
                                    (sleep 100))
                                  ;;; TODO: 
                                  ;;; Right now, we give it a little time to process the last data
                                  ;;; even when the queues are empty.
                                  ;;; We should actually use other means to indicate that the entire
                                  ;;; processing has finished.
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
            :default (throw (RuntimeException. (str "Unsupported operation: " k))))))))

(defn create-and-start-online-cljnetpcap
  "Convenience function for performing live online capturing.
   transformation-fn and forwarder-fn will be called for each captured packet.
   Capturing can be influenced via the optional device and filter-expression arguments.
   By default the 'any' device is used for capturing with no filter being applied.
   Please note that the returned handle should be stored as it is needed for stopping the capture."
  ([transformer-fn forwarder-fn]
    (create-and-start-online-cljnetpcap transformer-fn forwarder-fn any))
  ([transformer-fn forwarder-fn device]
    (create-and-start-online-cljnetpcap transformer-fn forwarder-fn device ""))
  ([transformer-fn forwarder-fn device filter-expr]
    (let [pcap (create-and-activate-online-pcap device)]
      (set-up-and-start-cljnetpcap pcap transformer-fn forwarder-fn filter-expr false))))

(defn print-stat-cljnetpcap
  "Given a handle as returned by, e.g., create-and-start-online-cljnetpcap or process-pcap-file,
   this prints statistical output about the capture process."
  [cljnetpcap] 
  (cljnetpcap :stat))

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

(defn remove-filter
  "Remove the matching filter."
  [cljnetpcap filter-expr]
  (cljnetpcap :remove-filter filter-expr))

(defn process-pcap-file
  "Convenience function to process data stored in pcap files.
   Arguments are the file-name of the pcap file, the transformation-fn and the handler-fn that are executed for each read packet.
   tranformation-fn takes a org.jnetpcap.packet.PcapPacket instance as single argument."
  ([file-name transformer-fn forwarder-fn]
    (let [pcap (create-offline-pcap file-name)
          clj-net-pcap (set-up-and-start-cljnetpcap pcap transformer-fn forwarder-fn "" true)]
      (clj-net-pcap :wait-for-completed)
      (stop-cljnetpcap clj-net-pcap))))

(defn process-pcap-file-with-extraction-fn
  "Convenience function to read a pcap file and process the packets."
  [file-name format-fn forwarder-fn]
    (process-pcap-file 
      file-name
      format-fn
      forwarder-fn))

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
        ; This is a pretty crude hack but it should do for now.
        (if (= "pcap-packet-to-nested-maps" (fn-name format-fn))
          format-fn
          (format-fn))
        #(dosync (alter extracted-data conj %)))
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

