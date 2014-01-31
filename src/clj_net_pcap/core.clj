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


(def ^:dynamic *queue-size* 100000)

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
  ([^PcapHeader ph ^ByteBuffer buf]
    (doto (ByteBuffer/allocate (+ (.remaining buf) 20))
      (.putInt (.caplen ph))
      (.putInt (.wirelen ph))
      (.putLong (.hdr_sec ph))
      (.putInt (.hdr_usec ph))
      (.put ^ByteBuffer buf)
      (.flip))))

(defn create-buffer-record
  "Create a BufferRecord.
   The BufferRecord contains the values of the PcapHeader and a directly allocated
   deep-copy of the ByteBuffer."
  [^PcapHeader ph ^ByteBuffer buf]
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

(defn set-up-and-start-cljnetpcap
  "Takes a pcap instance, sets up the capture pipe line, and starts the capturing and processing.
   This is not intended to be used directly.
   It is recommended to use: create-and-start-online-cljnetpcap or process-pcap-file"
  [pcap forwarder-fn filter-expr emit-raw-data force-put]
    (let [running (ref true)
          scanner-drop-counter (Counter.)
          scanner-queued-counter (Counter.)
          scanner-queue (ArrayBlockingQueue. *queue-size*)
          copy-drop-counter (Counter.)
          copy-queued-counter (Counter.)
          copy-queue (ArrayBlockingQueue. *queue-size*)
          out-drop-counter (Counter.)
          out-queued-counter (Counter.)
          out-queue (ArrayBlockingQueue. *queue-size*)
          handler-fn (fn [^PcapHeader ph ^ByteBuffer buf _]
                       (if (not (nil? buf))
                          (if emit-raw-data
                            (if force-put
                              (.put out-queue (deep-copy ph buf))
                              (if (< (.size out-queue) *queue-size*)
                                (if (.offer out-queue (deep-copy ph buf))
                                  (.inc out-queued-counter)
                                  (.inc out-drop-counter))
                                (.inc out-drop-counter)))
                            (if force-put
                              (.put scanner-queue (PcapPacket. ph buf))
                              (if (< (.size scanner-queue) *queue-size*)
                                (if (.offer scanner-queue (PcapPacket. ph buf))
                                  (.inc scanner-queued-counter)
                                  (.inc scanner-drop-counter))
                                (.inc scanner-drop-counter))))))
          scanner (fn []
                    (try
                      (let [^PcapPacket pkt (.take scanner-queue)]
                        (if force-put
                          (.put copy-queue (scan-packet pkt))
                          (if (< (.size copy-queue) *queue-size*)
                            (if (.offer copy-queue (scan-packet pkt))
                              (.inc copy-queued-counter)
                              (.inc copy-drop-counter))
                            (.inc copy-drop-counter))))
                      (catch Exception e
                        (if @running
                          (.printStackTrace e)))))
          scanner-thread (doto
                           (InfiniteLoop. scanner)
                           (.setName "PacketScanner")
                           (.setDaemon true)
                           (.start))
          copy-fn (fn [] 
                    (try
                      (let [^PcapPacket pkt (.take copy-queue)]
                        (if force-put
                          (.put out-queue (PcapPacket. pkt))
                          (if (< (.size out-queue) (- *queue-size* 1))
                            (if (.offer out-queue (PcapPacket. pkt))
                              (.inc out-queued-counter)
                              (.inc out-drop-counter))
                            (.inc out-drop-counter))))
                      (catch Exception e
                        (if @running
                          (.printStackTrace e)))))
          copy-thread (doto 
                        (InfiniteLoop. copy-fn)
                        (.setName "CopyThread")
                        (.setDaemon true)
                        (.start))
          filter-expressions (ref [])
          _ (if (and 
                  filter-expr 
                  (not= "" filter-expr))
              (dosync (alter filter-expressions conj filter-expr)))
          _ (create-and-set-filter pcap filter-expr)
          failed-packet-counter (Counter.)
          forwarder (create-and-start-forwarder
                      out-queue
                      #(try
                         (forwarder-fn %)
                         (catch Exception e
                           (.inc failed-packet-counter))))
          sniffer (create-and-start-sniffer pcap handler-fn)
          stat-fn (create-stat-fn pcap)
          header-output-counter (counter)
          delta-cntr (delta-counter)
          stat-print-fn (fn []
                          (when (= (header-output-counter) 0)
                            (print-err-ln
                              (str "recv,drop,ifdrop,rrecv,rdrop,rifdrop, ,"
                                   "sc_qsize,sc_qd,sc_drop,sc_rqd,sc_rdrop, ,"
                                   "cpy_qsize,cpy_qd,cpy_drop,cpy_rqd,cpy_rdrop, ,"
                                   "out_qsize,out_qd,out_drop,out_rqd,out_rdrop, ,"
                                   "failed,rfailed"))
                            (header-output-counter (fn [_] 0)))
                          (let [pcap-stats (stat-fn)
                                recv (pcap-stats "recv") pdrop (pcap-stats "drop") ifdrop (pcap-stats "ifdrop")
                                sc-qd (.value scanner-queued-counter) sc-drop (.value scanner-drop-counter)
                                cpy-qd (.value copy-queued-counter) cpy-drop (.value copy-drop-counter)
                                out-qd (.value out-queued-counter) out-drop (.value out-drop-counter)
                                failed (.value failed-packet-counter)]
                            (print-err-ln
                              (reduce
                                #(str %1 "," %2)
                                [recv pdrop ifdrop (delta-cntr :recv recv) (delta-cntr :drop pdrop) (delta-cntr :ifdrop ifdrop) " "
                                 (.size scanner-queue) sc-qd sc-drop (delta-cntr :sc-qd sc-qd) (delta-cntr :sc-drop sc-drop) " "
                                 (.size copy-queue) cpy-qd cpy-drop (delta-cntr :cpy-qd cpy-qd) (delta-cntr :cpy-drop cpy-drop) " "
                                 (.size out-queue) out-qd out-drop (delta-cntr :out-qd out-qd) (delta-cntr :out-drop out-drop) " "
                                 failed (delta-cntr :failed failed)]))
                            (if (>= (header-output-counter) 20)
                              (header-output-counter (fn [_] 0))
                              (header-output-counter inc))))]
      (fn 
        ([k]
          (condp = k
            :stat (stat-print-fn)
            :stop (do
                    (stop-sniffer sniffer)
                    (dosync (ref-set running false))
                    (.stop scanner-thread)
                    (.stop copy-thread)
                    (stop-forwarder forwarder))
            :get-filters @filter-expressions
            :remove-last-filter (do
                                  (dosync
                                    (alter filter-expressions pop))
                                  (create-and-set-filter pcap (join " " @filter-expressions)))
            :wait-for-completed (do
                                  (while (or
                                         (> (.size scanner-queue) 0)
                                         (> (.size copy-queue) 0)
                                         (> (.size out-queue) 0))
                                    (sleep 100))
                                  ;;; FIXME: 
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
   forwarder-fn will be called for each captured packet.
   Capturing can be influenced via the optional device and filter-expression arguments.
   By default the 'any' device is used for capturing with no filter being applied.
   Please note that the returned handle should be stored as it is needed for stopping the capture."
  ([forwarder-fn]
    (create-and-start-online-cljnetpcap forwarder-fn any))
  ([forwarder-fn device]
    (create-and-start-online-cljnetpcap forwarder-fn device ""))
  ([forwarder-fn device filter-expr]
    (create-and-start-online-cljnetpcap forwarder-fn device filter-expr false))
  ([forwarder-fn device filter-expr emit-raw-data]
    (let [pcap (create-and-activate-online-pcap device)]
      (set-up-and-start-cljnetpcap pcap forwarder-fn filter-expr emit-raw-data false))))

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
   Arguments are the file-name of the pcap file, the handler-fn that is executed for each read packet, and optional user data.
   handler-fn takes two arguments, the first is the org.jnetpcap.packet.PcapPacket instance, the second is the user data.
   By default nil is used as user data."
  ([file-name handler-fn]
    (process-pcap-file file-name handler-fn nil))
  ([file-name handler-fn user-data]
    (let [pcap (create-offline-pcap file-name)
          clj-net-pcap (set-up-and-start-cljnetpcap pcap handler-fn "" false true)]
      (clj-net-pcap :wait-for-completed)
      (stop-cljnetpcap clj-net-pcap))))

(defn process-pcap-file-with-extraction-fn
  "Convenience function to read a pcap file and process the packets."
  [file-name handler-fn extraction-fn]
    (process-pcap-file 
      file-name
      (fn [p]
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

