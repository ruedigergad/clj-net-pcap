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
  ([^ByteBuffer buf]
    (doto (ByteBuffer/allocateDirect (.remaining buf))
      (.put buf)
      (.flip)))
  ([^ByteBuffer buf ^PcapHeader ph]
    (doto (ByteBuffer/allocate (+ (.remaining buf) 20))
      (.putInt (.caplen ph))
      (.putInt (.wirelen ph))
      (.putLong (.hdr_sec ph))
      (.putInt (.hdr_usec ph))
      (.put ^ByteBuffer buf)
      (.flip))))

(defn create-buffer-record
  [^ByteBuffer buf ^PcapHeader ph]
  (BufferRecord.
    (.caplen ph)
    (.wirelen ph)
    (.hdr_sec ph)
    (.hdr_usec ph)
    (deep-copy buf)))

(defn peer-packet
  [^BufferRecord bufrec]
  (let [^ByteBuffer buf (:buf bufrec)
        ^PcapHeader ph (PcapHeader. (:cl bufrec) (:wl bufrec) (:s bufrec) (:us bufrec))
        ^PcapPacket pkt (doto (PcapPacket. JMemory$Type/POINTER)
                          (.peerHeaderAndData ph buf))]
    pkt))

(defn scan-packet
  [^PcapPacket pkt]
  (doto pkt (.scan (.value (PcapDLT/EN10MB)))))

(defn create-and-start-cljnetpcap
  "Convenience function for creating and starting packet capturing.
   forwarder-fn will be called for each captured packet.
   Capturing can be influenced via the optional device and filter-expression arguments.
   By default the 'any' device is used for capturing with no filter being applied.
   Please note that the returned handle should be stored as it is needed for stopping the capture."
  [pcap forwarder-fn filter-expr emit-raw-data force-put]
    (let [running (ref true)
          buffer-drop-counter (Counter.)
          buffer-queued-counter (Counter.)
          buffer-queue (ArrayBlockingQueue. *queue-size*)
          out-drop-counter (Counter.)
          out-queued-counter (Counter.)
          out-queue (ArrayBlockingQueue. *queue-size*)
          handler-fn (fn [ph buf _]
                       (if (not (nil? buf))
                          (if emit-raw-data
                            (if force-put
                              (.put out-queue (deep-copy buf ph))
                              (if (< (.size out-queue) (- *queue-size* 1))
                                (if (.offer out-queue (deep-copy buf ph))
                                  (.inc out-queued-counter)
                                  (.inc out-drop-counter))
                                (.inc out-drop-counter)))
                            (if force-put
                              (.put out-queue (create-buffer-record buf ph))
                              (if (< (.size buffer-queue) (- *queue-size* 1))
                                (if (.offer buffer-queue (create-buffer-record buf ph))
                                  (.inc buffer-queued-counter)
                                  (.inc buffer-drop-counter))
                                (.inc buffer-drop-counter))))))
          scanner-drop-counter (Counter.)
          scanner-queued-counter (Counter.)
          scanner-queue (ArrayBlockingQueue. *queue-size*)
          buffer-processor (fn [] 
                             (try
                               (let [bufrec (.take buffer-queue)]
                                 (if force-put
                                   (.put scanner-queue (peer-packet bufrec))
                                   (if (< (.size scanner-queue) (- *queue-size* 1))
                                     (if (.offer scanner-queue (peer-packet bufrec))
                                       (.inc scanner-queued-counter)
                                       (.inc scanner-drop-counter))
                                     (.inc scanner-drop-counter))))
                               (catch Exception e
                                 (if @running
                                   (.printStackTrace e)))))
          buffer-processor-thread (doto 
                                    (InfiniteLoop. buffer-processor)
                                    (.setName "ByteBufferProcessor")
                                    (.setDaemon true)
                                    (.start))
          scanner (fn []
                    (try
                      (let [^PcapPacket pkt (.take scanner-queue)]
                        (if force-put
                          (.put out-queue (scan-packet pkt))
                          (if (< (.size out-queue) (- *queue-size* 1))
                            (if (.offer out-queue (scan-packet pkt))
                              (.inc out-queued-counter)
                              (.inc out-drop-counter))
                            (.inc out-drop-counter))))
                      (catch Exception e
                        (if @running
                          (.printStackTrace e)))))
          scanner-thread (doto
                           (InfiniteLoop. scanner)
                           (.setName "PackerScanner")
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
                                   "buf_qsize,buf_qd,buf_drop,buf_rqd,buf_rdrop, ,"
                                   "sc_qsize,sc_qd,sc_drop,sc_rqd,sc_rdrop, ,"
                                   "out_qsize,out_qd,out_drop,out_rqd,out_rdrop, ,"
                                   "failed,rfailed"))
                            (header-output-counter (fn [_] 0)))
                          (let [pcap-stats (stat-fn)
                                recv (pcap-stats "recv")
                                pdrop (pcap-stats "drop")
                                ifdrop (pcap-stats "ifdrop")
                                buf-qd (.value buffer-queued-counter)
                                buf-drop (.value buffer-drop-counter)
                                sc-qd (.value scanner-queued-counter)
                                sc-drop (.value scanner-drop-counter)
                                out-qd (.value out-queued-counter)
                                out-drop (.value out-drop-counter)
                                failed (.value failed-packet-counter)]
                            (print-err-ln
                              (reduce
                                #(str %1 "," %2)
                                [recv pdrop ifdrop (delta-cntr :recv recv) (delta-cntr :drop pdrop) (delta-cntr :ifdrop ifdrop) " "
                                 (.size buffer-queue) buf-qd buf-drop (delta-cntr :buf-qd buf-qd) (delta-cntr :buf-drop buf-drop) " "
                                 (.size scanner-queue) sc-qd sc-drop (delta-cntr :sc-qd sc-qd) (delta-cntr :sc-drop sc-drop) " "
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
                    (dosync (ref-set running false))
                    (.stop buffer-processor-thread)
                    (.stop scanner-thread)
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
            :default (throw (RuntimeException. (str "Unsupported operation: " k))))))))

(defn create-and-start-online-cljnetpcap
  ([forwarder-fn]
    (create-and-start-online-cljnetpcap forwarder-fn any))
  ([forwarder-fn device]
    (create-and-start-online-cljnetpcap forwarder-fn device ""))
  ([forwarder-fn device filter-expr]
    (create-and-start-online-cljnetpcap forwarder-fn device filter-expr false))
  ([forwarder-fn device filter-expr emit-raw-data]
    (let [pcap (create-and-activate-online-pcap device)]
      (create-and-start-cljnetpcap pcap forwarder-fn filter-expr emit-raw-data false))))

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
    (let [pcap (create-offline-pcap file-name)
          clj-net-pcap (create-and-start-cljnetpcap pcap handler-fn "" false false)]
      (sleep 1000)
      (stop-cljnetpcap clj-net-pcap))))
;      (pcap :start packet-handler))))

(defn process-pcap-file-with-extraction-fn
  "Convenience function to read a pcap file and process the packets in map format."
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

