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
    :doc "Convenience functions for easing the implementation of a working
          sniffer. Please see the simple data flow diagram in the documentation
          for more details about the data flow and interaction."}
  clj-net-pcap.sniffer
  (:use clj-net-pcap.pcap)
  (:import (clj_net_pcap InfiniteLoop)
           (java.util ArrayList)
           (java.util.concurrent BlockingQueue)
           (org.jnetpcap Pcap)
           (org.jnetpcap.packet PcapPacket PcapPacketHandler)))

(def ^:dynamic *forwarder-bulk-size* 100)

(defrecord Packet 
  ^{:doc "Holds a PcapPacket and the optional user data. 
          This is not intended to be created directly 
          but via the create-packet function."}
   [pcap-packet user-data])

(defn create-packet 
  "Convenience function for creating a Packet instance. It creates a deep copy
   of the PcapPacket instance passed as parameter.
   Note: the current implementation clones the optional user data if this is 
   passed (using Object.clone()). This may affect the performance negatively." 
;;; Need to use type hints here as PcapPackets constructor/deep-copy mechanism 
;;; seems not to work otherwise.
  ([^PcapPacket pcap-packet]
    (create-packet pcap-packet nil))
  ([^PcapPacket pcap-packet ^java.lang.Object user-data]
    (Packet. (PcapPacket. pcap-packet) 
             user-data)))

(defn clone-packet
  [^PcapPacket p]
  (PcapPacket. p))

(defn create-and-start-sniffer
  "Creates a thread in which Pcap.loop() is called with Pcap/LOOP_INFINITE set.
   Each received packet is passed to the supplied handler-fn. 
   handler-fn needs to be a function accepting two parameters from which the
   first is the received PcapPacket and the second is the user-data passed to
   create-and-start-sniffer that got forwarded via the Pcap sniffing loop.
   If no user data is passed nil is used as user data.
   Please note that the sniffer must be explicitly stopped using the 
   stop-sniffer function. Stopping the sniffer also takes care of closing pcap."
  ([pcap handler-fn]
    (create-and-start-sniffer pcap handler-fn nil))
  ([^Pcap pcap handler-fn ^Object user-data]
    (let [packet-handler (proxy [PcapPacketHandler] []
                           (nextPacket [^PcapPacket p ^Object u] (handler-fn p u)))
          run-fn (fn [] 
                   (.loop pcap Pcap/LOOP_INFINITE packet-handler user-data)) 
          sniffer-thread (doto (Thread. run-fn) (.start))]
      (fn [k]
        (cond
          (= k :stop) (do 
                        (.breakloop pcap)
               ;;; The jNetPcap capture loop may still be active and process
               ;;; at least one packet even after calling Pcap.breakloop().
               ;;; To force the termination of the loop we inject a single dummy
               ;;; packet. To ensure this packet is not filtered by some 
               ;;; previously set filter the filter is explicitly set to accept
               ;;; all packets. See also the jNetPcap docs for more information
               ;;; about the behavior of Pcap.breakloop().
                        (create-and-set-filter pcap "")
                        (.inject pcap (byte-array 1 (byte 0)))
                        (.join sniffer-thread)
                        (.close pcap)))))))

(defn stop-sniffer
  "Convenience function for stopping a sniffer that has been created with 
   create-and-start-sniffer."
  [sniffer]
  (sniffer :stop))

(defn create-and-start-forwarder
  "Creates a thread in which the actual processing of the received packets is
   supposed to happen. 
   This function accepts a queue that is an instance of 
   java.util.concurrent.BlockingQueue and executes forwarder-fn for each packet
   taken from the queue passing the packet instance to forwarder-fn.
   When no packets are int the queue the execution of forwarder-fn blocks until
   new packets are available for being processed."
  [^BlockingQueue queue forwarder-fn]
  (let [running (ref true)
        ^ArrayList tmp-list (ArrayList. *forwarder-bulk-size*)
        run-fn (fn [] (try
                        (while @running
                          (.drainTo queue tmp-list *forwarder-bulk-size*)
                          (doseq [^PcapPacket packet tmp-list]
                            (if packet
                              (forwarder-fn packet)))
                          (.clear tmp-list))
                        (catch Exception e
                        ;;; Only print the exception if we still should be running. 
                        ;;; If we get this exception when @running is already
                        ;;; false then we ignore it.
                          (if @running 
                            (throw e)))))
        forwarder-thread (doto (Thread. run-fn) (.setDaemon true) (.start))]
;        run-fn (fn [] (try
;                        (.drainTo queue tmp-list *forwarder-bulk-size*)
;                        (doseq [^PcapPacket packet tmp-list]
;                          (if packet
;                            (forwarder-fn packet)))
;                        (.clear tmp-list)
;                        (catch Exception e
                        ;;; Only print the exception if we still should be running. 
                        ;;; If we get this exception when @running is already
                        ;;; false then we ignore it.
;                          (if @running
;                            (println "Caugh exception in forwarder run-fn:" e)))))
;        forwarder-thread (doto (InfiniteLoop. run-fn) (.setDaemon true) (.start))
    (fn [k]
      (cond
        (= k :stop) (do
                      (dosync (ref-set running false))
                      (.interrupt forwarder-thread)
                      (.join forwarder-thread))))))

(defn stop-forwarder
  "Stops the given forwarder."
  [forwarder]
  (forwarder :stop))

