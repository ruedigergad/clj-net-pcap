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
        clj-net-pcap.sniffer
        clj-assorted-utils.util)
  (:import (java.net InetAddress)
           (java.util.concurrent LinkedBlockingQueue)
           (org.jnetpcap.packet PcapPacket PcapPacketHandler)
           (org.jnetpcap.packet.format FormatUtils)
           (org.jnetpcap.protocol.lan Ethernet)
           (org.jnetpcap.protocol.network Arp Icmp Ip4 Ip6)
           (org.jnetpcap.protocol.tcpip Http Http$Request Http$Response 
                                        Tcp Tcp$Flag Tcp$Timestamp Udp)))

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
          handler-fn (fn [p u] 
                       (if-not (nil? p)
                         (.offer queue (create-packet p u))))
          sniffer (create-and-start-sniffer pcap handler-fn)
          stat-fn (create-stat-fn pcap)
          stat-print-fn #(print-err-ln "pcap-stats:" (stat-fn))]
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

(defn prettify-addr-array
  "Convenience function to print addresses as strings."
  [^Object a]
  (if (-> (.getClass a) (.isArray))
    (cond
      (= (alength a) 6) (FormatUtils/mac a)
      (= (alength a) 4) (FormatUtils/ip a)
      (= (alength a) 16) (FormatUtils/asStringIp6 a true)
      :default (FormatUtils/asString a))
    a))

(defmacro process-protocol-headers-to-map
  "Macro for processing protocol header information into a map representation.
   packet is a org.jnetpcap.packet.PcapPacket instance.
   headers contains the description about which information shall be retrieved for each protocol.

   For an example usage see parse-protocol-headers-to-map."
  [packet & headers]
  `(let [~'data-link-layer-protocols #{"Ethernet"}
         ~'network-layer-protocols #{"Ip4" "Ip6"}]
     (if 
       (not (nil? ~packet))
       (reduce into [{} 
                     ~@(map (fn [h]
                              (let [protocol-header (first h)
                                    body (rest h)]
                                `(if (.hasHeader ~packet ~protocol-header) 
                                   (let [protocol-class# (classname ~protocol-header)]
                                     {(cond
                                        (~'data-link-layer-protocols protocol-class#) "DataLinkLayer"
                                        (~'network-layer-protocols protocol-class#) "NetworkLayer"
                                        :default protocol-class#)
                                      (reduce into 
                                              [{}
                                               {"index" (.getIndex ~protocol-header)}
                                               (if
                                                 (or (~'data-link-layer-protocols protocol-class#) 
                                                     (~'network-layer-protocols protocol-class#))
                                                 {"ProtocolType" protocol-class#})
                                               ~@body    
                                               (if (.hasNextHeader ~protocol-header) 
                                                 {"next" (.getNextHeaderId ~protocol-header)})])}))))
                            headers)]))))

(defmacro src-dst-to-map
  "Write source and destination addresses into a map."
  [protocol]
  `{"source" (prettify-addr-array (.source ~protocol))
    "destination" (prettify-addr-array (.destination ~protocol))})

(defn extract-http-fields-to-map
  "Extract the given fields from an org.jnetpcap.protocol.tcpip.Http instance and store each into a map.
   fields is a vector that specifies which fields shall be extracted."
  [http fields]
  (into {}
        (map (fn [f] 
               (if (.hasField http f)
                 {(.toString f) (.fieldValue http f)}))
             fields)))

(def parse-protocol-headers-to-map
  "Function to parse the information contained in the protocol headers 
   of a org.jnetpcap.packet.PcapPacket instance into a map.

   This function is a closure over the individual protocol class instances.
   The reason for this is to minimize the overhead due to instantiating those classes.
   This is a typical design pattern when working with jNetPcap.
   Please refer to the jNetPcap documentation for more information."
  (let [eth (Ethernet.)
        arp (Arp.)
        icmp (Icmp.)
        ip4 (Ip4.)
        ip6 (Ip6.)
        tcp (Tcp.)
        tcp-timestamp (Tcp$Timestamp.)
        udp (Udp.)
        http (Http.)]
    (fn [^PcapPacket packet]
      (process-protocol-headers-to-map
        packet
        [eth 
         (src-dst-to-map eth)]
        [arp
         {"operationDescription" (.operationDescription arp)
          "targetMac" (prettify-addr-array (.tha arp))
          "targetIp" (prettify-addr-array (.tpa arp))
          "sourceMac" (prettify-addr-array (.sha arp))
          "sourceIp" (prettify-addr-array (.spa arp))}]
        [ip4
         (src-dst-to-map ip4)
         {"id" (.id ip4)
          "tos" (.tos ip4)
          "type" (.type ip4)
          "ttl" (.ttl ip4)}]
        [ip6
         (src-dst-to-map ip6)
         {"flowLabel" (.flowLabel ip6)
          "hopLimit" (.hopLimit ip6)
          "trafficClass" (.trafficClass ip6)}]
        [icmp
         {"typeDescription" (.typeDescription icmp)}]
        [tcp
         (src-dst-to-map tcp)
         {"ack" (.ack tcp)
          "seq" (.seq tcp)
          "flags" (set 
                    (map (fn [f] (.toString f))
                         (.flagsEnum tcp)))}
         (when (.hasSubHeader tcp tcp-timestamp)
           (into 
             {"tsval" (.tsval tcp-timestamp)}
             (if (.flags_ACK tcp)
               {"tsecr" (.tsecr tcp-timestamp)})))]
        [udp 
         (src-dst-to-map udp)]
        [http
         (extract-http-fields-to-map 
           http 
           [Http$Response/Content_Length
            Http$Response/Content_Type
            Http$Response/ResponseCode
            Http$Response/RequestUrl
            Http$Request/Authorization
            Http$Request/Content_Length
            Http$Request/Content_Type
            Http$Request/Referer
            Http$Request/RequestMethod
            Http$Request/RequestUrl
            Http$Request/RequestVersion])]))))

(declare stdout-byte-array-forwarder-fn)

(defn parse-pcap-header-to-map
  "Parse the information contained in the pcap header of a org.jnetpcap.packet.PcapPacket instance
   and store it into a map. The resulting map is returned."
  [^PcapPacket packet]
  (try
    (let [header (.getCaptureHeader packet)]
      {(classname header) {"timestampInNanos" (.timestampInNanos header)
                           "wirelen" (.wirelen header)}})
    (catch Exception e
      (println "Error parsing the pcap packet header!")
      (.printStackTrace e)
      (println "Packet raw data was:")
      (stdout-byte-array-forwarder-fn packet))))

(defn parse-pcap-packet
  "Convenience function to parse a org.jnetpcap.packet.PcapPacket into a map.
   The result contains the pcap header and protocol header information."
  [^PcapPacket packet]
  (try
    (reduce into [{}
                  (parse-pcap-header-to-map packet)
                  (parse-protocol-headers-to-map packet)])
    (catch Exception e
      (println "Error parsing the pcap packet!")
      (.printStackTrace e)
      (println "Packet raw data was:")
      (stdout-byte-array-forwarder-fn packet))))

(defn stdout-forwarder-fn
  "Pre-defined forwarder function which outputs information about org.jnetpcap.packet.PcapPacket to *out*.
   The information is in form of a map. The is pretty printed with pprint."
  [packet]
  (pprint (parse-pcap-packet (:pcap-packet packet))))

(defn pcap-packet-to-byte-vector
  "Convert the given org.jnetpcap.packet.PcapPacket to its byte array representation and return it as vector.
   This can be handy for debugging purposes as the resulting vector can be easily converted back into a org.jnetpcap.packet.PcapPacket instance."
  [pcap-packet]
  (let [buffer (byte-array (.getTotalSize pcap-packet) (byte 0))
        _ (.transferStateAndDataTo pcap-packet buffer)]
    (vec buffer)))

(defn stdout-byte-array-forwarder-fn
  "Print the byte vector representation of a org.jnetpcap.packet.PcapPacket as returned by pcap-packet-to-byte-vector to *out*."
  [packet]
  (let [pcap-packet (:pcap-packet packet)
        buffer-seq (pcap-packet-to-byte-vector pcap-packet)]
    (println "Packet Start (size:" (count buffer-seq) "):" buffer-seq "Packet End\n\n")))

(defn stdout-combined-forwarder-fn
  [packet]
  "Print both, the map and the byte vector representations, of a org.jnetpcap.packet.PcapPacket to *out*."
  (let [pcap-packet (:pcap-packet packet)
        buffer-seq (pcap-packet-to-byte-vector pcap-packet)]
    (pprint (parse-pcap-packet (:pcap-packet packet)))
    (println "Packet Start (size:" (count buffer-seq) "):" buffer-seq "Packet End\n\n")))

(defn process-pcap-file
  "Convenience function to process data stored in pcap files.
   Arguments are the file-name of the pcap file, the handler-fn that is executed for each read packet, and optional user data.
   handler-fn takes two arguments, the first is the org.jnetpcap.packet.PcapPacket instance, the second is the user data.
   By default nil is used as user data."
  ([file-name handler-fn]
    (process-pcap-file file-name handler-fn nil))
  ([file-name handler-fn user-data]
    (let [pcap (create-pcap-from-file file-name)
          packet-handler (proxy [PcapPacketHandler] []
                           (nextPacket [p u] (handler-fn p u)))]
      (.dispatch pcap -1 packet-handler user-data))))

(defn process-pcap-file-to-map
  "Convenience function to read a pcap file and process the packets in map format."
  [file-name handler-fn]
    (process-pcap-file 
      file-name
      (fn [p _]
        (handler-fn (parse-pcap-packet p)))))

