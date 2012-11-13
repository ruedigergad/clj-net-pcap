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
           (org.jnetpcap.packet PcapPacket)
           (org.jnetpcap.packet.format FormatUtils)
           (org.jnetpcap.protocol.lan Ethernet)
           (org.jnetpcap.protocol.network Arp Icmp Ip4 Ip6)
           (org.jnetpcap.protocol.tcpip Http Http$Request Http$Response 
                                        Tcp Tcp$Flag Tcp$Timestamp Udp)))

(defn create-and-start-cljnetpcap
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
        (cond
          (= k :stat) (stat-print-fn)
          (= k :stop) (do
                        (stop-sniffer sniffer)
                        (stop-forwarder forwarder)))))))

(defn print-stat-cljnetpcap [cljnetpcap]
  (cljnetpcap :stat))

(defn stop-cljnetpcap [cljnetpcap]
  (cljnetpcap :stop))

(defn prettify-addr-array [^Object a]
  (if (-> (.getClass a) (.isArray))
    (cond
      (= (alength a) 6) (FormatUtils/mac a)
      (= (alength a) 4) (FormatUtils/ip a)
      (= (alength a) 16) (FormatUtils/asStringIp6 a true)
      :default (FormatUtils/asString a))
    a))

(defmacro process-protocol-headers [packet & headers]
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

(defmacro src-dst [protocol]
  `{"source" (prettify-addr-array (.source ~protocol))
    "destination" (prettify-addr-array (.destination ~protocol))})

(defn get-http-fields [http fields]
  (into {}
        (map (fn [f] 
               (if (.hasField http f)
                 {(.toString f) (.fieldValue http f)}))
             fields)))

(def parse-protocol-headers
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
      (process-protocol-headers
        packet
        [eth 
         (src-dst eth)]
        [arp
         {"operationDescription" (.operationDescription arp)
          "targetMac" (prettify-addr-array (.tha arp))
          "targetIp" (prettify-addr-array (.tpa arp))
          "sourceMac" (prettify-addr-array (.sha arp))
          "sourceIp" (prettify-addr-array (.spa arp))}]
        [ip4
         (src-dst ip4)
         {"id" (.id ip4)
          "tos" (.tos ip4)
          "ttl" (.ttl ip4)}]
        [ip6
         (src-dst ip6)
         {"flowLabel" (.flowLabel ip6)
          "hopLimit" (.hopLimit ip6)
          "trafficClass" (.trafficClass ip6)}]
        [icmp
         {"typeDescription" (.typeDescription icmp)}]
        [tcp
         (src-dst tcp)
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
         (src-dst udp)]
        [http
         (get-http-fields 
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

(defn parse-pcap-header [^PcapPacket packet]
  (let [header (.getCaptureHeader packet)]
    {(classname header) {"timestampInNanos" (.timestampInNanos header)
                         "wirelen" (.wirelen header)}}))

(defn parse-pcap-packet [^PcapPacket packet]
  (reduce into [{}
                (parse-pcap-header packet)
                (parse-protocol-headers packet)]))

(defn stdout-forwarder-fn [packet]
  (pprint (parse-pcap-packet (:pcap-packet packet))))

(defn stdout-byte-array-forwarder-fn [packet]
  (let [pcap-packet (:pcap-packet packet)
        buffer (byte-array (.getTotalSize pcap-packet) (byte 0))
        _ (.transferStateAndDataTo pcap-packet buffer)
        buffer-seq (vec buffer)]
    (println "Packet Start (size:" (count buffer-seq) "):" buffer-seq "Packet End\n\n")))

(defn stdout-combined-forwarder-fn [packet]
  (let [pcap-packet (:pcap-packet packet)
        buffer (byte-array (.getTotalSize pcap-packet) (byte 0))
        _ (.transferStateAndDataTo pcap-packet buffer)
        buffer-seq (vec buffer)]
    (pprint (parse-pcap-packet (:pcap-packet packet)))
    (println "Packet Start (size:" (count buffer-seq) "):" buffer-seq "Packet End\n\n")))

