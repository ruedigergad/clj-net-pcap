;;;
;;; Copyright (C) 2013 Ruediger Gad
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
    :doc "Convenience functions for processing pcap data like packets and headers."}
  clj-net-pcap.pcap-data
  (:use clojure.pprint
        [clojure.string :only (join split)]
        clj-assorted-utils.util
        clj-net-pcap.native)
  (:import (java.net InetAddress)
           (java.nio ByteBuffer)
           (java.util Arrays ArrayList HashMap Map)
           (java.util.concurrent ScheduledThreadPoolExecutor)
           (clj_net_pcap ByteArrayHelper Counter PacketHeaderDataBean PacketHeaderDataBeanIpv4UdpOnly PacketHeaderDataBeanWithIpv4Udp)
           (org.jnetpcap PcapHeader)
           (org.jnetpcap.packet PcapPacket)
           (org.jnetpcap.packet.format FormatUtils)
           (org.jnetpcap.protocol.lan Ethernet)
           (org.jnetpcap.protocol.network Arp Icmp Icmp$Echo Icmp$EchoReply Icmp$EchoRequest Ip4 Ip6)
           (org.jnetpcap.protocol.tcpip Http Http$Request Http$Response
                                        Tcp Tcp$Flag Tcp$Timestamp Udp)))


(def ^:dynamic *tcp-flags-as-set* true)


(defn network-class
  "Determine the network class based on the private network classes as defined in RFC 1918. This assume no CIDR is used."
  [^String ip-addr]
  (cond
    (.startsWith ip-addr "192.168.") :class-c
    (.startsWith ip-addr "10.") :class-a
    (.startsWith ip-addr "172.") :class-b
    :default nil))

(defn guess-subnet
  "Try to guess the subnet address based on private network classes as defined in RFC 1918."
  [ip-addr]
  (let [addr-bytes (split ip-addr #"\.")
        n-class (network-class ip-addr)]
    (cond
      (= :class-c n-class) (join "." (conj (vec (drop-last addr-bytes)) "0"))
      (= :class-a n-class) (join "." (reduce conj (vec (drop-last 3 addr-bytes)) (repeat 3 "0")))
      (= :class-b n-class) (join "." (reduce conj (vec (drop-last 2 addr-bytes)) (repeat 2 "0")))
      :default nil)))

(defn guess-subnet-mask
  "Try to guess the subnet mask based on private network classes as defined in RFC 1918."
  [ip-addr]
  (let [n-class (network-class ip-addr)]
    (cond
      (= :class-c n-class) "255.255.255.0"
      (= :class-a n-class) "255.0.0.0"
      (= :class-b n-class) "255.255.0.0"
    :default nil)))

(defn guess-subnet-mask-bits
  "Try to guess the number of bits in the subnet mask based on private network classes as defined in RFC 1918."
  [ip-addr]
  (let [n-class (network-class ip-addr)]
    (cond
      (= :class-c n-class) 24
      (= :class-a n-class) 8
      (= :class-b n-class) 16
      :default nil)))

(defn prettify-addr-array
  "Convenience function to print addresses as strings."
  [#^bytes a]
  (if (-> (.getClass a) (.isArray))
    (cond
      (= (alength a) 6) (FormatUtils/mac a)
      (= (alength a) 4) (FormatUtils/ip a)
      (= (alength a) 16) (FormatUtils/asStringIp6 a true)
      :default (FormatUtils/asString a))
    a))

(defmacro process-protocol-headers-to-nested-maps
  "Macro for processing protocol header information into a representation of nested maps.
   packet is a org.jnetpcap.packet.PcapPacket instance.
   headers contains the description about which information shall be retrieved for each protocol.

   For an example usage see parse-protocol-headers-to-nested-maps."
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

(defmacro extract-subnet-information-to-map
  "Try to get information about source and destination subnets like network addresses or subnet masks.
   This is just a wild guess based on the private network ranges as defined in RFC 1918."
  [protocol]
  `(let [src# (prettify-addr-array (.source ~protocol))
         dst# (prettify-addr-array (.source ~protocol))]
    {"sourceNetwork" (guess-subnet src#)
     "sourceNetmaskBits" (guess-subnet-mask-bits src#)
     "destinationNetwork" (guess-subnet dst#)
     "destinationNetmaskBits" (guess-subnet-mask-bits dst#)}))

(defn extract-http-fields-to-map
  "Extract the given fields from an org.jnetpcap.protocol.tcpip.Http instance and store each into a map.
   fields is a vector that specifies which fields shall be extracted."
  [^Http http fields]
  (into {}
        (map (fn [f]
               (if (.hasField http f)
                 {(.toString f) (.fieldValue http f)}))
             fields)))

(def parse-protocol-headers-to-nested-maps
  ^{:doc "Function to parse the information contained in the protocol headers
          of a org.jnetpcap.packet.PcapPacket instance into a map.

          This function is a closure over the individual protocol class instances.
          The reason for this is to minimize the overhead due to instantiating those classes.
          This is a typical design pattern when working with jNetPcap.
          Please refer to the jNetPcap documentation for more information."}
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
      (process-protocol-headers-to-nested-maps
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
          "flags" (if *tcp-flags-as-set*
                    (set
                      (map #(.toString ^Tcp$Flag %1)
                           (.flagsEnum tcp)))
                    (.flags tcp))}
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

(defn parse-pcap-header-to-nested-map
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

(defn pcap-packet-to-nested-maps
  "Convenience function to parse a org.jnetpcap.packet.PcapPacket into a map.
   The result contains the pcap header and protocol header information."
  [^PcapPacket packet]
  (try
    (reduce into [{}
                  (parse-pcap-header-to-nested-map packet)
                  (parse-protocol-headers-to-nested-maps packet)])))

(defn- add-eth-fields
  [^Map m ^PcapPacket pkt ^Ethernet eth]
  (if (.hasHeader pkt eth)
    (doto m
      (.put "ethSrc" (prettify-addr-array (.source eth)))
	  (.put "ethDst" (prettify-addr-array (.destination eth))))
    m))

(defn- add-arp-fields
  [^Map m ^PcapPacket pkt ^Arp arp]
  (if (.hasHeader pkt arp)
    (doto m
      (.put "arpOpDesc" (.operationDescription arp))
      (.put "arpTargetMac" (prettify-addr-array (.tha arp)))
      (.put "arpTargetIp" (prettify-addr-array (.tpa arp)))
      (.put "arpSourceMac" (prettify-addr-array (.sha arp)))
      (.put "arpSourceIp" (prettify-addr-array (.spa arp))))
    m))

(defn- add-ip4-fields
  [^Map m ^PcapPacket pkt ^Ip4 ip4]
  (if (.hasHeader pkt ip4)
    (doto m
      (.put "ipSrc" (prettify-addr-array (.source ip4)))
      (.put "ipDst" (prettify-addr-array (.destination ip4)))
      (.put "ipVer" 4)
      (.put "ipId" (.id ip4))
      (.put "ipTtl" (.ttl ip4))
      (.put "ipChecksum" (.checksum ip4)))
    m))

(defn- add-ip6-fields
  [^Map m ^PcapPacket pkt ^Ip6 ip6]
  (if (.hasHeader pkt ip6)
    (doto m
      (.put "ipSrc" (prettify-addr-array (.source ip6)))
      (.put "ipDst" (prettify-addr-array (.destination ip6)))
      (.put "ipVer" 6))
    m))

(defn- add-icmp-echo-fields
  [^Map m ^Icmp icmp ^Icmp$Echo icmp-echo]
  (if (.hasSubHeader icmp icmp-echo)
    (doto
      (.put m "icmpEchoSeq" (.sequence icmp-echo)))
    m))

(defn- add-icmp-fields
  [^Map m ^PcapPacket pkt ^Icmp icmp ^Icmp$EchoReply icmp-echo-reply ^Icmp$EchoRequest icmp-echo-request]
  (if (.hasHeader pkt icmp)
    (doto m
      (.put "icmpType" (.typeDescription icmp))
      (add-icmp-echo-fields icmp icmp-echo-reply)
      (add-icmp-echo-fields icmp icmp-echo-request))
    m))

(defn- add-tcp-fields
  [^Map m ^PcapPacket pkt ^Tcp tcp]
  (if (.hasHeader pkt tcp)
    (doto m
      (.put "tcpSrc" (.source tcp))
      (.put "tcpDst" (.destination tcp))
      (.put "tcpAck" (.ack tcp))
      (.put "tcpSeq" (.seq tcp))
      (.put "tcpFlags" (.flags tcp)))
    m))

(defn- add-tcp-timestamp-fields
  [^Map m ^Tcp$Timestamp tcp-timestamp]
  (doto m
    (.put "tcpTsval" (.tsval tcp-timestamp))
    (.put "tcpTsecr" (.tsecr tcp-timestamp))))

(defn- add-udp-fields
  [^Map m ^PcapPacket pkt ^Udp udp]
  (if (.hasHeader pkt udp)
    (doto m
      (.put "udpSrc" (.source udp))
      (.put "udpDst" (.destination udp)))
    m))

(def pcap-packet-to-map
  "Convenience function to parse a org.jnetpcap.packet.PcapPacket into a flat,
   non-nested map."
  (let [eth (Ethernet.)
        arp (Arp.)
        icmp (Icmp.)
        icmp-echo-reply (Icmp$EchoReply.)
        icmp-echo-request (Icmp$EchoRequest.)
        ip4 (Ip4.)
        ip6 (Ip6.)
        tcp (Tcp.)
        tcp-timestamp (Tcp$Timestamp.)
        udp (Udp.)
        http (Http.)]
    (fn [^PcapPacket pkt]
      (let [hdr (.getCaptureHeader pkt)
            m (doto (HashMap.)
                (.put "ts" (.timestampInNanos hdr))
                (.put "len" (.wirelen hdr)))]
        (doto m
          (add-eth-fields pkt eth)
          (add-arp-fields pkt arp)
          (add-ip4-fields pkt ip4)
          (add-ip6-fields pkt ip6)
          (add-tcp-fields pkt tcp)
          (add-udp-fields pkt udp)
          (add-icmp-fields pkt icmp icmp-echo-reply icmp-echo-request)))
        )))

(def pcap-packet-to-map-ipv4-udp-only
  "Convenience function to parse a org.jnetpcap.packet.PcapPacket into a flat,
   non-nested map.
   Please note that this function only extracts data for IPv4 up to UDP."
  (let [eth (Ethernet.)
        ip4 (Ip4.)
        udp (Udp.)]
    (fn [^PcapPacket pkt]
      (let [hdr (.getCaptureHeader pkt)
            m (doto (HashMap.)
                (.put "ts" (.timestampInNanos hdr))
                (.put "len" (.wirelen hdr)))]
        (doto m
          (add-eth-fields pkt eth)
          (add-ip4-fields pkt ip4)
          (add-udp-fields pkt udp)))
        )))

(defn- add-pcap-header-data-bean
  [^PacketHeaderDataBeanWithIpv4Udp p ^PcapHeader hdr]
  (doto p
    (.setTs (.timestampInNanos hdr))
    (.setLen (.wirelen hdr))))

(defn- add-eth-fields-bean
  [^PacketHeaderDataBeanWithIpv4Udp p ^PcapPacket pkt ^Ethernet eth]
  (if (.hasHeader pkt eth)
    (doto p
      (.setEthSrc (prettify-addr-array (.source eth)))
      (.setEthDst (prettify-addr-array (.destination eth))))
    p))

(defn- add-arp-fields-bean
  [^PacketHeaderDataBean p ^PcapPacket pkt ^Arp arp]
  (if (.hasHeader pkt arp)
    (doto p
      (.setArpOpDesc (.operationDescription arp))
      (.setArpTargetMac (prettify-addr-array (.tha arp)))
      (.setArpTargetIp (prettify-addr-array (.tpa arp)))
      (.setArpSourceMac (prettify-addr-array (.sha arp)))
      (.setArpSourceIp (prettify-addr-array (.spa arp))))
    p))

(defn- add-ip4-fields-bean
  [^PacketHeaderDataBeanWithIpv4Udp p ^PcapPacket pkt ^Ip4 ip4]
  (if (.hasHeader pkt ip4)
    (doto p
      (.setIpSrc (prettify-addr-array (.source ip4)))
      (.setIpDst (prettify-addr-array (.destination ip4)))
      (.setIpVer 4)
      (.setIpId (.id ip4))
      (.setIpTtl (.ttl ip4))
      (.setIpChecksum (.checksum ip4)))
    p))

(defn- add-ip6-fields-bean
  [^PacketHeaderDataBean p ^PcapPacket pkt ^Ip6 ip6]
  (if (.hasHeader pkt ip6)
    (doto p
      (.setIpSrc (prettify-addr-array (.source ip6)))
      (.setIpDst (prettify-addr-array (.destination ip6)))
      (.setIpVer 6))
    p))

(defn- add-icmp-echo-fields-bean
  [^PacketHeaderDataBean p ^Icmp icmp ^Icmp$Echo icmp-echo]
  (if (.hasSubHeader icmp icmp-echo)
    (doto p
      (.setIcmpEchoSeq (.sequence icmp-echo)))
    p))

(defn- add-icmp-fields-bean
  [^PacketHeaderDataBean p ^PcapPacket pkt ^Icmp icmp ^Icmp$EchoReply icmp-echo-reply ^Icmp$EchoRequest icmp-echo-request]
  (if (.hasHeader pkt icmp)
    (doto p
      (.setIcmpType (.typeDescription icmp))
      (add-icmp-echo-fields-bean icmp icmp-echo-reply)
      (add-icmp-echo-fields-bean icmp icmp-echo-request))
    p))

(defn- add-tcp-fields-bean
  [^PacketHeaderDataBean p ^PcapPacket pkt ^Tcp tcp]
  (if (.hasHeader pkt tcp)
    (doto p
      (.setTcpSrc (.source tcp))
      (.setTcpDst (.destination tcp))
      (.setTcpAck (.ack tcp))
      (.setTcpSeq (.seq tcp))
      (.setTcpFlags (.flags tcp)))
    p))

(defn- add-udp-fields-bean
  [^PacketHeaderDataBeanWithIpv4Udp p ^PcapPacket pkt ^Udp udp]
  (if (.hasHeader pkt udp)
    (doto p
      (.setUdpSrc (.source udp))
      (.setUdpDst (.destination udp)))
    p))

(def pcap-packet-to-bean
  "Convenience function to parse a org.jnetpcap.packet.PcapPacket into a bean."
  (let [eth (Ethernet.)
        arp (Arp.)
        icmp (Icmp.)
        icmp-echo-reply (Icmp$EchoReply.)
        icmp-echo-request (Icmp$EchoRequest.)
        ip4 (Ip4.)
        ip6 (Ip6.)
        tcp (Tcp.)
        udp (Udp.)
        http (Http.)]
    (fn [^PcapPacket pkt]
      (let [hdr (.getCaptureHeader pkt)
            p (PacketHeaderDataBean.)]
        (-> p
          (add-pcap-header-data-bean hdr)
          (add-eth-fields-bean pkt eth)
          (add-arp-fields-bean pkt arp)
          (add-ip4-fields-bean pkt ip4)
          (add-ip6-fields-bean pkt ip6)
          (add-icmp-fields-bean pkt icmp icmp-echo-reply icmp-echo-request)
          (add-tcp-fields-bean pkt tcp)
          (add-udp-fields-bean pkt udp))))))

(def pcap-packet-to-bean-ipv4-udp-only
  "Convenience function to parse a org.jnetpcap.packet.PcapPacket into a bean.
   Please note that this function only extracts data for IPv4 up to UDP."
  (let [eth (Ethernet.)
        arp (Arp.)
        ip4 (Ip4.)
        udp (Udp.)]
    (fn [^PcapPacket pkt]
      (let [hdr (.getCaptureHeader pkt)
            p (PacketHeaderDataBeanIpv4UdpOnly.)]
        (-> p
          (add-pcap-header-data-bean hdr)
          (add-eth-fields-bean pkt eth)
          (add-ip4-fields-bean pkt ip4)
          (add-udp-fields-bean pkt udp))))))

(defn pcap-packet-to-byte-vector
  "Convert the given org.jnetpcap.packet.PcapPacket to its byte array representation and return it as vector.
   This can be handy for debugging purposes as the resulting vector can be easily converted back into a org.jnetpcap.packet.PcapPacket instance.

   The re-assembly process is as follows:
[rc@WOPR dist]$ CLASSPATH=$CLASSPATH:clj-net-pcap-1.3.1.jar:../lib/jnetpcap-1.4.r1390-1b.jar:../lib/clj-assorted-utils-1.0.0.jar clojure
Clojure 1.5.1
user=> (use 'clj-net-pcap.native)
nil
user=> (extract-and-load-native-libs)
nil
user=> (import '(org.jnetpcap.packet PcapPacket))
org.jnetpcap.packet.PcapPacket
user=> (import '(org.jnetpcap.nio JMemory))
org.jnetpcap.nio.JMemory
user=> (import '(org.jnetpcap.nio JMemory$Type))
org.jnetpcap.nio.JMemory$Type
user=> (def pkt (PcapPacket. JMemory$Type/POINTER))
#'user/pkt
user=> (def ba (byte-array (map byte [22 3 -110 81 0 0 0 0 100 12 2 0 0 0 0 0 -48 0 0 0 -48 0 0 0 42 0 0 0 0 0 0 0 -9 -82 104 95 1 0 3 0 3 3 5 0 12 95 104 83 -1 2 0 12 17 0 0 0 17 0 0 0 67 -12 0 0 108 7 0 0 -1 2 0 12 12 95 104 83 17 0 0 0 17 0 0 0 108 7 0 0 67 -12 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 6 0 0 0 0 0 0 0 43 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 -48 0 0 0 -48 0 0 0 4 0 0 0 0 0 0 0 1 0 0 0 0 8 0 0 0 0 0 0 14 0 0 0 -62 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 3 0 0 0 0 8 0 0 14 0 0 0 40 0 0 0 -102 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 5 0 0 0 0 8 0 0 54 0 0 0 8 0 0 0 -110 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 8 0 0 62 0 0 0 -110 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 51 51 0 0 0 12 8 0 39 113 22 114 -122 -35 96 0 0 0 0 -102 17 1 -2 -128 0 0 0 0 0 0 81 -56 104 119 -93 23 0 36 -1 2 0 0 0 0 0 0 0 0 0 0 0 0 0 12 -12 67 7 108 0 -102 69 -96 77 45 83 69 65 82 67 72 32 42 32 72 84 84 80 47 49 46 49 13 10 72 111 115 116 58 91 70 70 48 50 58 58 67 93 58 49 57 48 48 13 10 83 84 58 117 114 110 58 77 105 99 114 111 115 111 102 116 32 87 105 110 100 111 119 115 32 80 101 101 114 32 78 97 109 101 32 82 101 115 111 108 117 116 105 111 110 32 80 114 111 116 111 99 111 108 58 32 86 52 58 73 80 86 54 58 76 105 110 107 76 111 99 97 108 13 10 77 97 110 58 34 115 115 100 112 58 100 105 115 99 111 118 101 114 34 13 10 77 88 58 51 13 10 13 10])))
#'user/ba
user=> (.transferStateAndDataFrom pkt ba)
576
  user=> (import '(org.jnetpcap.protocol.network Ip6))
org.jnetpcap.protocol.network.Ip6
user=> (def ip6 (Ip6.))
#'user/ip6
user=> (.hasHeader pkt ip6)
true
user=> (.source ip6)
#<byte[] [B@3c1c6c94>
user=> (use 'clj-net-pcap.pcap-data)
nil
user=> (prettify-addr-array (.source ip6))
\"FE80::51C8:6877:A317:0024\"
user=>
  "
  [^PcapPacket pcap-packet]
  (let [buffer (byte-array (.getTotalSize pcap-packet) (byte 0))
        _ (.transferStateAndDataTo pcap-packet buffer)]
    (vec buffer)))

(defn no-op
  "Function that forwardes the supplied argument as-is.
   This is used for testing purposes."
  [obj]
  obj)

(defn stdout-forwarder-fn
  "Pre-defined forwarder function which outputs information about org.jnetpcap.packet.PcapPacket to *out*."
  [packet]
  (pprint packet)
  (println "---"))

(defn stdout-byte-array-forwarder-fn
  "Print the byte vector representation of a org.jnetpcap.packet.PcapPacket as returned by pcap-packet-to-byte-vector to *out*."
  [^PcapPacket packet]
  (let [buffer-seq (pcap-packet-to-byte-vector packet)]
    (println "Packet Start (size:" (count buffer-seq) "):" buffer-seq "Packet End\n\n")))

(defn stdout-combined-forwarder-fn
  [^PcapPacket packet]
  "Print both, the parsed packet and the byte vector representations, of a org.jnetpcap.packet.PcapPacket to *out*."
  (let [buffer-seq (pcap-packet-to-byte-vector packet)]
    (pprint (pcap-packet-to-map packet))
    (println "Packet Start (size:" (count buffer-seq) "):" buffer-seq "Packet End\n\n")))

(defn no-op-converter-forwarder-fn
  "Forwarder that does nothing.
   This is used for testing purposes."
  [^PcapPacket packet])

(defn counting-no-op-forwarder-fn
  "No-op forwarder that counts how many times it was called.
   This is used for testing purposes."
  [bulk-size]
  (let [cntr (Counter.)
        printer #(let [val (.value cntr)]
                   (if (>= val 0)
                     (println (* (.value cntr) bulk-size))))
        _ (run-repeat (executor) printer 1000)]
    (fn [_]
      (do
        (.inc cntr)))))

(defn calls-per-second-no-op-forwarder-fn
  "No-op forwarder that periodically prints how many times it was called per second.
   This is used for testing purposes."
  [bulk-size]
  (let [cntr (Counter.)
        delta-cntr (delta-counter)
        time-tmp (ref (System/currentTimeMillis))
        pps-printer #(let [val (* bulk-size (.value cntr))]
                       (if (>= val 0)
                         (let [cur-time (System/currentTimeMillis)
                               time-delta (- cur-time @time-tmp)]
                           (when (> time-delta 0)
                             (println "pps" (float (/ (delta-cntr :val val) (/ time-delta 1000))) "total" val)
                             (dosync
                               (ref-set time-tmp cur-time))))))
        _ (run-repeat (executor) pps-printer 1000)]
    (fn [_]
      (.inc cntr))))



(def pcap-hdr-len 16)
(def eth-hdr-len 14)
(def ip-hdr-len 20)
(def udp-hdr-len 8)
(def eth-hdr-offset pcap-hdr-len)
(def ip-hdr-offset (+ eth-hdr-offset eth-hdr-len))
(def udp-hdr-offset (+ ip-hdr-offset ip-hdr-len))

(defn packet-byte-array-extract-map-ipv4-udp
  [^bytes ba]
  (let [m (doto (HashMap.)
            (.put "ts" (+ (* (ByteArrayHelper/getInt ba 0) 1000000000) (* (ByteArrayHelper/getInt ba 4) 1000)))
            (.put "len" (ByteArrayHelper/getInt ba 12))
            (.put "ethDst" (FormatUtils/asStringZeroPad ba \: 16 eth-hdr-offset 6))
            (.put "ethSrc" (FormatUtils/asStringZeroPad ba \: 16 (+ eth-hdr-offset 6) 6))
            (.put "ipVer" 4)
            (.put "ipSrc" (FormatUtils/asString ba \. 10 (+ ip-hdr-offset 12) 4))
            (.put "ipDst" (FormatUtils/asString ba \. 10 (+ ip-hdr-offset 16) 4))
            (.put "ipId" (ByteArrayHelper/getInt16 ba (+ ip-hdr-offset 4)))
            (.put "ipChecksum" (ByteArrayHelper/getInt16 ba (+ ip-hdr-offset 10)))
            (.put "ipTtl" (ByteArrayHelper/getByte ba (+ ip-hdr-offset 8)))
            (.put "udpSrc" (ByteArrayHelper/getInt16 ba udp-hdr-offset))
            (.put "udpDst" (ByteArrayHelper/getInt16 ba (+ udp-hdr-offset 2))))]
    m))

(defn packet-byte-array-extract-map-ipv4-udp-be
  [^bytes ba offset]
  (let [m (doto (HashMap.)
            (.put "ts" (+ (* (ByteArrayHelper/getIntBigEndian ba (+ offset 0)) 1000000000) (* (ByteArrayHelper/getIntBigEndian ba (+ offset 4)) 1000)))
            (.put "len" (ByteArrayHelper/getIntBigEndian ba (+ offset 12)))
            (.put "ethDst" (FormatUtils/asStringZeroPad ba \: 16 (+ offset eth-hdr-offset) 6))
            (.put "ethSrc" (FormatUtils/asStringZeroPad ba \: 16 (+ offset eth-hdr-offset 6) 6))
            (.put "ipVer" 4)
            (.put "ipSrc" (FormatUtils/asString ba \. 10 (+ offset ip-hdr-offset 12) 4))
            (.put "ipDst" (FormatUtils/asString ba \. 10 (+ offset ip-hdr-offset 16) 4))
            (.put "ipId" (ByteArrayHelper/getInt16 ba (+ offset ip-hdr-offset 4)))
            (.put "ipChecksum" (ByteArrayHelper/getInt16 ba (+ offset ip-hdr-offset 10)))
            (.put "ipTtl" (ByteArrayHelper/getByte ba (+ offset ip-hdr-offset 8)))
            (.put "udpSrc" (ByteArrayHelper/getInt16 ba (+ offset udp-hdr-offset)))
            (.put "udpDst" (ByteArrayHelper/getInt16 ba (+ offset udp-hdr-offset 2))))]
    m))

(defn packet-byte-buffer-extract-map-ipv4-udp-single
  [^ByteBuffer bb]
  (if (.hasArray bb)
    (packet-byte-array-extract-map-ipv4-udp (.array bb))))

(defn packet-byte-buffer-extract-map-ipv4-udp-bulk
  [^ByteBuffer bb]
  (if (.hasArray bb)
    (let [ba (.array bb)
          r (ArrayList.)]
      (loop [offset 0]
        (.add r (packet-byte-array-extract-map-ipv4-udp-be ba offset))
        (let [new-offset (+ 16 offset (ByteArrayHelper/getIntBigEndian ba 8))]
          (if (< new-offset (alength ba))
            (recur new-offset))))
      r)))

