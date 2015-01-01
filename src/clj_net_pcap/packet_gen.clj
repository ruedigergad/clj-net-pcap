;;;
;;; Copyright (C) 2015 Ruediger Gad
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
    :doc "The packet-gen namespace contains functionality for generating and sending packets."}
  clj-net-pcap.packet-gen
  (:use clj-net-pcap.pcap
        clj-assorted-utils.util)
  (:import (clj_net_pcap ByteArrayHelper)
           (java.nio BufferUnderflowException ByteBuffer)
           (java.util Map)
           (java.util.concurrent ArrayBlockingQueue)
           (org.jnetpcap Pcap PcapDLT PcapHeader)
           (org.jnetpcap.nio JBuffer JMemory JMemory$Type)
           (org.jnetpcap.packet PcapPacket PcapPacketHandler)))

(defn generate-packet-data
  [^Map pkt-desc-map]
  (let [ba (byte-array (.get pkt-desc-map "len"))]
    (System/arraycopy 
      (ByteArrayHelper/ethMacStringToByteArrayUnchecked (.get pkt-desc-map "ethDst"))
      0 ba 0 6)
    (System/arraycopy 
      (ByteArrayHelper/ethMacStringToByteArrayUnchecked (.get pkt-desc-map "ethSrc"))
      0 ba 6 6)
    ba))

