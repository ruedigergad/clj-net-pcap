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
    :doc "Common offsets of header fields etc."}
  clj-net-pcap.packet-offsets)

(def pcap-hdr-len 16)
(def eth-hdr-len 14)
(def ip-hdr-len 20)
(def udp-hdr-len 8)

(def eth-hdr-offset pcap-hdr-len)
(def ip-hdr-offset (+ eth-hdr-offset eth-hdr-len))
(def udp-hdr-offset (+ ip-hdr-offset ip-hdr-len))

(def eth-dst eth-hdr-offset)
(def eth-src (+ eth-hdr-offset 6))
(def ip-src (+ ip-hdr-offset 12))
(def ip-dst (+ ip-hdr-offset 16))
(def ip-id (+ ip-hdr-offset 4))
(def ip-checksum (+ ip-hdr-offset 10))
(def ip-ttl (+ ip-hdr-offset 8))
(def udp-src udp-hdr-offset)
(def udp-dst (+ udp-hdr-offset 2))

