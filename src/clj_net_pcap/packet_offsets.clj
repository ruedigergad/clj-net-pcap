;;;
;;; Copyright (C) 2015 Ruediger Gad
;;;
;;; This file is part of clj-net-pcap.
;;; clj-net-pcap is licensed under the terms of either
;;; - the GNU Lesser General Public License (LGPL) version 3 or later
;;;   http://www.gnu.org/licenses/lgpl-3.0.html
;;; or, at your option,
;;; - the Eclipse Public License (EPL) 1.0.
;;;   http://opensource.org/licenses/eclipse-1.0.php
;;;
;;; By contributing to clj-net-pcap, you agree that your contribution will be licensed under both licenses
;;; and that users of clj-net-pcap can chose any of these licenses.
;;;

(ns
  ^{:author "Ruediger Gad",
    :doc "Common offsets of header fields etc."}
  clj-net-pcap.packet-offsets)

(def pcap-hdr-len 16)
(def eth-hdr-len 14)
(def ipv4-hdr-len 20)
(def udp-hdr-len 8)

(def eth-hdr-offset pcap-hdr-len)
(def ipv4-hdr-offset (+ eth-hdr-offset eth-hdr-len))
(def udp-hdr-offset (+ ipv4-hdr-offset ipv4-hdr-len))
(def icmp-hdr-offset (+ ipv4-hdr-offset ipv4-hdr-len))

(def eth-dst eth-hdr-offset)
(def eth-src (+ eth-hdr-offset 6))
(def ipv4-src (+ ipv4-hdr-offset 12))
(def ipv4-dst (+ ipv4-hdr-offset 16))
(def ipv4-id (+ ipv4-hdr-offset 4))
(def ipv4-checksum (+ ipv4-hdr-offset 10))
(def ipv4-ttl (+ ipv4-hdr-offset 8))
(def ipv4-proto (+ ipv4-hdr-offset 9))
(def ipv4-version ipv4-hdr-offset)
(def udp-src udp-hdr-offset)
(def udp-dst (+ udp-hdr-offset 2))

(def icmp-type icmp-hdr-offset)
(def icmp-code (+ icmp-hdr-offset 8))
(def icmp-id (+ icmp-hdr-offset 32))
(def icmp-seq-no (+ icmp-hdr-offset 48))

