;;;
;;; Copyright (C) 2015-2022 Ruediger Gad
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
    :doc "Transformation functions for the simple DSL for extracting data from packets that are represented as byte arrays."}
  clj-net-pcap.dsl.transformation
  (:import (clj_net_pcap ByteArrayHelper)
           (org.jnetpcap.packet.format FormatUtils)))


(defn int4low
  "Get the lower 4 bits (nibble) of the byte at the given index idx in the provided byte-array ba."
  [ba idx]
  (ByteArrayHelper/getNibbleLow ba idx))

(defn int4high
  "Get the higher 4 bits (nibble) of the byte at the given index idx in the provided byte-array ba."
  [ba idx]
  (ByteArrayHelper/getNibbleHigh ba idx))

(defn int8
  "Get the byte at the index idx in the byte-array ba."
  [ba idx]
  (ByteArrayHelper/getByte ba idx))

(defn int16
  "Get the Int16 value of the two bytes starting at index idx in the byte-array ba."
  [ba idx]
  (ByteArrayHelper/getInt16 ba idx))

(defn int16be
  "Get the big endian Int16 value of the two bytes starting at index idx in the byte-array ba."
  [ba idx]
  (ByteArrayHelper/getInt16BigEndian ba idx))

(defn int32
  "Get the Int32 value of the four bytes starting at index idx in the byte-array ba."
  [ba idx]
  (ByteArrayHelper/getInt ba idx))

(defn int32be
  "Get the big endian Int32 value of the four bytes starting at index idx in the byte-array ba."
  [ba idx]
  (ByteArrayHelper/getIntBigEndian ba idx))

(defn timestamp
  "Get the pcap timestamp value of the four bytes starting at index idx in the byte-array ba."
  [ba idx]
  (+ (* (ByteArrayHelper/getInt ba idx) 1000000000) (* (ByteArrayHelper/getInt ba (+ idx 4)) 1000)))

(defn timestamp-be
  "Get the pcap big endian timestamp value of the four bytes starting at index idx in the byte-array ba."
  [ba idx]
  (+ (* (ByteArrayHelper/getIntBigEndian ba idx) 1000000000) (* (ByteArrayHelper/getIntBigEndian ba (+ idx 4)) 1000)))

(defn ethernet-address
  "Get the formated ethernet address String starting at index idx in the byte-array ba."
  [ba idx]
  (FormatUtils/asStringZeroPad ba \: 16 idx 6))

(defn ipv4-address
  "Get the formated IPv4 address String starting at index idx in the byte-array ba."
  [ba idx]
  (FormatUtils/asString ba \. 10 idx 4))
