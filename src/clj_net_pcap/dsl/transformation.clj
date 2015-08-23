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
    :doc "Transformation functions for the simple DSL for extracting data from packets that are represented as byte arrays."}
  clj-net-pcap.dsl.transformation
  (:require (clj-net-pcap [packet-offsets :as offsets]))
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

