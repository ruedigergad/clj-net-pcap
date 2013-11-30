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
    :doc "Adapter class to enable usage of clj-net-pcap from Java."} 
  clj-net-pcap.CljNetPcapJavaAdapter
  (:use clj-net-pcap.core)
  (:gen-class
    :methods [#^{:static true} [extractNestedMapsFromPcapFile [String] java.util.List]
              #^{:static true} [extractMapsFromPcapFile [String] java.util.List]
              #^{:static true} [extractBeansFromPcapFile [String] java.util.List]]))

(defn -extractNestedMapsFromPcapFile
  "Wrapper function for extract-nested-maps-from-pcap-file."
  [file]
  (extract-nested-maps-from-pcap-file file))

(defn -extractMapsFromPcapFile
  "Wrapper function for extract-maps-from-pcap-file."
  [file]
  (extract-maps-from-pcap-file file))

(defn -extractBeansFromPcapFile
  "Wrapper function for extract-beans-from-pcap-file."
  [file]
  (extract-beans-from-pcap-file file))
