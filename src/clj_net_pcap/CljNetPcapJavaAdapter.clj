;;;
;;; Copyright (C) 2013 Ruediger Gad
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
