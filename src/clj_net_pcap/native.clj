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
    :doc "Functions etc. for extracting, loading etc. native libraries from the jar file."} 
  clj-net-pcap.native
  (:use clojure.java.io 
        clj-assorted-utils.util)
  (:import (cljNetPcap LibLoader)))

(def ^:dynamic *lib-dir* "clj-net-pcap")

(defn native-lib-dir []
  (let [user (System/getProperty "user.name")]
    (cond
      (is-os? "linux") (str "/tmp/" *lib-dir* "_" user "/")
      (is-os? "windows") (str "C:\\TEMP\\" *lib-dir* "_" user "\\")
      :default (str "~/" *lib-dir* user "/"))))

(defn pcap-lib-name [p]
  (let [prefix (cond 
                 (is-os? "windows") ""
                 :default "lib")
        suffix (cond
                 (is-os? "windows") ".dll"
                 :default ".so")]
    (str prefix p suffix)))
(def pcap080
  (pcap-lib-name "jnetpcap"))
(def pcap100
  (pcap-lib-name "jnetpcap-pcap100"))

(defn pcap-jar-path [p]
  (let [os (.toLowerCase (get-os))
        arch (.toLowerCase (get-arch))]
    (str "native/" os "/" arch "/" p)))

(defn pcap-lib-path [p]
  (str (native-lib-dir) p))

(defn mk-native-lib-dir []
  (mkdir (native-lib-dir)))

(defn rm-native-lib-dir []
  (if (dir-exists? (native-lib-dir))
    (rmdir (native-lib-dir))))

(defn copy-resource-to-file [source target]
  (let [in (-> source (resource) (.openStream))
        out (file target)]
    (copy in out)))

(defn extract-native-lib [l]
  (copy-resource-to-file 
    (pcap-jar-path l)
    (pcap-lib-path l)))

(defn remove-native-libs []
  (if (file-exists? (pcap-lib-path pcap080))
    (rm (pcap-lib-path pcap080)))
  (if (file-exists? (pcap-lib-path pcap100))
    (rm (pcap-lib-path pcap100)))
  (rm-native-lib-dir))

(defn extract-native-libs []
  (do
    (if (dir-exists? (native-lib-dir))
      (remove-native-libs))
    (mk-native-lib-dir)
    (extract-native-lib pcap080)
    (extract-native-lib pcap100)))

(defn load-native-libs []
  (LibLoader/load (pcap-lib-path pcap080))
  (LibLoader/load (pcap-lib-path pcap100)))

(defn extract-and-load-native-libs []
  (extract-native-libs)
  (load-native-libs))

(extract-and-load-native-libs)

