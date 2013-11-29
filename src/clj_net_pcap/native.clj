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
  (:import (clj_net_pcap LibLoader)))

(def ^:dynamic *lib-dir* "clj-net-pcap")

(defn native-lib-dir
  "Returns the directory to which the native libraries will be extracted.
   This may vary depending on the operating system."
  []
  (let [user (System/getProperty "user.name")]
    (cond
      (is-os? "linux") (str "/tmp/" *lib-dir* "_" user "/")
      (is-os? "windows") (str "C:\\TEMP\\" *lib-dir* "_" user "\\")
      :default (str "~/" *lib-dir* user "/"))))

(defn pcap-lib-name
  "Get the pcap lib names depending on the OS."
  [p]
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

(defn pcap-jar-path
  "Get the path of the jnetpcap libraries inside the clj-net-pcap jar."
  [p]
  (let [os (.toLowerCase (get-os))
        arch (.toLowerCase (get-arch))]
    (str "native/" os "/" arch "/" p)))

(defn pcap-lib-path
  "Path for an actual library file, given the file name."
  [p]
  (str (native-lib-dir) p))

(defn mk-native-lib-dir
  "Create the dir for extracting the native libraries."
  []
  (mkdir (native-lib-dir)))

(defn rm-native-lib-dir
  "Remove the native library temp directory."
  []
  (if (dir-exists? (native-lib-dir))
    (rmdir (native-lib-dir))))

(defn copy-resource-to-file
  "Copy from Jar to file."
  [source target]
  (let [in (-> source (resource) (.openStream))
        out (file target)]
    (copy in out)))

(defn extract-native-lib
  "Extract a single native library l."
  [l]
  (copy-resource-to-file 
    (pcap-jar-path l)
    (pcap-lib-path l)))

(defn remove-native-libs
  "Clean up native libs."
  []
  (if (file-exists? (pcap-lib-path pcap080))
    (rm (pcap-lib-path pcap080)))
  (if (file-exists? (pcap-lib-path pcap100))
    (rm (pcap-lib-path pcap100)))
  (rm-native-lib-dir))

(defn extract-native-libs
  "Extract the native libraries."
  []
  (do
    (if (dir-exists? (native-lib-dir))
      (remove-native-libs))
    (mk-native-lib-dir)
    (extract-native-lib pcap080)
    (extract-native-lib pcap100)))

(defn load-native-libs
  "Load the native libraries.
   This uses a little hack:
   The LibLoader Java class is used for actually loading the native libs."
  []
  (LibLoader/load (pcap-lib-path pcap080))
  (LibLoader/load (pcap-lib-path pcap100)))

(defn extract-and-load-native-libs
  "Convenience function for extracting and loading the native libraries."
  []
  (extract-native-libs)
  (load-native-libs)
  (add-shutdown-hook remove-native-libs))

(extract-and-load-native-libs)

