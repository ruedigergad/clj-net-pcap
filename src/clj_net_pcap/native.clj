;;;
;;; Copyright (C) 2012 Ruediger Gad
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
      (is-os? "freebsd") (str "/tmp/" *lib-dir* "_" user "/")
      (is-os? "windows") (str "C:\\TEMP\\" *lib-dir* "_" user "\\")
      :else (str "~/" *lib-dir* user "/"))))

(defn pcap-lib-name
  "Get the pcap lib names depending on the OS."
  [p]
  (let [prefix (cond 
                 (is-os? "windows") ""
                 :else "lib")
        suffix (cond
                 (is-os? "windows") ".dll"
                 :else ".so")]
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
  (when (dir-exists? (native-lib-dir))
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
  (when (file-exists? (pcap-lib-path pcap080))
    (rm (pcap-lib-path pcap080)))
  (when (file-exists? (pcap-lib-path pcap100))
    (rm (pcap-lib-path pcap100)))
  (rm-native-lib-dir))

(defn extract-native-libs
  "Extract the native libraries."
  []
  (when (dir-exists? (native-lib-dir))
    (remove-native-libs))
  (mk-native-lib-dir)
  (extract-native-lib pcap080)
  (extract-native-lib pcap100))

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

(defn extract-and-reference-native-libs
  "Convenience function for extracting and referencing the native libraries via System Properties: \"clj-net-pcap.lib.[jnetpcap, jnetpcap-pcap100]\"."
  []
  (extract-native-libs)
  (System/setProperty "clj-net-pcap.lib.jnetpcap" (pcap-lib-path pcap080))
  (System/setProperty "clj-net-pcap.lib.jnetpcap-pcap100" (pcap-lib-path pcap100))
  (add-shutdown-hook remove-native-libs))

(extract-and-reference-native-libs)
