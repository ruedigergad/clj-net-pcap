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
    :doc "Tests for extracting/loading the native libraries"} 
  clj-net-pcap.test.native
  (:require
   (clojure.java [io :as jio])
   (clojure [test :as test])
   (clj-assorted-utils [util :as utils])
   (clj-net-pcap [native :as native])
   [clj-net-pcap.native :as native]
   [clj-assorted-utils.util :as utils]))

(def test-filename "test-native-file-foo")

(test/deftest get-url-for-lib
  ; Test if we can actually get the location of a file contained in the jnetpcap.jar.
  ; For this to work jnetpcap.jar has to be on the classpath and the file we look
  ; for has to be in the jnetpcap.jar. This should be the case for the jar we
  ; created as we explicitly inlcuded the native libs there.
  (test/is (jio/resource "native/linux/amd64/libjnetpcap.so")))

(test/deftest get-url-for-lib-error
  (test/is (not (jio/resource "native/linux/amd64/doesnotexist.so"))))

(test/deftest mk-rm-native-lib-dir
  ; TODO: Should we use something more elaborate here? (mocking/stubbing?)
  (binding [native/*lib-dir* "clj-net-pcap-native-tests"]
    (let [dir (native/native-lib-dir)]
      (test/is (not (utils/dir-exists? dir)))
      (native/mk-native-lib-dir)
      (test/is (utils/dir-exists? dir))
      (native/rm-native-lib-dir)
      (test/is (not (utils/dir-exists? dir))))))

(test/deftest extract-from-jar-to-file
  (let [jar-content "native/linux/amd64/libjnetpcap.so"
        target-file test-filename]
    (test/is (not (utils/file-exists? target-file)))
    (test/is (jio/resource jar-content))
    (native/copy-resource-to-file jar-content target-file)
    (test/is (utils/file-exists? target-file))
    (utils/rm target-file)))

(test/deftest find-lib-in-jar
  (let [res (native/pcap-jar-path native/pcap080)]
    (println "\nUsing the following path to locate the library inside the JAR file: " res)
    (test/is (jio/resource res)
        (str "This test failed either because: \n"
             "1) The path used for locating the library was not correct (see above).\n"
             "2) The JAR archive does not contain a library for the "
             "combination of operating system and architecture you are using.\n"
             "Please verify if the latter is the case prior to filing a bug report."))))

(test/deftest extract-remove-native-libs
  ; TODO: Should we use something more elaborate here? (mocking/stubbing?)
  (binding [native/*lib-dir* "clj-net-pcap-native-tests"]
    (let [dir (native/native-lib-dir)
          prefix (cond
                   (utils/is-os? "windows") ""
                   :else "lib")
          suffix (cond
                   (utils/is-os? "windows") ".dll"
                   :else ".so")
          pcap080 (str dir prefix "jnetpcap" suffix)
          pcap100 (str dir prefix "jnetpcap-pcap100" suffix)]
      (test/is (not (utils/dir-exists? dir)))
      (test/are [x] (not (utils/file-exists? x))
        pcap080
        pcap100)
      (native/extract-native-libs)
      (test/are [x] (utils/file-exists? x)
        pcap080
        pcap100)
      (native/remove-native-libs)
      (test/is (not (utils/dir-exists? dir))))))

(test/deftest extract-and-refernce-native-libs-from-jar
  (binding [native/*lib-dir* "clj-net-pcap-native-tests"]
    (let [dir (native/native-lib-dir)
          prefix (cond
                   (utils/is-os? "windows") ""
                   :else "lib")
          suffix (cond
                   (utils/is-os? "windows") ".dll"
                   :else ".so")
          pcap080 (str dir prefix "jnetpcap" suffix)
          pcap100 (str dir prefix "jnetpcap-pcap100" suffix)]
      (test/is (not (utils/dir-exists? dir)))
      (test/are [x] (not (utils/file-exists? x))
        pcap080
        pcap100)
      (let [out-str (with-out-str (native/extract-and-reference-native-libs))]
        (test/is (= "Using native libs from clj-net-pcap jar file...\n" out-str)))
      (test/is pcap080 (System/getProperty "clj-net-pcap.lib.jnetpcap"))
      (test/is pcap100 (System/getProperty "clj-net-pcap.lib.jnetpcap-pcap100"))
      (test/are [x] (utils/file-exists? x)
        pcap080
        pcap100)
      (native/remove-native-libs)
      (test/is (not (utils/dir-exists? dir))))))

(test/deftest extract-and-refernce-native-libs-from-current-working-directory
  (let [prefix (cond
                 (utils/is-os? "windows") ""
                 :else "lib")
        suffix (cond
                 (utils/is-os? "windows") ".dll"
                 :else ".so")
        ; Refer to just the file names to read from current working directory.
        pcap080 (str prefix "jnetpcap" suffix)
        pcap100 (str prefix "jnetpcap-pcap100" suffix)]
    (test/are [x] (not (utils/file-exists? x))
      pcap080
      pcap100)
    ; Extract libs to current working directory ourselvses.
    ; If clj-net-pcap finds these there, it should load them from there instead of extracting the ones from the jar file.
    (native/copy-resource-to-file (native/pcap-jar-path pcap080) pcap080)
    (native/copy-resource-to-file (native/pcap-jar-path pcap100) pcap100)
    (test/are [x] (utils/file-exists? x)
      pcap080
      pcap100)
    (let [out-str (with-out-str (native/extract-and-reference-native-libs))]
      (test/is (= "Using native libs from current working directory...\n" out-str)))
    (test/is pcap080 (System/getProperty "clj-net-pcap.lib.jnetpcap"))
    (test/is pcap100 (System/getProperty "clj-net-pcap.lib.jnetpcap-pcap100"))
    ; Clean up manually and check that clean up succeeded.
    (utils/rm pcap080)
    (utils/rm pcap100)
    (test/are [x] (not (utils/file-exists? x))
      pcap080
      pcap100)))