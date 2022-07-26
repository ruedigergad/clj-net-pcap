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
   (clojure [test :as test]))
  (:use
        clojure.java.io
        clj-net-pcap.native
        clj-assorted-utils.util))  

(def test-filename "test-native-file-foo")

(test/deftest get-url-for-lib
  "Test if we can actually get the location of a file contained in the jnetpcap.jar.
   For this to work jnetpcap.jar has to be on the classpath and the file we look
   for has to be in the jnetpcap.jar. This should be the case for the jar we
   created as we explicitly inlcuded the native libs there."
  (test/is (resource "native/linux/amd64/libjnetpcap.so")))

(test/deftest get-url-for-lib-error
  (test/is (not (resource "native/linux/amd64/doesnotexist.so"))))

(test/deftest mk-rm-native-lib-dir
  ; TODO: Should we use something more elaborate here? (mocking/stubbing?)
  (binding [*lib-dir* "clj-net-pcap-native-tests"]
    (let [dir (native-lib-dir)]
      (test/is (not (dir-exists? dir)))
      (mk-native-lib-dir)
      (test/is (dir-exists? dir))
      (rm-native-lib-dir)
      (test/is (not (dir-exists? dir))))))

(test/deftest extract-from-jar-to-file
  (let [jar-content "native/linux/amd64/libjnetpcap.so"
        target-file test-filename]
    (test/is (not (file-exists? target-file)))
    (test/is (resource jar-content))
    (copy-resource-to-file jar-content target-file)
    (test/is (file-exists? target-file))
    (rm target-file)))

(test/deftest find-lib-in-jar
  (let [res (pcap-jar-path pcap080)]
    (println "\nUsing the following path to locate the library inside the JAR file: " res)
    (test/is (resource res)
        (str "This test failed either because: \n"
             "1) The path used for locating the library was not correct (see above).\n"
             "2) The JAR archive does not contain a library for the "
             "combination of operating system and architecture you are using.\n"
             "Please verify if the latter is the case prior to filing a bug report."))))

(test/deftest extract-remove-native-libs
  ; TODO: Should we use something more elaborate here? (mocking/stubbing?)
  (binding [*lib-dir* "clj-net-pcap-native-tests"]
    (let [dir (native-lib-dir)
          prefix (cond
                   (is-os? "windows") ""
                   :else "lib")
          suffix (cond
                   (is-os? "windows") ".dll"
                   :else ".so")
          pcap080 (str dir prefix "jnetpcap" suffix)
          pcap100 (str dir prefix "jnetpcap-pcap100" suffix)]
      (test/is (not (dir-exists? dir)))
      (test/are [x] (not (file-exists? x))
        pcap080
        pcap100)
      (extract-native-libs)
      (test/are [x] (file-exists? x)
        pcap080
        pcap100)
      (remove-native-libs)
      (test/is (not (dir-exists? dir))))))

