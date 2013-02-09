;(defproject clj-net-pcap "1.0.6"
(defproject clj-net-pcap "1.1.0-SNAPSHOT"
  :description "clj-net-pcap is a wrapper/adapter/facade (No matter how you wanna call it.) 
                around jNetPcap that enables and eases packet capturing with Clojure."
  :dependencies [[org.clojure/clojure "1.4.0"]
                 [org.clojure/tools.cli "0.2.2"]
                 [clj-assorted-utils "1.0.0"]
                 [jnetpcap "1.4.r1390-1b"]]
  :main clj-net-pcap.main
  :java-source-path "src"
  :omit-source true)
