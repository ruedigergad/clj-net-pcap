;(defproject clj-net-pcap "1.4.1"
(defproject clj-net-pcap "1.5.0-SNAPSHOT"
  :description "clj-net-pcap is a wrapper/adapter/facade (No matter how you wanna call it.) 
                around jNetPcap that enables and eases packet capturing with Clojure."
  :dependencies [[org.clojure/clojure "1.4.0"]
                 [org.clojure/tools.cli "0.2.2"]
                 [clj-assorted-utils "1.4.0"]
                 [jnetpcap "1.4.r1390-1b"]]
  :aot [#"^clj-net-pcap.*"]
  :global-vars {*warn-on-reflection* true}
  :main clj-net-pcap.main
  :java-source-paths ["src-java"]
  :omit-source true
  :html5-docs-docs-dir "ghpages/doc"
  :html5-docs-ns-includes #"^clj-net-pcap.*"
  :html5-docs-repository-url "https://github.com/ruedigergad/clj-net-pcap/blob/master"
  :test2junit-output-dir "ghpages/test-results"
  :test2junit-run-ant true)
