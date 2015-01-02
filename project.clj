(defproject clj-net-pcap "1.6.9995"
;(defproject clj-net-pcap "1.7.0-SNAPSHOT"
  :description "clj-net-pcap is a wrapper/adapter/facade (No matter how you want to call it.)
                around jNetPcap that enables and eases packet capturing and processing with Clojure."
  :dependencies [[org.clojure/clojure "1.6.0"]
                  [org.clojure/tools.cli "0.2.4"]
                  [clj-assorted-utils "1.8.0"]
                  [jnetpcap "1.4.r1425-1e"]]
  :min-lein-version "2.0.0"
  :aot [#"^clj-net-pcap.*"]
  :global-vars {*warn-on-reflection* true}
  :main clj-net-pcap.main
  :java-source-paths ["src-java"]
;  :javac-options     ["-target" "1.6" "-source" "1.6"]
;  :jvm-opts ["-Dnio.blocksize=1048576"]
  :omit-source true
  :html5-docs-docs-dir "ghpages/doc"
  :html5-docs-ns-includes #"^clj-net-pcap.*"
  :html5-docs-repository-url "https://github.com/ruedigergad/clj-net-pcap/blob/master"
  :test2junit-output-dir "ghpages/test-results"
  :test2junit-run-ant true
  :plugins [[lein-cloverage "1.0.2"]]
  :profiles {:uberjar {:source-paths ["src" "src-main"]}
             :run {:source-paths ["src" "src-main"]}}
)
