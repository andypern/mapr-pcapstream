In this repo, we use spark streaming to pull the flow information from PCAP files that are being
written live to MapR FS.

Captures happen via either a Corvil appliance or Solarcapture software and get written to MapR FS via the POSIX client (eventually FUSE client).

Eventually, this will hopefully be able to deal with very high ingest rate, multiple 40Gbps interfaces being captured.

TODO
=====

* Push flow data into Elasticsearch or Solr with each batch

* Push flow data onto a Kafka/Marlin topic for pull by ES?

* ~~Output the flow data as parquet for query by BI tools~~

* Include a directory path for the files

* Good naming convention for the pcap filenames so we can pull them back

* Dashboard the flow data in Kibana

