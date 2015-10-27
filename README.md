Oak
===

Reporting and iterative search engine

## Purpose
This project is an attempt to create a long-term storage engine for reporting capabilities. In addition, it attempts to provide a way to execute ad-hoc searches as reports. These searches can have any number of aggregations and transformations, depending on the request. The overriding goal is to do all of this as cheaply and simply as possible by sacrificing speed in exchange for managed user expectations. To that end, Oak streams results back as they are discovered, incomplete or otherwise, to give the user something to analyze as the rest of the results are tallied. This is possible with aggregations by providing estimates that are continually revised in realtime as more results are available. Many existing search technologies focus on query throughput and optimize the architecture for serving data that largely fits in available memory. Oak assumes that the data it serves will be much larger than memory and all actions are disk-bound.

## Indexing Features
  * High index rate (2 MB/sec/core), scales linearly with cores
  * Data normalization
    * Accepts JSON and non-JSON
    * Nested data structure flattening ({ "a": { "b": 1 } } becomes a.b=1)
    * Field rewrites based on configuration ("src_port" becomes "srcport")
    * Decoration (tagging, etc.)
    * Auto field type detection for integer, string, and IPv4
  * 2:1 overall compression rate (including all indexes) versus original data.
  * No management daemons. The only running processes are actively indexing.
  * No daemonized DB's. All files are flat files, the only database is a SQLite DB or Zookeeper.
  * All key-values stored by default for reporting. All docs stored by default.
  * All data stored per-segment except for segment names and counts, guaranteeing scalability as segment count grows.
  * Three field indexing strategies: key-value, doc value, and document introspection.

## Reporting Features
  * Moderate search speed: 1-2 million docs/sec/core for sparse queries, 250k docs/sec/core for groupby or dense queries.
  * Very low RAM use for search. No running daemon using RAM or any caching. All caching is disk caching via OS.
  * Standard query interface with JSON query objects for terms, filters, and groupby, as well as standard directives such as limit/offset/sort.
  * Fast key-value access
  * Multi-groupby queries such as groupby:* returning every field as a facet.
  * Streaming result sets with known total work and percentage complete tallied as results accrue.
  * Queries are automatically optimized for the right index strategy.

## Architecture
### Indexing
A parent process reads data from a file object (raw file, FIFO, or socket) and writes to a multiprocess queue in batches. Workers read from the queue and write to a segment until the segment size is reached. Then the segment is closed, the directory is updated with the min/max timestamps detected in the data for the segment (which is calculated on-line as docs are streamed in), and the segment is available for searching. Each worker writes to its own segment which achieves extremely high parallelism. The segments are not normally merged unless many small segments appear due to process start/stop.

All data is stored in Sparkey. Sparkey is an embedded key-value database written and open-sourced by Spotify and is available on github.com/spotify/sparkey. Sparkey stores all data using Google's Snappy compression. Sparkey is uniquely suited for this workload as it is highly optimized for a write-once read-many workload and provides incredible disk space reduction due to its optimizations. This allows significantly less data to be necessarily retrieved from disk during query execution, which is the limiting performance factor for any data access on data sets larger than available memory. Sparkey outperforms LevelDB, HyperLevelDB, Symas LMDB, Sophia, and InfluxDB on random reads by an order of magnitude when the dataset does not fit in memory. All embedded key-value stores have extremely high write throughput such that the performance is irrelevant. Oak is entirely CPU bound for almost all index operations.

An indexed doc is inspected and every field is checked for type and possible rewrite via configured aliases. Optional decoration occurs. The doc is given an id which is a composite of the incremented counter and the field signature ID, which is a concatenation of the sorted fields in the doc. The field signature is used at query time for efficiently determining whether a given doc could contain a requested field without having to retrieve the doc. The field signature ID is in the upper 20 bits of the ID, and the incremented counter ID is in the lower 12. This efficient use of space dramatically reduces the overall index size which in turn means less data retrieved from disk during query, which translates directly to performance gains. The fields are recorded in the overall key-value store as well as in the doc values store which contains a simple binary encoding of every doc_id to ordinal tuple for fast groupby and sort of field values. The entire doc is recorded. 

Each segment consists of five databases, each of which is two files:
  - Doc - the docs themselves
  - Idx - the inverted index
  - Stats - the key-value pairs
  - Docvals - the fields and the corresponding packed tuples of ID-hashed-value
  - Classes - the short list of field signatures observed in the segment

### Searching
A parent search process takes a hash of params and checks the SQLite global directory for which segments contain the right dates. Workers are spawned and the segments are sequentially enqueued to the workers for searching. Each worker performs the search on a single segment and enqueues the result in the return queue to the parent. The parent tallies the results and provides updates to the user.

Searches are fastest when a list of terms is given that the docs should or should not match. Searches can use and, or, and not as booleans, and nested filters are allowed. Searches are not required to contain search terms, they may be filter-only, such as range-only searches, only negation searches, regex, and substring searches.

Searches can search for single, multiple, or all fields in a groupby. If a search does not specify any terms or filters, the key-value store is used for extremely fast results. If simple field filters and operations are used, the docvals database is used for efficient grouping and sorting. If the filter uses regex, contains, or any fields not native to the docs, an introspective search is performed in which all docs matching the search terms are retrieved and a filter is applied to fields therein. This method offers unlimited flexibility but is the slowest.

Results are sorted and the top or bottom N in the limit are returned. Limitless searches are possible. The default is reverse timestamp sort and a limit of 100.
