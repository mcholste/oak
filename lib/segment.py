import re
import traceback
import sqlite3
import collections
import StringIO
import marshal

from datetime import datetime
from time import *
from struct import pack, unpack
from operator import itemgetter
from socket import inet_aton, inet_ntoa

import ujson as json

# https://github.com/spotify/sparkey-python which requires sparkey from https://github.com/spotify/sparkey
import sparkey

from utils import *
from taxonomy import Taxonomy

class SegmentFullException(Exception):
    pass

class Segment(Logger, Utils):

    db_names = [ "idx", "doc", "stats", "classes", "docvals" ]
    COMPOSITE_SEPARATOR = "\0"

    def __init__(self, config, prefix):
        #self.log = self._log_init_name("segment")
        self.config = config
        if not config.has_key("composite_fields"):
            config["composite_fields"] = []
        self.splitter = re.compile("[^A-Z-a-z0-9\.\_\@]")
        self.keywords = {}
        self.timer = Timer()
        self.prefix = str(prefix)
        self.dbs = {}
        for db in self.db_names:
            # Compression size 32768 is best compromise between speed
            #  and compression rate
            self.dbs[db] = sparkey.LogWriter(
                get_db_file(self.prefix, db, "log"),
                compression_type=sparkey.Compression.SNAPPY, 
                compression_block_size=32768)
        
        self.timestamp_col = config.get("timestamp_col", "meta_ts")
        #self.standard_cols = [self.timestamp_col, "meta_rule", "class"]
        self.standard_cols = [self.timestamp_col]
        self.standard_cols_set = frozenset(self.standard_cols)
        self.non_stats_cols = ["rawmsg", "meta_cid", "meta_mid"]
        self.non_stats_cols_set = frozenset(self.non_stats_cols)

        self.values = {}
        self.id = 0
        
        self.classes = {}
        self.min_event_time = time()
        self.max_event_time = time()

        self.docvals = {}
        self.field_count = 0
        self.stats = {}

        # Known map of field name to type
        self.field_type_map = config.get("field_types", {})

        # ID's are 32 bits, and 20 bits are reserved for the id with 12 bits for the class ID
        self.max_segment_count = config.get("max_segment_size", 2**20 - 1)
        self.max_classes = 2**12

        self.timer.status("init")
        self.timer.stat_start("collect")
        self.timer.stat_start("index")

        def iso_no_tz_formatter(doc):
            return mktime(datetime.strptime(doc[ self.timestamp_col ], 
                "%Y-%m-%dT%H:%M:%S.%f").timetuple())
        def epoch_micro_formatter(doc):
            return float(doc[ self.timestamp_col ]) / 1000000
        pat = re.compile("(\d+)\-(\d+)\-(\d+)T(\d+)\:(\d+)\:(\d+)\.(\d+)")
        # This function uses regex and simple math instead of strptime because strptime=slow
        def iso_no_tz_regex_formatter(doc):
            matches = pat.findall(doc[ self.timestamp_col ])
            if len(matches):
                matches = matches[0]
                day = mktime((int(matches[0]), int(matches[1]), 
                    int(matches[2]), 0, 0, 0, 0, 0, -1))
                return day + (int(matches[3]) * 3600) + \
                    (int(matches[4]) * 60) + int(matches[5])
        
        if config.get("ts_format") is "iso_no_tz":
            self.timestamp_formatter = iso_no_tz_regex_formatter
        else:
            self.timestamp_formatter = epoch_micro_formatter

        self.keep_original = False
        if config.get("keep_original"):
            self.keep_original = True

    def index_datum(self, datum):
        """Autodetect what kind of datum we were given and index."""
        self.id += 1
        if self.id >= self.max_segment_count:
            raise SegmentFullException("Segment is full with %d entries" 
                % self.id)
        if type(datum) is str:
            self.index_line(datum)
        else:
            self.index_doc(datum)

    def index_line(self, line):
        """Given a string, autodetect what kind of string and index."""
        try:
            if line[0] == "{":
                self.index_doc(json.loads(line), line)
            else:
                #TODO timestamp parsing, then create JSON doc from raw line
                self.log.error("Non-json line: %s" % line)
                self.id -= 1
        except:
            self.log.error(traceback.format_exc())
            self.id -= 1

    def index_doc(self, doc, line=None):
        """Index a given doc dict."""
        l_field_aliases = Taxonomy.field_aliases
        l_nested = {}
        # The def/map combo is faster than a for loop
        def handle_nested(key):
            if type(doc[key]) is dict:
                self.flatten(key, doc[key], l_nested)
            elif type(doc[key]) is list:
                self.flatten_list(key, doc[key], l_nested)
            # Rewrite any field names found in the taxonomy as aliases
            elif key in l_field_aliases:
                doc[ l_field_aliases[key] ] = doc[key]
                del doc[key]
                key = l_field_aliases[key]
        map(handle_nested, doc.keys())

        def process_nested(key):
            # Rewrite any nested field names found in the taxonomy as aliases
            if key in l_field_aliases:
                doc[ l_field_aliases[key] ] = l_nested[key]
                del l_nested[key]
                key = l_field_aliases[key]
        map(process_nested, l_nested.keys())

        self.decorate(doc)

        if not set(doc.keys()).issuperset(self.standard_cols_set):
            self.log.error("Invalid ts col %s" % self.timestamp_col)
            return
        if doc[ self.timestamp_col ] is None:
            self.log.error("Invalid ts col %s" % self.timestamp_col)
            return
        l_ts = self.timestamp_formatter(doc)
        if l_ts < self.min_event_time:
            self.min_event_time = l_ts

        if l_ts > self.max_event_time:
            self.max_event_time = l_ts

        combined_fields = ",".join(sorted(doc.keys() + l_nested.keys()))
        class_id = 0
        try:
            class_id = self.classes[combined_fields]
        except KeyError:
            class_id = self.classes[combined_fields] = len(self.classes)
            if class_id > self.max_classes:
                raise SegmentFullException("Too many unique classes, class_id" +
                    " is a 12-bit int which limits total classes to 4096")
        composite_id = (class_id << 20) + self.id

        # Make these vars local to avoid the hash lookup necessary 
        #  for the attribute deref
        l_timestamp_col = self.timestamp_col
        l_splitter = self.splitter
        l_keywords = self.keywords
        l_non_stats_cols_set = self.non_stats_cols_set
        l_values = self.values
        l_docvals = self.docvals
        l_field_count = self.field_count
        l_field_type_map = self.field_type_map

        l_field_type_string = self.FIELD_TYPE_STRING
        l_field_type_numeric = self.FIELD_TYPE_NUMERIC
        l_field_type_ipv4 = self.FIELD_TYPE_IPv4

        # All code here is extremely expensive because it's done for 
        #  every field in every doc
        for field in doc:
            l_field_count += 1
            l_value = doc[field]
            if type(l_value) is dict or type(l_value) is list:
                continue
            try:
                field_type = l_field_type_map[field]
            except KeyError:
                try:
                    int(l_value)
                    field_type = l_field_type_map[field] = self.FIELD_TYPE_NUMERIC
                except ValueError:
                    if self.ipv4_check.match(l_value):
                        field_type = l_field_type_map[field] = self.FIELD_TYPE_IPv4
                    else:
                        field_type = l_field_type_map[field] = self.FIELD_TYPE_STRING
            try:
                l_value = str(l_value)
            except UnicodeEncodeError:
                l_value = str(l_value.encode("ascii", "ignore"))
            # Tokenize for inverted index
            if field_type == self.FIELD_TYPE_STRING:
                for token in l_splitter.split(l_value):
                    token = token.lower()
                    try:
                        l_keywords[token].append(composite_id)
                    except KeyError:
                        l_keywords[token] = list()
                        l_keywords[token].append(composite_id)
            else:
                try:
                    l_keywords[l_value].append(composite_id)
                except KeyError:
                    l_keywords[l_value] = list()
                    l_keywords[l_value].append(composite_id)
            
            # Record docvals and reporting stats
            if field in l_non_stats_cols_set:
                continue
            try:
                l_values[field][l_value] += 1
            except KeyError:
                l_values[field] = collections.Counter()
                l_values[field][l_value] += 1

            try:
                if field_type is l_field_type_string:
                    l_towrite = pack("L", (composite_id << 32) + hasher(l_value))
                    l_docvals[field].write(l_towrite)
                elif field_type is l_field_type_ipv4:
                    try:
                        l_towrite = pack("L", (composite_id << 32) + 
                            unpack("!I", inet_aton(l_value))[0])
                        l_docvals[field].write(l_towrite)
                    except Exception as e:
                        if str(e).count("inet_aton"):
                            # For whatever reason, this isn't really an IP
                            l_towrite = pack("L", (composite_id << 32) + 
                                hasher(l_value))
                            l_docvals[field].write(l_towrite)
                            #l_field_type_map[field] = l_field_type_string
                        else:
                            raise e
                elif field_type is l_field_type_numeric:
                    try:
                        l_towrite = pack("L", (composite_id << 32) + 
                            int(l_value))
                        l_docvals[field].write(l_towrite)
                    except:
                        # For whatever reason, this isn't really an int
                        l_towrite = pack("L", (composite_id << 32) + 
                            hasher(l_value))
                        l_docvals[field].write(l_towrite)
                        #l_field_type_map[field] = l_field_type_string
                else:
                    raise Exception("Field type not found for field %s" % 
                        field)
            except KeyError:
                l_docvals[field] = StringIO.StringIO()
                l_docvals[field].write(l_towrite)

        # Lots of redundant code here, but that's to save the overhead of a 
        #  function call plus the reassigments of the l_* values
        for field in l_nested:
            l_field_count += 1
            l_value = l_nested[field]
            
            try:
                field_type = l_field_type_map[field]
            except KeyError:
                try:
                    int(l_value)
                    field_type = l_field_type_map[field] = self.FIELD_TYPE_NUMERIC
                except ValueError:
                    if self.ipv4_check.match(l_value):
                        field_type = l_field_type_map[field] = self.FIELD_TYPE_IPv4
                    else:
                        field_type = l_field_type_map[field] = self.FIELD_TYPE_STRING
            try:
                l_value = str(l_value)
            except UnicodeEncodeError:
                l_value = str(l_value.encode("ascii", "ignore"))
            # Tokenize for inverted index
            if field_type == self.FIELD_TYPE_STRING:
                for token in l_splitter.split(l_value):
                    token = token.lower()
                    try:
                        l_keywords[token].append(composite_id)
                    except KeyError:
                        l_keywords[token] = list()
                        l_keywords[token].append(composite_id)
            else:
                try:
                    l_keywords[l_value].append(composite_id)
                except KeyError:
                    l_keywords[l_value] = list()
                    l_keywords[l_value].append(composite_id)
            
            # Record docvals and reporting stats
            if field in l_non_stats_cols_set:
                continue
            try:
                l_values[field][l_value] += 1
            except KeyError:
                l_values[field] = collections.Counter()
                l_values[field][l_value] += 1

            try:
                if field_type is l_field_type_string:
                    l_towrite = pack("L", (composite_id << 32) + 
                        hasher(l_value))
                    l_docvals[field].write(l_towrite)
                elif field_type is l_field_type_ipv4:
                    try:
                        l_towrite = pack("L", (composite_id << 32) + 
                            unpack("!I", inet_aton(l_value))[0])
                        l_docvals[field].write(l_towrite)
                    except Exception as e:
                        if str(e).count("inet_aton"):
                            # For whatever reason, this isn't really an IP
                            l_towrite = pack("L", (composite_id << 32) + 
                                hasher(l_value))
                            l_docvals[field].write(l_towrite)
                            #l_field_type_map[field] = l_field_type_string
                        else:
                            raise e
                elif field_type is l_field_type_numeric:
                    try:
                        l_towrite = pack("L", (composite_id << 32) + 
                            int(l_value))
                        l_docvals[field].write(l_towrite)
                    except:
                        # For whatever reason, this isn't really an int
                        l_towrite = pack("L", (composite_id << 32) + 
                            hasher(l_value))
                        l_docvals[field].write(l_towrite)
                        #l_field_type_map[field] = l_field_type_string
                else:
                    raise Exception("Field type not found for field %s" % 
                        field)
            except KeyError:
                l_docvals[field] = StringIO.StringIO()
                l_docvals[field].write(l_towrite)

        # Might want to revisit this. Currently, indexed data is modified to 
        #  include normalizations, with optional original saved.
        #  This is more costly than just writing the original to the 
        #  doc_db because of the serialization.
        doc["_ts"] = l_ts
        if self.keep_original:
            doc["_original"] = line
        self.dbs["doc"].put(str(composite_id), json.dumps(doc))

    def decorate(self, doc):
        # Just a placeholder at the moment
        #doc["_tags"] = {}
        for composite_fields in self.config["composite_fields"]:
            if set(doc.keys()).issuperset(composite_fields):
                key = "-".join(composite_fields)
                value = self.COMPOSITE_SEPARATOR.join([doc[x] for x in composite_fields])
                doc[key] = value

    # Finalize and write all to disk
    def close(self):
        self.dbs["doc"].close()
        sparkey.writehash(get_db_file(self.prefix, "doc", "hash"),
            get_db_file(self.prefix, "doc", "log"))
        self.timer.status("Collection")
        
        for class_buf in self.classes:
            self.dbs["classes"].put(str(self.classes[class_buf]), str(class_buf))
        self.dbs["classes"].close()
        sparkey.writehash(get_db_file(self.prefix, "classes", "hash"),
            get_db_file(self.prefix, "classes", "log"))
        self.timer.status("Wrote " + str(len(self.classes)) + " classes")
        
        topn = {}
        for field in self.values:
            self.dbs["stats"].put(str(field), json.dumps(self.values[field]))
        self.dbs["stats"].close()
        sparkey.writehash(get_db_file(self.prefix, "stats", "hash"),
            get_db_file(self.prefix, "stats", "log"))
        took = self.timer.status("Values write")
        
        for field in self.docvals:
            if self.docvals[field].getvalue() is not None:
                self.dbs["docvals"].put(str(field), self.docvals[field].getvalue())
        self.dbs["docvals"].close()
        sparkey.writehash(get_db_file(self.prefix, "docvals", "hash"),
            get_db_file(self.prefix, "docvals", "log"))
        self.timer.status("Docvals write")
        
        self.stats["total_fields"] = self.field_count
        self.stats["total_docs"] = self.id
        self.stats["total_classes"] = len(self.classes)
        self.stats["keywords"] = len(self.keywords)
        self.timer.stat_end("collect", self.id)
        self.log.debug("keywords: %d" % self.stats["keywords"])
        self.log.debug("docs: %d" % self.stats["total_docs"])
        
        self.timer.stat_start("idx_write")
        for k in self.keywords:
            self.dbs["idx"].put(str(k), marshal.dumps(self.keywords[k]))
        self.dbs["idx"].close()
        sparkey.writehash(get_db_file(self.prefix, "idx", "hash"),
            get_db_file(self.prefix, "idx", "log"))
        took = self.timer.status("Wrote index")
        self.timer.stat_end("idx_write", self.stats["keywords"])
        
        self.timer.stat_end("index", self.id)

    def meta_info(self):
        return {
            "start": self.min_event_time,
            "end": self.max_event_time,
            "count": self.id,
            "stats": self.stats,
            "performance": self.timer.stats
        }

def get_field_type_map(directory_file):
    type_map = dict()
    with sqlite3.connect(directory_file) as con:
        cur = con.cursor()
        cur.execute("SELECT * FROM field_type_map")
        for row in cur.fetchall():
            type_map[ row[0] ] = row[1]
    return type_map

def get_db_file(prefix, db_name, filetype):
    if filetype == "log":
        return prefix + "_" + db_name + ".log"
    elif filetype == "hash":
        return prefix + "_" + db_name + ".hash"
    else:
        raise Exception("Unknown db filetype %s" % filetype)