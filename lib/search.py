import os
import re
import sqlite3
import traceback
import marshal
import threading
import datetime
import copy
#import Queue as QQ

from struct import pack, unpack
from operator import itemgetter
from socket import inet_aton, inet_ntoa

from multiprocessing import Pool, Queue, Process, cpu_count
from time import *

import ujson as json

import sparkey

from utils import *
from segment import get_field_type_map, get_db_file, Segment

class SegmentSearcher(Logger, Utils):
    def __init__(self, config, prefix):
        self.keywords = {}
        self.timer = Timer()
        self.prefix = str(prefix)
        self.log.debug("Using prefix %s" % prefix)
        self.db_names = [ "idx", "doc", "stats", "classes", "docvals" ]
        self.dbs = {}
        for db in Segment.db_names:
            self.dbs[db] = sparkey.HashReader(
                get_db_file(self.prefix, db, "hash"),
                get_db_file(self.prefix, db, "log"))

        self.docvals = {}
        
        self.classes = {}
        for class_id, buf in self.dbs["classes"]:
            self.classes[int(class_id)] = buf.split(",")
        
        self.timestamp_col = config.get("timestamp_col", "_ts")
        self.timestamp_cols = frozenset([self.timestamp_col, "timestamp", "meta_ts"])
        self.standard_cols = [self.timestamp_col, "meta_rule", "class"]
        self.standard_cols_set = frozenset(self.standard_cols)
        self.non_stats_cols = ["rawmsg", "meta_cid", "meta_mid"]
        self.non_stats_cols_set = frozenset(self.non_stats_cols)
        
        self.msg_cache = {}
        
        self.default_limit = 100
        self.DEFAULT_MAX_LIMIT = 1000000
        self.default_sort = [ { "field": "_ts", "dir": "desc" } ]

        self.field_types = config["field_type_map"]

        self.numeric_ops = frozenset([">", "<", ">=", "<="])
        self.ops_forcing_introspection = frozenset(["contains", "=~", "!~"])

    def get_doc(self, id):
        # TODO: Reevaluate if msg_cache is really every useful.
        # if id not in self.msg_cache:
        #   try:
        #       self.msg_cache[id] = json.loads(self.doc_db.get(str(id)))
        #   except:
        #       self.log.error("Failed to get %s: %s" % (id, traceback.format_exc()))
        #       self.msg_cache[id] = {}
        # orig = self.msg_cache[id]
        # return orig
        try:
            return json.loads(self.dbs["doc"].get(str(id)))
        except:
            self.log.error("Failed to get %s: %s" % (id, traceback.format_exc()))
            return {}

    def known_fields(self, params):
        # Check a given search params hash to see if it can use docvals for acceleration
        ret = { "known": set(), "unknown": set() }
        fields = set()
        for class_name in self.classes:
            for field in self.classes[class_name]:
                fields.add(field)
        if params.has_key("filters"):
            for boolean in ["and", "or", "not"]:
                for filter_hash in params["filters"].get(boolean, []):
                    if filter_hash.has_key("filters"):
                        copy = dict(params)
                        copy["filters"] = dict(filter_hash["filters"])
                        recurse_ret = self.known_fields(copy)
                        ret.update(recurse_ret)
                    elif filter_hash["field"] not in fields:
                        ret["unknown"].add(filter_hash["field"])
                    else:
                        ret["known"].add(filter_hash["field"])
        if params.has_key("sort"):
            for sort_hash in params["sort"]:
                if sort_hash["field"] not in fields:
                    ret["unknown"].add(sort_hash["field"])
                else:
                    ret["known"].add(sort_hash["field"])
        if params.has_key("groupby"):
            for groupby in params["groupby"]:
                if groupby not in fields:
                    ret["unknown"].add(groupby)
                else:
                    ret["known"].add(groupby)
        return ret

    def get_fields(self, params):
        # Check a given search params hash to see if it can use docvals for acceleration
        fields = set()
        for class_name in self.classes:
            for field in self.classes[class_name]:
                fields.add(field)
        return dict.fromkeys(fields, 1)         

    def check_introspective_fields(self, filters):
        for boolean in filters:
            for filter_hash in filters[boolean]:
                if filter_hash.has_key("filters"):
                    return self.check_introspective_fields(filter_hash["filters"])
                if filter_hash["op"] in self.ops_forcing_introspection:
                    return True
        return False

    def search(self, params):
        ret = { "segment": self.prefix, "stats": [], "activities": [] }

        if params.has_key("groupby") and (params["groupby"] == "*" \
                or ((type(params["groupby"]) is list) and (params["groupby"][0] == "*"))):
            self.log.debug("Found groupby %s, forcing introspection" % params["groupby"])
            params["force_introspection"] = True
            params["groupby"] = "*"

        if params.has_key("groupby"):
            if type(params["groupby"]) is list:
                for groupby in params["groupby"]:
                    if groupby.count(","):
                        self.log.debug("Found compound groupby, forcing introspection.")
                        params["force_introspection"] = True
                        break
            elif type(params["groupby"]) is str and params["groupby"].count(","):
                self.log.debug("Found compound groupby, forcing introspection.")
                params["force_introspection"] = True
        
        if self.check_introspective_fields(params.get("filters", {})):
            self.log.debug("Found introspective fields, forcing introspection")
            params["force_introspection"] = True

        if not params.has_key("terms"):
            if not params.has_key("filters") and params.has_key("groupby")\
                and (not params.has_key("force_introspection") or params["groupby"] == "*"\
                    or params["groupby"] == "DISTINCT(*)"):
                is_fieldvalues = False
                for groupby in params["groupby"]:
                    if groupby.count(":"):
                        is_fieldvalues = True
                        break
                if is_fieldvalues:
                    ret.update(self.report_fieldvalues(params))
                else:
                    if params["groupby"] == "*":
                        copy = dict(params)
                        copy["groupby"] = self.get_fields(params)
                        ret.update(self.report_field(copy))
                    elif params["groupby"] == "DISTINCT(*)":
                        copy = dict(params)
                        copy["groupby"] = self.get_fields(params)
                        #ret.update(self.report_field_distinct_count(copy))
                        ret.update(self.report_field(copy))
                    else:
                        if type(params["groupby"]) is not list:
                            params["groupby"] = [ params["groupby"] ]
                        ret.update(self.report_field(params))
                ret["stats"] = self.timer.stats
                ret["activities"] = self.timer.activities
                return ret

        ids = set()
        if params.has_key("terms"):
            ids = self.get_term_hits(params)
            if len(ids) < 1:
                self.log.debug("No hits")
                return ret

            ids = self.filter_hits(params, ids)
            if len(ids) < 1:
                self.log.debug("All results filtered")
                return ret
        # Scan
        elif not params.has_key("filters") and not params.has_key("groupby"):
            for id, _ in self.dbs["doc"]:
                ids.add(int(id))

        if params.get("force_introspection", False) is True:
            self.log.debug("Forcing introspection at user request")
            results = self.get_results_via_introspection(params, ids)
        else:
            known_fields = self.known_fields(params)
            if len(ids) == 0 or len(known_fields["unknown"]) > 0:
                self.log.debug("No results filtered")
                results = self.get_results_via_introspection(params, ids)
            else:
                results = self.get_results_via_docvals(params, ids)
        
        ret.update(results)
        ret["stats"] = self.timer.stats
        ret["activities"] = self.timer.activities

        return ret

    def get_term_hits(self, params):
        result_set = set()
        for term in params["terms"].get("and", []):
            buf = self.dbs["idx"].get(term.lower())
            if buf is None:
                continue
            term_result_set = set(marshal.loads(buf))
            if not len(result_set):
                result_set = term_result_set
            else:
                result_set = term_result_set & result_set

        for term in params["terms"].get("or", []):
            buf = self.dbs["idx"].get(term.lower())
            if buf is None:
                continue
            term_result_set = set(marshal.loads(buf))
            if not len(result_set):
                result_set = term_result_set
            else:
                result_set = term_result_set | result_set

        for term in params["terms"].get("not", []):
            buf = self.dbs["idx"].get(term.lower())
            if buf is None:
                continue
            term_result_set = set(marshal.loads(buf))
            if len(result_set):
                result_set = result_set - term_result_set
            else:
                for id, _ in self.dbs["doc"]:
                    if id not in term_result_set:
                        result_set.add(int(id))


        self.timer.status("Got " + str(len(result_set)) + " ids")

        return result_set

    def filter_hits(self, params, result_set):

        filter_fields = set()
        if params.has_key("groupby") and params["groupby"] != "*":
            for groupby in params["groupby"]:
                terms = groupby.split(",")
                for term in terms:
                    filter_fields.add(term)

        if params.has_key("filters"):
            for boolean in ["and", "or", "not"]:
                for filter_hash in params["filters"].get(boolean, []):
                    if filter_hash.has_key("filters"):
                        copy = dict(params)
                        copy["filters"] = dict(filter_hash["filters"])
                        self.filter_hits(copy, result_set)
                        continue
                    filter_fields.add(filter_hash.get("field"))

        if len(filter_fields):
            # Find classes which have the field
            field_set = set()
            for filter_field in filter_fields:
                classes_with_field = set()
                for class_id in self.classes:
                    if filter_field in self.classes[class_id]:
                        classes_with_field.add(class_id)
                if len(classes_with_field) < 1:
                    self.log.debug(self.classes)
                    raise Exception("Filter field %s not found in any doc" % filter_field)
                if len(field_set):
                    field_set = field_set.intersection(classes_with_field)
                else:
                    field_set = classes_with_field
            
            filtered_set = set()
            for id in result_set:
                class_id = id >> 20
                if class_id in field_set:
                    filtered_set.add(id)
            self.timer.status("Filtered " + str(len(result_set) - len(filtered_set)))
            result_set = filtered_set

        return result_set

    def get_results_via_docvals(self, params, result_set):
        ret = {}
        
        self.log.debug("getting %d results via docvals" % len(result_set))
        self.timer.stat_start("filter_by_docval")
        if params.has_key("filters"):
            self.filter_by_docval(params, result_set)
        if not len(result_set):
            self.log.debug("All results filtered by docvals")
            return ret

        self.timer.stat_start("count")
        if params.has_key("groupby"):
            ret["ordinal_by_id"] = {}
            ret["ordinal_groupby"] = {}
            self.timer.stat_start("docval_group")
            
            for groupby in params["groupby"]:
                ret["ordinal_groupby"][groupby] = {}
                def unpack_long(buf):
                    id = buf >> 32
                    if id in result_set:
                        ordinal = buf & 0xffffffff
                        ret["ordinal_by_id"][ordinal] = id
                        try:
                            ret["ordinal_groupby"][groupby][ordinal] += 1
                        except KeyError:
                            ret["ordinal_groupby"][groupby][ordinal] = 1
                buf = self.dbs["docvals"].get(groupby)
                if buf is None:
                    raise Exception("Groupby field %s not found" % groupby)
                map(unpack_long, unpack(str(len(buf)/8) + "L", buf))

                # Apply sorting/limit
                ret["ordinal_groupby"][groupby] = dict(sorted(ret["ordinal_groupby"][groupby].iteritems(), 
                    key=itemgetter(1), reverse=params.get("sort_reverse", True))[0:params.get("limit", 100)])

                # Attach the required CRC"s that remain after the limit has been applied
                ordinals_required = set()
                for ordinal_groupby in ret["ordinal_groupby"]:
                    for ordinal in ret["ordinal_groupby"][ordinal_groupby]:
                        ordinals_required.add(ordinal)
                for ordinal in ret["ordinal_by_id"].keys():
                        if ordinal not in ordinals_required:
                            del ret["ordinal_by_id"][ordinal]

                self.timer.status("Collected and sorted groupby %s" % groupby)
            
            self.timer.status("Grouped via docvals")
            self.timer.stat_end("docval_group", len(result_set))
        else:
            if params.has_key("sort"):
                result_set = self.sort_by_docval(params, result_set, 
                    params["sort"][0]["field"])
            ret["results"] = list()
            for id in result_set:
                ret["results"].append(self.get_doc(id))

        took = self.timer.status("Counted")
        self.timer.stat_end("count", len(result_set))
        
        return ret

    def resolve_ordinals(self, results, ordinal_id_tuples):
        self.timer.stat_start("ordinal_resolve")
        docs = {}
        ordinal_by_id = {}
        for tup in ordinal_id_tuples:
            doc = self.get_doc(tup[1])
            docs[ int(tup[1]) ] = doc
            ordinal_by_id[ tup[0] ] = tup[1]
        self.timer.status("Retrieved %d docs in segment %s for ordinal resolving" % (len(docs), self.prefix))

        if results.has_key("ordinal_groupby"):
            for groupby in results["ordinal_groupby"]:
                if not results["groupby"].has_key(groupby):
                    results["groupby"][groupby] = {}
                for ordinal in results["ordinal_groupby"][groupby].keys():
                    if ordinal not in ordinal_by_id:
                        continue
                    try:
                        doc = docs[ ordinal_by_id[ordinal] ]
                        if groupby.count("."):
                            this_level = doc
                            for level in groupby.split("."):
                                this_level = this_level[level]
                            results["groupby"][groupby][this_level] = results["ordinal_groupby"][groupby][ordinal]
                        else:
                            results["groupby"][groupby][ doc[groupby] ] = results["ordinal_groupby"][groupby][ordinal]

                        del results["ordinal_groupby"][groupby][ordinal]
                    except Exception as e:
                        traceback.print_exc()
                        self.log.error("Error %s, no ordinal found for groupby " +
                            "%s ordinal %s docid %s" % (repr(e), 
                                groupby, ordinal, ordinal_by_id[ordinal]))
        self.timer.status("Resolved ordinal's")
        self.timer.stat_end("ordinal_resolve", len(docs))

    def sort_by_docval(self, params, result_set, field):
        params_limit = params.get("limit", self.default_limit)
        if params_limit is None:
            params_limit = self.DEFAULT_MAX_LIMIT
        topn = params_limit + params.get("offset", 0)
        sort_field = params.get("sort", self.default_sort)[0]["field"]
        sort_dir = params.get("sort", self.default_sort)[0]["dir"]
        heap = list()
        def f(k):
            if k >> 32 in result_set:
                heapq.heappush(heap, k & 0xffffffff, k >> 32)
        buf = self.docvals_db.get(field)
        if buf is None:
            raise Exception("Field %s not found for sorting" % field)
        map(f, unpack(str(len(buf)/8) + "L", buf))
        if sort_dir == "desc":
            return map(lambda x: x[1], heapq.nlargest(topn, heap))
        else:
            return map(lambda x: x[1], heapq.nsmallest(topn, heap))
        
    def filter_by_docval(self, params, result_set, is_recurse=False):
        if not is_recurse:
            self.timer.stat_start("filter_by_docval")
        orig_len = len(result_set)
        self.log.debug("filtering %d results" % orig_len)
        for boolean in ["and", "not"]:
            for filter_hash in params["filters"].get(boolean, []):
                if filter_hash.has_key("filters"):
                    copy = dict(params)
                    params["filters"] = dict(filter_hash)
                    self.filter_by_docval(copy, result_set, is_recurse=True)
                    continue
                before_len = len(result_set)
                self.timer.stat_start("filter %s%s%s" % (filter_hash["field"], 
                    filter_hash["op"], filter_hash["value"]))
                buf = self.dbs["docvals"].get(filter_hash["field"])
                if buf is None:
                    continue
                
                l_field = filter_hash["field"]
                if self.field_types[l_field] == self.FIELD_TYPE_IPv4:
                    test_value = unpack("!I", inet_aton(filter_hash["value"]))
                    test_value = test_value[0]
                elif self.field_types[l_field] == self.FIELD_TYPE_NUMERIC:
                    test_value = int(filter_hash["value"])
                else:
                    test_value = hasher(filter_hash["value"])
                for composite_id in unpack(str(len(buf)/8) + "L", buf):
                    id = composite_id >> 32
                    value = composite_id & 0xffffffff
                    if id in result_set:
                        if boolean == "not":
                            if self.filter_test(value, test_value, filter_hash["op"]):
                                result_set.remove(id)
                        else:
                            if not self.filter_test(value, test_value, filter_hash["op"]):
                                result_set.remove(id)
                
                self.timer.stat_end("filter %s%s%s" % (filter_hash["field"], 
                    filter_hash["op"], filter_hash["value"]), before_len)
        
            if params["filters"].has_key("or"):
                or_set = set()
                for filter_hash in params["filters"]["or"]:
                    if filter_hash.has_key("filters"):
                        # Recurse
                        copy = dict(params)
                        copy["filters"] = dict(filter_hash["filters"])
                        result_copy = set(result_set)
                        self.filter_by_docval(copy, result_copy, True)
                        or_set.update(result_copy)
                    else:
                        before_len = len(result_set)
                        self.timer.stat_start("filter %s%s%s" % 
                            (filter_hash["field"], filter_hash["op"], filter_hash["value"]))
                        buf = self.dbs["docvals"].get(filter_hash["field"])
                        if buf is None:
                            raise Exception("Docval field %s not found" % filter_hash["field"])
                        
                        l_field = filter_hash["field"]
                        if self.field_types[l_field] == self.FIELD_TYPE_IPv4:
                            test_value = unpack("!I", inet_aton(filter_hash["value"]))
                            test_value = test_value[0]
                        else:
                            test_value = int(filter_hash["value"])
                        for composite_id in unpack(str(len(buf)/8) + "L", buf):
                            id = composite_id >> 32
                            value = composite_id & 0xffffffff
                            if id in result_set:
                                if self.filter_test(value, test_value, filter_hash["op"]):
                                    or_set.add(id)
                        self.timer.stat_end("filter %s%s%s" % (filter_hash["field"], 
                            filter_hash["op"], filter_hash["value"]), before_len)
                result_set.intersection_update(or_set)

        if not is_recurse:
            self.timer.stat_end("filter_by_docval", orig_len)

    def get_ids(self, params, ids, queue, db, sample_rate):
        chunk = list()
        limit = 50
        counter = 0

        if len(ids):
            if (len(ids) / sample_rate) > limit:
                # Preload entire file into RAM cache. 
                # This is faster than without because the read is sequential instead of random (which happens next with the db.gets) within the file.
                self.log.debug("Prewarming cache")
                self.timer.stat_start("prewarm")
                with open("/dev/null", "w") as devnull:
                    devnull.write(open(get_db_file(self.prefix, "doc", "log")).read())
                self.timer.stat_end("prewarm", 1)
            
            for id in ids:
                if id % sample_rate == 0:
                    try:
                        doc = db.get(str(id))                           
                        chunk.append([id,doc])
                        if len(chunk) >= limit:
                            queue.put(chunk)
                            chunk = list()
                        counter += 1
                    except Exception as e:
                        self.log.error("Failed to get id %d: %s\n%s" % 
                            (id, e, traceback.format_exc()))
                if params.get("groupby") is None and counter > params.get("limit", 100):
                    break
        else:
            for id, doc in db:
                if int(id) % sample_rate == 0:
                    try:
                        chunk.append([id,doc])
                        if len(chunk) >= limit:
                            queue.put(chunk)
                            chunk = list()
                        counter += 1
                    except Exception as e:
                        self.log.error("Failed to get id %d: %s\n%s" % 
                            (id, e, traceback.format_exc()))
                if params.get("groupby") is None and counter > params.get("limit", 100):
                    break
    
        if len(chunk) > 0:
            queue.put(chunk)
        queue.put("STOP")

    # Retrieve the full doc and open it up to get field data. Very expensive. Prewarming the index helps significantly, but pollutes the disk cache.
    def get_results_via_introspection(self, params, result_set):
        ret = {}
        self.timer.stat_start("get_by_introspection")
        self.log.debug("Filtering %d results" % len(result_set))

        # Speed up groupby queries requesting many docs by sampling
        sample_rate = int(params.get("sample_rate", 1))
        if len(result_set) > 0 and sample_rate > len(result_set):
            raise Exception("Invalid sample_rate %d given for number of " +
                "docs to process %d" % (sample_rate, len(result_set)))
        if not params.get("no_sample", False) and len(result_set) > 1000 \
            and params.get("groupby") is not None:
            sample_rate = int(len(result_set) / int(params.get("sample_rate_ratio", 10000))) + 1
        self.log.debug("sample rate %d" % sample_rate)

        doc_queue = Queue()
        
        thread = threading.Thread(target=self.get_ids, args=(params, 
            result_set, doc_queue, self.dbs["doc"], sample_rate))
        thread.start()

        if params.has_key("groupby"):
            ret["groupby"] = {}
            if params["groupby"] == "*":
                for chunk in iter(doc_queue.get, "STOP"):
                    for tup in chunk:
                        doc = json.loads(tup[1])
                        l_nested = {}
                        for key in doc:
                            if type(doc[key]) is dict:
                                self.flatten(key, doc[key], l_nested)
                        doc.update(l_nested)
                        if self.filter_match(params, doc):
                            for groupby in doc:
                                if groupby in self.timestamp_cols \
                                    or groupby in self.non_stats_cols \
                                    or type(doc[groupby]) is dict:
                                    continue
                                try:
                                    ret["groupby"][groupby][ doc[groupby] ] += sample_rate
                                except KeyError:
                                    if not ret["groupby"].has_key(groupby):
                                        ret["groupby"][groupby] = {}
                                    ret["groupby"][groupby][ doc[groupby] ] = sample_rate
                            doc["id"] = tup[0]
            else:
                
                for groupby in params["groupby"]:
                    ret["groupby"][groupby] = {}
                for chunk in iter(doc_queue.get, "STOP"):
                    for tup in chunk:
                        doc = json.loads(tup[1])
                        l_nested = {}
                        for key in doc:
                            if type(doc[key]) is dict:
                                self.flatten(key, doc[key], l_nested)
                        doc.update(l_nested)
                        if self.filter_match(params, doc):
                            doc["id"] = tup[0]
                            for groupby in params["groupby"]:
                                terms = groupby.split(",")
                                next = False
                                for term in terms:
                                    # Verify that this event will have the desired field
                                    if term not in doc:
                                        #self.log.error("Field does not contain groupby %s" % groupby)
                                        next = True
                                        break
                                if next:
                                    continue
                                value = ",".join(map(str, [doc[x] for x in terms]))
                                try:
                                    ret["groupby"][groupby][value] += sample_rate
                                except KeyError:
                                    ret["groupby"][groupby][value] = sample_rate
            # Apply sorting/limit
            for groupby in ret["groupby"]:
                ret["groupby"][groupby] = dict(sorted(ret["groupby"][groupby].iteritems(), 
                    key=itemgetter(1), reverse=params.get("sort_reverse", True))[0:params.get("limit", 100)])
        else:
            ret["results"] = list()
            for chunk in iter(doc_queue.get, "STOP"):
                for tup in chunk:
                    doc = json.loads(tup[1])
                    if self.filter_match(params, doc):
                        doc["id"] = tup[0]
                        ret["results"].append(doc)

        thread.join()

        took = self.timer.status("Get by introspection")
        self.timer.stat_end("get_by_introspection", len(result_set))
        
        return ret

    def filter_test(self, doc_value, test_value, op):
        if (type(test_value) is int or op in self.numeric_ops) \
            and type(doc_value) is not int:
            try:
                doc_value = int(doc_value)
            except:
                return False
        if op == "=":
            if doc_value != test_value:
                return False
        elif op == "!=":
            if doc_value == test_value:
                return False
        elif op == "=~":
            f = re.compile(test_value)
            if not f.match(doc_value):
                return False
        elif op == "!~":
            f = re.compile(test_value)
            if f.match(doc_value):
                return False
        elif op == "contains":
            #self.log.debug("checking value " + doc_value + " against " + test_value)
            if not doc_value.count(test_value):
                return False
        elif op == ">":
            try:
                if not doc_value > test_value:
                    return False
            except:
                return False
        elif op == "<":
            try:
                if not doc_value < test_value:
                    return False
            except:
                return False
        elif op == ">=":
            try:
                if not doc_value >= test_value:
                    return False
            except:
                return 
        elif op == "<=":
            try:
                if not doc_value <= test_value:
                    return False
            except:
                return False
        else:
            raise Exception("Unknown op " + op)
        return True

    def filter_match(self, params, doc):
        if params.has_key("filters"):
            
            for filter_hash in params["filters"].get("and", []):
                if not doc.has_key(filter_hash["field"]):
                    return False
                if self.field_types[ filter_hash["field"] ] == self.FIELD_TYPE_IPv4 \
                    and filter_hash["op"] in self.numeric_ops:
                    value = unpack("!I", inet_aton(doc[ filter_hash["field"] ]))[0]
                    test_value = unpack("!I", inet_aton(filter_hash["value"]))[0]
                else:
                    value = doc[ filter_hash["field"] ]
                    test_value = filter_hash["value"]
                if not self.filter_test(value, test_value, filter_hash["op"]):
                    return False

            for filter_hash in params["filters"].get("not", []):
                if not doc.has_key(filter_hash["field"]):
                    return True
                if self.field_types[ filter_hash["field"] ] == self.FIELD_TYPE_IPv4 \
                    and filter_hash["op"] in self.numeric_ops:
                    value = unpack("!I", inet_aton(doc[ filter_hash["field"] ]))[0]
                    test_value = unpack("!I", inet_aton(filter_hash["value"]))[0]
                else:
                    value = doc[ filter_hash["field"] ]
                    test_value = filter_hash["value"]
                if self.filter_test(value, test_value, filter_hash["op"]):
                    return False

            if params["filters"].has_key("or"):
                for filter_hash in params["filters"]["or"]:
                    if filter_hash.has_key("filters"):
                        # Recurse
                        copy = dict(params)
                        copy["filters"] = dict(filter_hash["filters"])
                        if self.filter_match(copy, doc):
                            return True
                    elif self.filter_match(copy, doc):
                        return True
                return False
        return True

    def report_field(self, params):
        ret = { "groupby": {} }
        try:
            for field in params.get("groupby"):
                ret["groupby"][field] = {}
                self.timer.stat_start("field " + field)
                data = self.dbs["stats"].get(field)
                if data is None:
                    continue
                field_data = json.loads(data)
                for field_value in field_data:
                    try:
                        ret["groupby"][field][field_value] += field_data[field_value]
                    except KeyError:
                        ret["groupby"][field][field_value] = field_data[field_value]
                self.timer.stat_end("field " + field, len(field_data))
        except Exception as e:
            self.log.error(traceback.format_exc())
        took = self.timer.status("Field report")
        return ret

    def report_field_distinct_count(self, params):
        ret = { "groupby": {} }
        try:
            for field in params.get("groupby"):
                self.log.debug("distinct on field " + field)
                ret["groupby"][field] = {}
                self.timer.stat_start("field " + field)
                data = self.dbs["stats"].get(field)
                if data is None:
                    continue
                field_data = json.loads(data)
                if field == "srcipv4":
                    self.log.debug("srcipv4 keys: %r" % field_data.keys())
                    self.log.debug("srcipv4 keys length: %d" % len(field_data.keys()))
                ret["groupby"][field] = { "DISTINCT(*)": len(field_data.keys()) }
                self.timer.stat_end("field " + field, len(field_data))
        except Exception as e:
            self.log.error(traceback.format_exc())
        took = self.timer.status("Distinct field report")
        return ret

    def report_fieldvalues(self, params):
        ret = { "groupby": {} }
        for fieldvalue in params["groupby"]:
            field, value = fieldvalue.split(":", 1)
            ret["groupby"][fieldvalue] = {}
            if value[0] == "*":
                value = value.lstrip("*")
                value = ".*" + value
            if value[-1] == "*":
                value = value.rstrip("*")
                value = value + ".*"
            self.timer.stat_start("field " + field)
            field_data = json.loads(self.dbs["stats"].get(field))
            for field_value in field_data:
                if re.match(value, field_value):
                    if ret.has_key(field_value):
                        ret["groupby"][fieldvalue][field_value] += field_data[field_value]
                    else:
                        ret["groupby"][fieldvalue][field_value] = field_data[field_value]
            self.timer.stat_end("field " + field, len(field_data))
        took = self.timer.status("Fieldvalues report")
        return ret

class Searcher(Logger):
    def __init__(self, config):
        #self.log = self._log_init_name("searcher")
        self.dir = config.get("dir", "/tmp/oak")
        self.prefix = config.get("prefix", "oak_")
        self.directory_file = self.dir + "/" + self.prefix + "directory"
        if not os.path.exists(self.directory_file):
            raise Exception("Directory file not present: %s" % self.directory_file)

        self.default_sort = [ { "field": "_ts", "dir": "desc" } ]

        self.num_workers = cpu_count() * 3
        self.config = config
        self.config["field_type_map"] = get_field_type_map(self.directory_file)
        self.composite_separator = Segment.COMPOSITE_SEPARATOR

    def iter(self, params):
        self.log.info("Searching for terms %s" % (params.get("terms", {})))
        def spawn_worker(segment_queue, queue, params):
            for prefix in iter(segment_queue.get, "STOP"):
                try:
                    segment_searcher = SegmentSearcher(self.config, prefix)
                    if params.get("meta") == "field_report":
                        results = { 
                            "stats": [], 
                            "activities": [], 
                            "results": {}, 
                            "meta": { "fields": segment_searcher.get_fields(params) } 
                        }
                    else:
                        results = segment_searcher.search(params)
                    queue.put(results)
                except Exception as e:
                    self.log.error("Error on prefix %s: %s\n%s" % (prefix, e, traceback.format_exc()))
            queue.put("STOP")
        
        if not params.has_key("start"):
            params["start"] = 0
        if not params.has_key("end"):
            params["end"] = time()
        if params["start"] > params["end"]:
            raise Exception("Invalid start/end: %s %s" % 
                (params["start"], params["end"]))
        self.log.debug("Searching times %s through %s" %
            (datetime.datetime.fromtimestamp(params["start"]), 
                datetime.datetime.fromtimestamp(params["end"])))

        self.procs = list()
        con = sqlite3.connect(self.directory_file)
        files = dict()
        with con:
            cur = con.cursor()
            cur.execute("SELECT filename, count FROM directory WHERE " +
                "(start >= ? AND end <= ?) OR (start >= ? AND end <=?)" +
                " OR (start >= ? AND end <= ?) OR (start <= ? AND end >= ?)" +
                " ORDER BY end DESC",
                (params["start"], params["start"], params["end"], params["end"],
                params["start"], params["end"], params["start"], params["end"]))
            for row in cur.fetchall():
                files[ row[0] ] = row[1]
        total_segments = len(files)
        total_to_search = sum(map(itemgetter(1), files.iteritems()))
        self.log.debug("Searching total of %d docs" % total_to_search)

        # Start workers to pull segments off the queue to process
        queue = Queue()
        segment_queue = Queue()
        for i in range(self.num_workers):
            proc = Process(target=spawn_worker, args=(segment_queue, queue, params))
            proc.start()
            self.procs.append(proc)

        # Send all segments to the queue
        map(segment_queue.put, files)

        # Add a sentinel for each worker
        for i in range(self.num_workers):
            segment_queue.put("STOP")

        overall_results = { "stats": [], "activities": [] }
        ordinals = {}
        results_back = 0
        sort_dir = params.get("sort", self.default_sort)[0]["dir"]
        if sort_dir == "desc":
            sort_dir = True
        else:
            sort_dir = False
        limit = params.get("limit", 100)
        search_start_time = time()

        if params.has_key("direct_results"):
            for t in self.procs:
                for results in iter(queue.get, "STOP"):
                    result = results.get("results", [])
                    if result:
                        results_back += len(result)
                        yield result[0:limit]
                        self.log.debug('results back: %d' % results_back)
                        if results_back >= limit:
                            self.log.debug("hit limit")
                            break        
                if results_back >= limit:
                    break

            # clear the segment_queue to stop
            self.log.debug("clearing queue")
            while not segment_queue.empty():
                segment_queue.get()
            for i in range(self.num_workers):
                segment_queue.put("STOP")
            self.log.debug("cleared segment queue")
            for t in self.procs:
                t.terminate()
                t.join()
            self.log.debug("all done")
            return
        else:
            overall_results = { "stats": [], "activities": [] }
            ordinals = {}
            results_back = 0
            sort_dir = params.get("sort", self.default_sort)[0]["dir"]
            if sort_dir == "desc":
                sort_dir = True
            else:
                sort_dir = False
            limit = params.get("limit", 100)

            for t in self.procs:
                for results in iter(queue.get, "STOP"):
                    results_back += 1
                    self.log.info("Percentage complete: %f" % 
                        (float(results_back)/total_segments))
                    overall_results["percentage_complete"] = (float(results_back)/total_segments)
                    overall_results["stats"].extend(results["stats"])
                    overall_results["activities"].extend(results["activities"])
                    if results.has_key("meta"):
                        if not overall_results.has_key("meta"):
                            overall_results["meta"] = {}
                        for meta in results["meta"]:
                            if not overall_results["meta"].has_key(meta):
                                overall_results["meta"][meta] = {}
                            for k in results["meta"][meta]:
                                try:
                                    overall_results["meta"][meta][k] += results["meta"][meta][k]
                                except KeyError:
                                    overall_results["meta"][meta][k] = results["meta"][meta][k]
                    if results.has_key("ordinal_groupby"):
                        if not overall_results.has_key("ordinal_groupby"):
                            overall_results["ordinal_groupby"] = {}
                        og = overall_results["ordinal_groupby"]
                        rg = results["ordinal_groupby"]
                        for groupby in rg:
                            for k in rg[groupby]:
                                if not og.has_key(groupby):
                                    og[groupby] = {}
                                if og[groupby].has_key(k):
                                    og[groupby][k] += rg[groupby][k]
                                else:
                                    og[groupby][k] = rg[groupby][k]
                        # Collect ordinal"s to resolve
                        for ordinal in results["ordinal_by_id"]:
                            if ordinal not in ordinals:
                                ordinals[ordinal] = (results["segment"], results["ordinal_by_id"][ordinal])
                    elif results.has_key("groupby"):
                        if not overall_results.has_key("groupby"):
                            overall_results["groupby"] = {}
                        og = overall_results["groupby"]
                        rg = results["groupby"]
                        for groupby in rg:
                            for k in rg[groupby]:
                                if not og.has_key(groupby):
                                    og[groupby] = {}
                                if og[groupby].has_key(k):
                                    og[groupby][k] += rg[groupby][k]
                                else:
                                    og[groupby][k] = rg[groupby][k]
                    else:
                        if not overall_results.has_key("results"):
                            overall_results["results"] = list()
                        overall_results["results"].extend(results.get("results", []))
                
                    tmp_results = {
                        "time_taken": (time() - search_start_time),
                        "percentage_complete": overall_results["percentage_complete"]
                    }
                    if results.has_key("groupby"):
                        # Apply sorting/limit
                        tmp_results["groupby"] = {}
                        for groupby in overall_results["groupby"]:
                            tmp_results["groupby"][groupby] = dict(sorted(overall_results["groupby"][groupby].iteritems(), 
                                key=itemgetter(1), reverse=params.get("sort_reverse", True))[0:limit])
                        yield tmp_results
                    else:
                        tmp_results["results"] = list(sorted(overall_results["results"], 
                            key=itemgetter(params.get("sort", self.default_sort)[0]["field"]), 
                            reverse=sort_dir))[0:limit]
                        yield tmp_results

    def search(self, params):
        self.log.info("Searching for terms %s" % (params.get("terms", {})))
        def spawn_worker(segment_queue, queue, params):
            for prefix in iter(segment_queue.get, "STOP"):
                try:
                    segment_searcher = SegmentSearcher(self.config, prefix)
                    if params.get("meta") == "field_report":
                        results = { 
                            "stats": [], 
                            "activities": [], 
                            "results": {}, 
                            "meta": { "fields": segment_searcher.get_fields(params) } 
                        }
                    else:
                        results = segment_searcher.search(params)
                    queue.put(results)
                except Exception as e:
                    self.log.error("Error on prefix %s: %s\n%s" % (prefix, e, traceback.format_exc()))
            queue.put("STOP")
        
        if not params.has_key("start"):
            params["start"] = 0
        if not params.has_key("end"):
            params["end"] = time()
        if params["start"] > params["end"]:
            raise Exception("Invalid start/end: %s %s" % 
                (params["start"], params["end"]))
        self.log.debug("Searching times %s through %s" %
            (datetime.datetime.fromtimestamp(params["start"]), 
                datetime.datetime.fromtimestamp(params["end"])))

        self.procs = list()
        con = sqlite3.connect(self.directory_file)
        files = dict()
        with con:
            cur = con.cursor()
            cur.execute("SELECT filename, count FROM directory WHERE " +
                "(start >= ? AND end <= ?) OR (start >= ? AND end <=?)" +
                " OR (start >= ? AND end <= ?) OR (start <= ? AND end >= ?)" +
                " ORDER BY end DESC",
                (params["start"], params["start"], params["end"], params["end"],
                params["start"], params["end"], params["start"], params["end"]))
            for row in cur.fetchall():
                files[ row[0] ] = row[1]
        total_segments = len(files)
        total_to_search = sum(map(itemgetter(1), files.iteritems()))
        self.log.debug("Searching total of %d docs" % total_to_search)

        # Start workers to pull segments off the queue to process
        queue = Queue()
        segment_queue = Queue()
        for i in range(self.num_workers):
            proc = Process(target=spawn_worker, args=(segment_queue, queue, params))
            proc.start()
            self.procs.append(proc)

        # Send all segments to the queue
        map(segment_queue.put, files)

        # Add a sentinel for each worker
        for i in range(self.num_workers):
            segment_queue.put("STOP")

        overall_results = { "stats": [], "activities": [] }
        ordinals = {}
        results_back = 0
        sort_dir = params.get("sort", self.default_sort)[0]["dir"]
        if sort_dir == "desc":
            sort_dir = True
        else:
            sort_dir = False
        limit = params.get("limit", 100)
        search_start_time = time()

        for t in self.procs:
            for results in iter(queue.get, "STOP"):
                results_back += 1
                self.log.info("Percentage complete: %f" % 
                    (float(results_back)/total_segments))
                overall_results["percentage_complete"] = (float(results_back)/total_segments)
                overall_results["stats"].extend(results["stats"])
                overall_results["activities"].extend(results["activities"])
                if results.has_key("meta"):
                    if not overall_results.has_key("meta"):
                        overall_results["meta"] = {}
                    for meta in results["meta"]:
                        if not overall_results["meta"].has_key(meta):
                            overall_results["meta"][meta] = {}
                        for k in results["meta"][meta]:
                            try:
                                overall_results["meta"][meta][k] += results["meta"][meta][k]
                            except KeyError:
                                overall_results["meta"][meta][k] = results["meta"][meta][k]
                if results.has_key("ordinal_groupby"):
                    if not overall_results.has_key("ordinal_groupby"):
                        overall_results["ordinal_groupby"] = {}
                    og = overall_results["ordinal_groupby"]
                    rg = results["ordinal_groupby"]
                    for groupby in rg:
                        for k in rg[groupby]:
                            if not og.has_key(groupby):
                                og[groupby] = {}
                            if og[groupby].has_key(k):
                                og[groupby][k] += rg[groupby][k]
                            else:
                                og[groupby][k] = rg[groupby][k]
                    # Collect ordinal"s to resolve
                    for ordinal in results["ordinal_by_id"]:
                        if ordinal not in ordinals:
                            ordinals[ordinal] = (results["segment"], results["ordinal_by_id"][ordinal])
                elif results.has_key("groupby"):
                    if not overall_results.has_key("groupby"):
                        overall_results["groupby"] = {}
                    og = overall_results["groupby"]
                    rg = results["groupby"]
                    for groupby in rg:
                        for k in rg[groupby]:
                            if not og.has_key(groupby):
                                og[groupby] = {}
                            if og[groupby].has_key(k):
                                og[groupby][k] += rg[groupby][k]
                            else:
                                og[groupby][k] = rg[groupby][k]
                else:
                    if not overall_results.has_key("results"):
                        overall_results["results"] = list()
                    overall_results["results"].extend(results.get("results", []))
                        
        for t in self.procs:
            t.join()

        overall_results["final"] = True

        # Resolve ordinal"s
        if len(ordinals):
            segments = {}
            overall_results["groupby"] = {}
            for ordinal in ordinals:
                segment = ordinals[ordinal][0]
                id = ordinals[ordinal][1]
                if not segments.has_key(segment):
                    segments[segment] = list()
                segments[segment].append((ordinal,id))
            for segment in segments:
                segment_searcher = SegmentSearcher(self.config, segment)
                segment_searcher.resolve_ordinals(overall_results, segments[segment])
                overall_results["stats"].extend(segment_searcher.timer.stats)
            del overall_results["ordinal_groupby"]

        if params.has_key("groupby"):
            if not overall_results.has_key("groupby"):
                overall_results["groupby"] = {}
            # Handle DISTINCT
            elif params["groupby"] == "DISTINCT(*)":
                for groupby in overall_results["groupby"]:
                    overall_results["groupby"][groupby] = { "DISTINCT": len(overall_results["groupby"][groupby]) }
            else:
                # Apply sorting/limit
                for groupby in overall_results["groupby"]:
                    overall_results["groupby"][groupby] = dict(sorted(overall_results["groupby"][groupby].iteritems(), 
                        key=itemgetter(1), reverse=params.get("sort_reverse", True))[0:limit])
        else:
            if overall_results.has_key("results"):
                overall_results["results"] = list(sorted(overall_results["results"], 
                    key=itemgetter(params.get("sort", self.default_sort)[0]["field"]), 
                    reverse=sort_dir))[0:limit]

        if overall_results.has_key("groupby"):
            self.log.debug("groupbys %d" % len(overall_results["groupby"]))
        elif overall_results.has_key("results"):
            self.log.debug("overall len: " + str(len(overall_results["results"])))

        agg = { "stats": {}, "activities": {} }
        for tup in overall_results["stats"]:
            if agg["stats"].has_key(tup[2]):
                agg["stats"][ tup[2] ][0] += tup[0]
                agg["stats"][ tup[2] ][1] += tup[1]
            else:
                agg["stats"][ tup[2] ] = list(tup)
        
        return overall_results