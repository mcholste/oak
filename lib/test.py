import os
import gzip
import sqlite3
import tempfile
import shutil

from multiprocessing import cpu_count

from processor import *
from search import *

##############################
# Run tests with nosetests
##############################

# Suricata JSON test data based on running the default rulest 
#  against http://www.snaketrap.co.uk/pcap/hptcp.pcap
test_data_file = "../testdata/eve.json.gz"
test_prefix = "test_"

# Setup test dir
directory = tempfile.mkdtemp(prefix="oak")
csvgz_directory = tempfile.mkdtemp(prefix="oak_csvgz_")

# Query tests depend on the index test to populate data
def test_index():
    test_fh = gzip.GzipFile(test_data_file)
    # Provide Suricata-specific timestamp config
    processor = Processor({ "dir": directory, 
        "prefix": test_prefix, "timestamp_col": "timestamp", 
        "ts_format": "iso_no_tz" })
    processor.process(test_fh)
    with sqlite3.connect(processor.directory_file) as con:
        cur = con.cursor()
        cur.execute("SELECT filename, start, end, count FROM directory")
        total = 0
        total_rows = 0
        for row in cur.fetchall():
            total_rows += 1
            total += row[3]
        assert total_rows == cpu_count()
        assert total == 26135

def test_fullscan():
    searcher = Searcher({ "dir": directory, "prefix": test_prefix })
    results = searcher.search({"limit": None})
    assert len(results["results"]) == 26135

def test_field_report():
    searcher = Searcher({ "dir": directory, "prefix": test_prefix })
    results = searcher.search({ "meta": "field_report" })
    assert results["meta"]["fields"]["alert.signature"] == cpu_count()

def test_report_all():
    searcher = Searcher({ "dir": directory, "prefix": test_prefix })
    results = searcher.search({"groupby":"*"})
    assert results["groupby"]["alert.signature"]["ET DROP Dshield Block Listed Source group 1"] == 3

def test_groupby_all():
    searcher = Searcher({ "dir": directory, "prefix": test_prefix })
    results = searcher.search({
        "terms": { "and": [ "tcp" ]}, 
        "filters": 
            { "and": [ { "field": "alert.rev", "op": "=", "value": 11 } ]}, 
        "groupby":"*"})
    assert results["groupby"]["alert.signature"]["ET SCAN Potential FTP Brute-Force attempt"] == 49

def test_groupby_all_nosample():
    searcher = Searcher({ "dir": directory, "prefix": test_prefix })
    results = searcher.search({
        "terms": { "and": [ "tcp" ]}, 
        "filters": { "and": [ { "field": "alert.rev", "op": "=", "value": 11 } ]}, 
        "groupby":"*", "no_sample": True})
    assert results["groupby"]["alert.signature"]["ET SCAN Potential FTP Brute-Force attempt"] == 49

def test_groupby_and_ipv4_filter():
    searcher = Searcher({ "dir": directory, "prefix": test_prefix })
    results = searcher.search({
        "terms": { "and": [ "tcp" ]}, 
        "filters": { 
            "and": [ 
                { "field": "dstipv4", "op": ">=", "value": "10.0.0.0" }, 
                { "field": "dstipv4", "op": "<=", "value": "10.255.255.255" } 
            ]}, 
        "groupby": ["dstipv4"]})
    assert results["groupby"]["dstipv4"]["10.200.59.77"] == 6791
    
def test_introspection_filtered_groupby_ipv4_or():
    searcher = Searcher({ "dir": directory, "prefix": test_prefix })
    results = searcher.search({
        "terms": { "and": [ "tcp" ]}, 
        "filters": { "or": [ 
            { "filters": 
                { 
                    "and": [ { "field": "dstipv4", "op": ">=", "value": "192.168.0.0" }, 
                        { "field": "dstipv4", "op": "<=", "value": "192.168.255.255" } ]
                }
            },
            { "filters": 
                { 
                    "and": [ { "field": "dstipv4", "op": ">=", "value": "172.16.0.0" }, 
                        { "field": "dstipv4", "op": "<=", "value": "172.31.255.255" } ]
                }
            },
            { "filters": 
                { 
                    "and": [ { "field": "dstipv4", "op": ">=", "value": "10.0.0.0" }, 
                        { "field": "dstipv4", "op": "<=", "value": "10.255.255.255" } ]
                }
            } ]
        }, 
        "groupby": ["dstipv4"], 
        "no_sample": False, 
        "force_introspection": True})
    assert results["groupby"]["dstipv4"]["10.200.59.77"] == 6791

def test_docvals_filtered_groupby_ipv4_or():
    searcher = Searcher({ "dir": directory, "prefix": test_prefix })
    results = searcher.search({
        "terms": { "and": [ "tcp" ]}, 
        "filters": { "or": [ 
            { "filters": 
                { 
                    "and": [ { "field": "dstipv4", "op": ">=", "value": "192.168.0.0" }, 
                        { "field": "dstipv4", "op": "<=", "value": "192.168.255.255" } ]
                }
            },
            { "filters": 
                { 
                    "and": [ { "field": "dstipv4", "op": ">=", "value": "172.16.0.0" }, 
                        { "field": "dstipv4", "op": "<=", "value": "172.31.255.255" } ]
                }
            },
            { "filters": 
                { 
                    "and": [ { "field": "dstipv4", "op": ">=", "value": "10.0.0.0" }, 
                        { "field": "dstipv4", "op": "<=", "value": "10.255.255.255" } ]
                }
            } ]
        }, "groupby": ["dstipv4"]})
    assert results["groupby"]["dstipv4"]["10.200.59.77"] == 6791

def test_docvals_filtered_string_groupby():
    searcher = Searcher({ "dir": directory, "prefix": test_prefix })
    results = searcher.search({
        "terms": { "and": [ "tcp" ]}, 
        "filters": { 
            "and": [ 
                { "field": "alert.action", "op": "=", "value": "allowed" } 
            ]            
        }, "groupby": ["alert.action"]})
    assert results["groupby"]["alert.action"]["allowed"] == 2129

def test_simple_search_tcp():
    searcher = Searcher({ "dir": directory, "prefix": test_prefix })
    results = searcher.search({"terms": { "and": [ "tcp" ]} })
    assert len(results["results"]) == 100

def test_casesensitive_contains():
    searcher = Searcher({ "dir": directory, "prefix": test_prefix })
    results = searcher.search({ 
        "terms": { "and": [ "inrelease" ] }, 
        "filters": { 
            "and": [ { "field": "url", "value": "InRelease", "op": "contains" } ] } })
    assert len(results["results"]) == 78

def test_regex():
    searcher = Searcher({ "dir": directory, "prefix": test_prefix })
    results = searcher.search({ 
        "terms": { "and": [ "inrelease" ] }, 
        "filters": { 
            "and": [ { "field": "url", "value": ".*[Ii]n[Rr]elease.*", "op": "=~" } ] } })
    assert len(results["results"]) == 78

def test_docvals_simple_groupby():
    searcher = Searcher({ "dir": directory, "prefix": test_prefix })
    results = searcher.search({
        "terms": { "and": [ "tcp" ]}, 
        "groupby": ["dstport"]})
    assert len(results["groupby"]["dstport"]) == 100 \
        and results["groupby"]["dstport"][35408] == 6

def test_nested_field_groupby():
    searcher = Searcher({ "dir": directory, "prefix": test_prefix })
    results = searcher.search({ 
        "terms": { 
            "and": [ "security.ubuntu.com" ] }, 
        "groupby": [ "http.hostname" ] })
    assert results["groupby"]["http.hostname"]["security.ubuntu.com"] == 213

def test_noterms_groupby():
    searcher = Searcher({ "dir": directory, "prefix": test_prefix })
    results = searcher.search({ 
        "filters": { 
            "and": [ { "field": "http.http_user_agent", "op": "contains", "value": "Mozilla" }]}, 
        "groupby": [ "http.hostname" ] })
    assert results["groupby"]["http.hostname"]["server5.cyberpods.net"] == 14 \
        and len(results["groupby"]["http.hostname"]) == 5

def test_compound_groupby():
    searcher = Searcher({ "dir": directory, "prefix": test_prefix })
    results = searcher.search({
        "terms": { "and": [ "tcp" ]}, 
        "groupby": ["srcport,dstport"]})
    assert len(results["groupby"]["srcport,dstport"]) == 100 \
        and results["groupby"]["srcport,dstport"]["80,35408"] == 6

def test_compound_groupby_no_terms():
    searcher = Searcher({ "dir": directory, "prefix": test_prefix })
    results = searcher.search({
        "groupby": ["srcport,dstport"]})
    assert len(results["groupby"]["srcport,dstport"]) == 100 \
        and results["groupby"]["srcport,dstport"]["46231,80"] == 22

def test_distinct_groupby():
    searcher = Searcher({ "dir": directory, "prefix": test_prefix })
    results = searcher.search({"groupby":"DISTINCT(*)"})
    print results
    assert results["groupby"]["srcipv4"]["DISTINCT"] == 80

def teardown_test():
    shutil.rmtree(directory)

def test_csvgz_index():
    test_data_file = "../testdata/test.csv.gz"
    cols = ["timestamp", "src", "answer"]
    processor = CsvProcessor(test_data_file, cols,
        { 
            "dir": csvgz_directory, 
            "prefix": test_prefix, 
            "timestamp_col": "timestamp",
            "composite_fields": [
                ["src", "answer"]
            ]
        })
    processor.process()
    with sqlite3.connect(processor.directory_file) as con:
        cur = con.cursor()
        cur.execute("SELECT filename, start, end, count FROM directory")
        total = 0
        total_rows = 0
        for row in cur.fetchall():
            total_rows += 1
            total += row[3]
        print "total rows: " + str(total_rows)
        assert total_rows == cpu_count()
        assert total == 10

def test_csvgz_composite_groupby():
    searcher = Searcher({ "dir": csvgz_directory, "prefix": test_prefix })
    results = searcher.search({"groupby":"src-answer"})
    print results
    assert len(results["groupby"]["src-answer"]) == 9