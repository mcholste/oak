import os
import sqlite3
import re
import traceback
import gzip
from Queue import Full
from time import sleep
from socket import inet_aton, inet_ntoa, socket, AF_UNIX, SOCK_STREAM
from multiprocessing import Pool, Queue, Process, cpu_count

from utils import *
from segment import *

DEFAULT_MAX_QUEUE_SIZE = 200

def close_segment(segment, directory_file):
    """Function to close a given segment and write to a given directory_file.

    Arguments:
    directory_file -- SQLite3 database to write to in the form of a filename.
    """
    segment.close()
    # Add to the directory
    with sqlite3.connect(directory_file, timeout=60.0) as con:
        cur = con.cursor()
        meta_info = segment.meta_info()
        cur.execute("INSERT INTO directory (filename, start, end, count) VALUES(?,?,?,?)", 
            (segment.prefix, meta_info["start"], meta_info["end"], meta_info["count"]))
        for field in segment.field_type_map:
            cur.execute("REPLACE INTO field_type_map (field, field_type_id) VALUES(?,?)", 
                (field, segment.field_type_map[field]))
    
def spawn_worker(queue, config, id, directory_file):
    """Function to read a given queue and index to a segment.

    Arguments:
    queue -- Queue object to read batches from
    config -- Dict config object
    id -- String prefix to use for the segment
    directory_file -- SQLite3 database to write to in the form of a filename.
    """
    segment_count = 0
    segment = Segment(config, id)
    for arr in iter(queue.get, "STOP"):
        for datum in arr:
            try:
                segment.index_datum(datum)
            except SegmentFullException:
                close_segment(segment, directory_file)
                config["field_type_map"] = segment.field_type_map
                segment_count += 1
                prefix = id + "_" + str(segment_count)
                segment = Segment(config, prefix)
                segment.log.info("New segment %s" % prefix)
    close_segment(segment, directory_file)
    return

class Processor(Logger):

    """Reads events to index from a fifo or queue."""

    def __init__(self, config=dict()):
        self.config = config
        self.dir = config.get("dir", "/tmp/oak")
        self.prefix = config.get("prefix", "oak_")
        self.directory_file = self.dir + "/" + self.prefix + "directory"
        self.log.debug("directory file %s" % self.directory_file)
        self.max_queue_size = config.get("max_queue_size", DEFAULT_MAX_QUEUE_SIZE)

        self.max_id = 0
        with sqlite3.connect(self.directory_file) as con:
            cur = con.cursor()
            # Init tables
            cur.execute("CREATE TABLE IF NOT EXISTS directory (id INTEGER UNSIGNED " +
                "PRIMARY KEY, filename VARCHAR(255), start INTEGER UNSIGNED, " +
                "end INTEGER UNSIGNED, count INTEGER UNSIGNED)")
            cur.execute("CREATE TABLE IF NOT EXISTS field_type_map " +
                "(field VARCHAR(255) PRIMARY KEY, field_type_id INTEGER UNSIGNED)")

            # Get max id. Sqlite calls the primary auto increment key "ROWID."
            cur.execute("SELECT MAX(ROWID) + 1 FROM directory")
            (found_max_id,) = cur.fetchone()
            if found_max_id is not None:
                self.max_id = found_max_id

        self.config["field_type_map"] = get_field_type_map(self.directory_file)

    def process(self, fileobj=None, queue=None):
        """Given a file object or queue, process with workers equal to CPU's.
        Either a fileobj or a queue is required to process. If given a queue,
        batches (in list form) of arrays are expected, and the caller is required
        to put the STOP sentinel on the queue when complete.

        Keyword arguments:
        fileobj -- (Optional) Filehandle-like object to read
        queue -- (Optional) Queue object to read
        """
        if fileobj is None and queue is None:
            raise Exception("Either a fileobj or queue is required.")

        num_workers = cpu_count()
        if fileobj is not None:
            queue = Queue()

        self.procs = list()
        for i in range(num_workers):
            proc = Process(target=spawn_worker, args=(queue, self.config, 
                self.dir + "/" + self.prefix + str(self.max_id + i), self.directory_file))
            proc.start()
            self.procs.append(proc)

        if fileobj is not None:
            self.batch_size = int(self.config.get("batch_size", 100))
            batch = list()
            for line in fileobj:
                if len(batch) >= self.batch_size:
                    try: 
                        queue.put(batch)
                        batch = list()
                    except Full:
                        self.log.warn("Queue full, pausing")
                        sleep(.1)
                batch.append(line)
            if len(batch) > 0:
                queue.put(batch)

            # Tell the workers to close the segments
            for t in self.procs:
                queue.put("STOP")
        
        # Wait for workers to finish
        for t in self.procs:
            t.join()

class UnixSocketProcessor(Logger, Processor):
    # Default config suitable for Suricata
    def __init__(self, fifo_name, socket_name="/tmp/oak_socket", 
            config={ "timestamp_col": "timestamp", "ts_format": "iso_no_tz" }):
        Processor.__init__(self, config)

    def process():
        def listen(fifo_name, socket_name):
            sock = socket(AF_UNIX, SOCK_STREAM)
            os.remove(socket_name)
            sock.bind(socket_name)
            sock.listen(1)
            
            with open(fifo_name, os.O_CREAT | os.O_WRONLY | os.O_NONBLOCK) as fifo:
                while True:
                    connection, client_address = sock.accept()
                    buf = ""
                    while True:
                        data = connection.recv(16)
                        lines = data.split("\n")
                        if len(lines) == 1:
                            buf += lines[0]
                        else:
                            buf += lines.pop(0)
                            fifo.write(buf)
                            while len(lines) > 1:
                                fifo.write(lines.pop(0))
                            buf = lines.pop(0)
                        
        threading.Thread(target=listen, args=(fifo_name,socket_name)).start()

        Processor.process(self, fifo_name)

class CsvProcessor(Logger, Processor):
    # Default config suitable for Suricata
    def __init__(self, file_name, column_names,
            config={ 
                "timestamp_col": "timestamp"
        }):
        Processor.__init__(self, config)
        self.file_name = file_name
        if file_name[-3:] == ".gz":
            self.get_line = self.get_gz_line
        else:
            self.get_line = self.get_single_line
        self.column_names = column_names        

    def get_gz_line(self):
        for line in gzip.GzipFile(self.file_name):
            yield line

    def get_single_line(self):
        for line in self.file_name:
            yield line

    def process(self):
        # Speed this up be removing the dot deref
        num_workers = cpu_count()
        queue = Queue(self.max_queue_size)

        self.procs = list()
        for i in range(num_workers):
            proc = Process(target=spawn_worker, args=(queue, self.config, 
                self.dir + "/" + self.prefix + str(self.max_id + i), self.directory_file))
            proc.start()
            self.procs.append(proc)

        
        self.batch_size = int(self.config.get("batch_size", 100))
        batch = list()
        
        for line in self.get_line():
            if len(batch) >= self.batch_size:
                try: 
                    queue.put(batch)
                    batch = list()
                except Full:
                    self.log.warn("Queue full, pausing")
                    sleep(.1)
            # Convert CSV to JSON
            batch.append(dict(zip(self.column_names, line.strip().split(","))))
                
        if len(batch) > 0:
            queue.put(batch)

        # Tell the workers to close the segments
        for t in self.procs:
            queue.put("STOP")

        # Wait for workers to finish
        for t in self.procs:
            t.join()