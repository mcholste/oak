import sys
import os
import logging
import signal
import threading
import json as slow_json
from multiprocessing import Queue

import tornado
from tornado.web import RequestHandler, asynchronous
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.httpclient import AsyncHTTPClient, HTTPRequest, HTTPClient, HTTPError
from tornado import gen

import ujson as json

from search import *
from utils import Logger

# Reset logging so we can use our own from utils package
logging.shutdown()
reload(logging)

directory = sys.argv[1]
prefix = os.environ.get("PREFIX", "")

class BaseWebHandler(RequestHandler, Logger):
	def __init__(self, *args, **kwargs):
		super(BaseWebHandler, self).__init__(*args, **kwargs)
		#self.log = logging.getLogger(str(type(self)))
		#self.log.setLevel(logging.DEBUG)

class IndexHandler(BaseWebHandler):
	def initialize(self, content_dir):
		self.content_dir = content_dir

	def get(self):
		self.set_header("Content-Type", "text/html")
		self.write(open(self.content_dir + "index.html").read())
		
class JSHandler(BaseWebHandler):
	def initialize(self, content_dir):
		self.content_dir = content_dir

	def get(self):
		self.set_header("Content-Type", "application/javascript")
		self.write(open(self.content_dir + "lib.js").read())

class SearchHandler(BaseWebHandler):
	def initialize(self):
		self.searcher = searcher = Searcher({ "dir": directory, "prefix": prefix })

	def __init__(self, application, request, **kwargs):
		super(SearchHandler, self).__init__(application, request, **kwargs)
		#self.stream = request.connection.stream

	@asynchronous
	def get(self):
		try:
			args = self.get_argument('args')
			args = json.loads(args)
		except Exception as e:
			self.log.exception(e)
			self.set_status(400)
			headers = self._generate_headers()
			self.write(headers)
			self.write("Invalid args")
			self.flush()
			return

		try:
			self.set_header("Content-Type", "text/event-stream")
			self.set_header("Cache-Control", "no-cache")
			self.set_header("Connection", "keep-alive")
			self.set_status(200)
			headers = self._generate_headers()
			self.write(headers); self.flush()
			self.write("\n")
			
			def result_cb(result):
				payload = "id:1\ndata: " + json.dumps(result) + "\n\n"
				#self.log.debug(payload)
				self.write(payload)
				self.flush()

			args["dir"] = directory
			# for result in self.searcher.search({
			# 	"dir": directory,
			# 	"terms": {
			# 		"and": "C5638"
			# 	},
			# 	"filters": { 
			# 	"and": [ 
			# 			#{ "field": "src", "op": "=", "value": "C1685" },
			# 			{ "field": "dst", "op": "=", "value": "C5638" } 
			# 		]
			# 	}
			# }):
			for result in self.searcher.iter(args):
				for groupby in result.get("groupby", {}):
					for k, v in result["groupby"][groupby].iteritems():
						if (k.count(Segment.COMPOSITE_SEPARATOR)):
							del result["groupby"][groupby][k]
							tup = k.split(Segment.COMPOSITE_SEPARATOR)
							if args.has_key("arrkeys"):
								result["groupby"][groupby][k] = { "k": tup, "v": v }
							else:
								result["groupby"][groupby][ " ".join(tup) ] = v
				result_cb(result)
			
			# for result in iter(queue.get, "STOP"):
			# 	payload = "id:1\ndata: " + json.dumps(result) + "\n\n"
			# 	self.log.debug(payload)
			# 	self.write(payload)
			# 	self.flush()
					
			self.write("id: final\ndata:{}\n\n")
			self.flush()
			#self.stream.close()
		except Exception as e:
			self.log.exception(e)
			self.set_status(500)
			headers = self._generate_headers()
			self.write(headers)
			self.write("Error during execution")
			self.flush()
			return
	
	def post(self):
		try:
			self.log.debug("body: %r" % self.request.body)
			args = json.loads(self.request.body)
		except Exception as e:
			self.log.exception(e)
			self.set_status(400)
			headers = self._generate_headers()
			self.write(headers)
			self.write("Invalid args")
			self.flush()
			return

		try:
			self.set_header("Content-Type", "application/json")
			
			args["dir"] = directory
			result = self.searcher.search(args)

			for groupby in result.get("groupby", {}):
				for k, v in result["groupby"][groupby].iteritems():
					if (k.count(Segment.COMPOSITE_SEPARATOR)):
						del result["groupby"][groupby][k]
						tup = k.split(Segment.COMPOSITE_SEPARATOR)
						if args.has_key("arrkeys"):
							result["groupby"][groupby][k] = { "k": tup, "v": v }
						else:
							result["groupby"][groupby][ " ".join(tup) ] = v
			self.write(json.dumps(result))
			
		except Exception as e:
			self.log.exception(e)
			self.set_status(500)
			headers = self._generate_headers()
			self.write(headers)
			self.write("Error during execution")
			self.flush()


class WebAPI(threading.Thread):
	def __init__(self, port=4001):
		super(WebAPI, self).__init__()
		self.log = logging.getLogger(str(type(self)))
		self.log.setLevel(logging.DEBUG)
		#self.app = Flask(__name__)
		self.content_dir = "../static/"

		self.loop = IOLoop.instance()
		self.http_client = AsyncHTTPClient(self.loop)
		self.routes = [
			("/", IndexHandler, dict(content_dir=self.content_dir)),
			("/include/lib.js", JSHandler, dict(content_dir=self.content_dir)),
			("/search", SearchHandler)
		]
		
		#self.http_server = HTTPServer(WSGIContainer(self.app))
		#self.http_server.listen(port)
		self.app = tornado.web.Application(self.routes)
		self.app.listen(port)
		print "Listening on port %d" % port

	def run(self):
		"""Init main thread loop."""
		self.loop.start()

	def stop(self, *args, **kwargs):
		self.loop.stop()


if __name__ == "__main__":
	
	print "starting..."
	web = WebAPI()
	web.start()
	print "started."

	def stop_all(*args, **kwargs):
		print "Stopping"
		web.stop()
	signal.signal(signal.SIGINT, stop_all)
	signal.pause()