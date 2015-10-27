class Taxonomy:
    field_aliases = {
        "src_ip": "srcipv4",
        "dest_ip": "dstipv4",
        "dest_port": "dstport",
        "src_port": "srcport",
        "event_type": "class",
        "proto": "protocol",
        "http.url": "url"
    }