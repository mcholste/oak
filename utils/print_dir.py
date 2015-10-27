import sqlite3
with sqlite3.connect("/tmp/oak/oak_directory") as con:
    cur = con.cursor()
    cur.execute("SELECT ROWID, filename, datetime(start, 'unixepoch'), datetime(end, 'unixepoch'), count, end-start AS length FROM directory")
    for row in cur.fetchall():
        print row
