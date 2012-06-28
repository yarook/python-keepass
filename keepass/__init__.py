#!/usr/bin/env python
'''
KeePass module
'''

import os.path

from .kpdb import Database

def get_entry(dbfilename, title, keyfilename=None, passphrase=None):

    dbname = os.path.basename(dbfilename).split(".")[0]
    if keyfilename is None:
        keyfilename = os.path.abspath(os.path.dirname(dbfilename) + "/secure/" + dbname + ".key")

    infile = file(keyfilename)
    filekey = infile.read().strip().decode('hex')
    infile.close()

    db = Database(dbfilename, filekey=filekey, passphrase=passphrase)
    entry = db.get(title)

    return entry
