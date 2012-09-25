#!/usr/bin/env python
'''
KeePass v1 database file from Docs/DbFormat.txt of KeePass v1.

General structure:

[DBHDR][GROUPINFO][GROUPINFO][GROUPINFO]...[ENTRYINFO][ENTRYINFO][ENTRYINFO]...

[1x] Database header
[Nx] All groups
[Mx] All entries

'''

import sys, struct, hashlib

from header import DBHDR
from infoblock import GroupInfo, EntryInfo
from Crypto.Cipher import AES
from random import randrange

class Database(object):
    '''
    Access a KeePass DB file of format v3
    '''
    
    def __init__(self, filename = None, masterkey=None, filekey=None, passphrase=None):
        self.masterkey = masterkey
        self.filekey = filekey
        self.passphrase = passphrase

        self.filename = filename
        if filename:
            self.read(filename)
            return
        self.header = DBHDR()
        self.groups = []
        self.entries = []
        return

    def read(self,filename):
        'Read in given .kdb file'
        fp = open(filename)
        buf = fp.read()
        fp.close()

        headbuf = buf[:124]
        self.header = DBHDR(headbuf)
        self.groups = []
        self.entries = []

        payload = buf[124:]

#        if self.masterkey:
#            key = self.masterkey
#        elif self.filekey or self.password:
#            key = self.composite_key()

#        self.finalkey = self.final_key(key,
#                                       self.header.final_master_seed,
#                                       self.header.transform_seed,
#                                       self.header.transform_rounds)
        self.finalkey = self.final_key()
        payload = self.decrypt_payload(payload, self.finalkey, 
                                       self.header.encryption_type(),
                                       self.header.encryption_iv)

        ngroups = self.header.ngroups
        while ngroups:
            gi = GroupInfo(payload)
            self.groups.append(gi)
            length = len(gi)
            #print 'GroupInfo of length',length,'payload=',len(payload)
            payload = payload[length:]
            ngroups -= 1
            continue

        nentries = self.header.nentries
        while nentries:
            ei = EntryInfo(payload)
            self.entries.append(ei)
            payload = payload[len(ei):]
            nentries -= 1
            continue
        return

    def get(self, title=None):
        for e in self.entries:
            if e.title == title:
                return e

    def transform(self, key, seed, rounds):
        cipher = AES.new(seed,  AES.MODE_ECB)
        total = 0
        for i in range(0, rounds):
            total += 1
            key = cipher.encrypt(key)
        return key

    def composite_key(self):
        if self.filekey and not self.passphrase:
            return self.filekey

        if self.passphrase and not self.filekey:
            return hashlib.sha256(self.passphrase).digest()

        composite = hashlib.sha256()
        composite.update(hashlib.sha256(self.passphrase).digest())
        composite.update(self.filekey)
        return composite.digest()

    def final_key(self):
        composite_key = self.composite_key()
        tmaster = self.transform(composite_key, self.header.transform_seed, self.header.transform_rounds)
        tdigest = hashlib.sha256(tmaster).digest()
        return hashlib.sha256(self.header.final_master_seed + tdigest).digest()


    def old_final_key(self,masterkey,final_master_seed,transform_seed, rounds):
        '''Munge masterkey into the final key for decryping payload by
        encrypting it for the given number of rounds masterseed2 and
        hashing it with masterseed.'''
        from Crypto.Cipher import AES
        import hashlib

        #key = hashlib.sha256(masterkey).digest()
        key = masterkey
        cipher = AES.new(transform_seed,  AES.MODE_ECB)
        
        while rounds:
            rounds -= 1
            key = cipher.encrypt(key)
            continue
        key = hashlib.sha256(key).digest()
        return hashlib.sha256(final_master_seed + key).digest()

    def decrypt_payload(self, payload, finalkey, enctype, iv):
        'Decrypt payload (non-header) part of the buffer'

        if enctype != 'Rijndael':
            raise ValueError, 'Unsupported decryption type: "%s"'%enctype

        payload = self.decrypt_payload_aes_cbc(payload, finalkey, iv)
        crypto_size = len(payload)

        if ((crypto_size > 2147483446) or (not crypto_size and self.header.ngroups)):
            raise ValueError, "Decryption failed.\nThe key is wrong or the file is damaged"

        import hashlib
        #print payload
        #print repr(hashlib.sha256(payload).hexdigest())
        #print repr(self.header.contents_hash.encode('hex'))
        if self.header.contents_hash != hashlib.sha256(payload).digest():
            raise ValueError, "Decryption failed. The file checksum did not match."

        return payload

    def decrypt_payload_aes_cbc(self, payload, finalkey, iv):
        'Decrypt payload buffer with AES CBC'

        from Crypto.Cipher import AES
        cipher = AES.new(finalkey, AES.MODE_CBC, iv)
        payload = cipher.decrypt(payload)
        extra = ord(payload[-1])
        payload = payload[:len(payload)-extra]
        #print 'Unpadding payload by',extra
        return payload

    def encrypt_payload(self, payload, finalkey, enctype, iv):
        'Encrypt payload'
        if enctype != 'Rijndael':
            raise ValueError, 'Unsupported encryption type: "%s"'%enctype
        return self.encrypt_payload_aes_cbc(payload, finalkey, iv)

    def encrypt_payload_aes_cbc(self, payload, finalkey, iv):
        'Encrypt payload buffer with AES CBC'
        from Crypto.Cipher import AES
        cipher = AES.new(finalkey, AES.MODE_CBC, iv)
        # pad out and store amount as last value
        length = len(payload)
        encsize = (length/AES.block_size+1)*16
        padding = encsize - length
        #print 'Padding payload by',padding
        for ind in range(padding):
            payload += chr(padding)
        return cipher.encrypt(payload)
        
    def __str__(self):
        ret = [str(repr(self.header))]
        ret += map(str,self.groups)
        ret += map(str,self.entries)
        return '\n'.join(ret)

    def encode_payload(self):
        'Return encoded, plaintext groups+entries buffer'
        payload = ""
        for group in self.groups:
            payload += group.encode()
        for entry in self.entries:
            payload += entry.encode()
        return payload

    def write(self, filename=None):
        '''' 
        Write out DB to given filename with optional master key.
        If no master key is given, the one used to create this DB is used.
        '''
        import hashlib

        outfilename = filename or self.filename
        self.header.ngroups = len(self.groups)
        self.header.nentries = len(self.entries)

        header = DBHDR(self.header.encode())

        # fixme: should regenerate encryption_iv, master_seed,
        # master_seed2 and allow for the number of rounds to change

        payload = self.encode_payload()
        header.contents_hash = hashlib.sha256(payload).digest()

#        finalkey = self.final_key(masterkey = masterkey or self.masterkey,
#                                  masterseed = self.header.master_seed,
#                                  masterseed2 = self.header.master_seed2,
#                                  rounds = self.header.key_enc_rounds)

        payload = self.encrypt_payload(payload, self.final_key(), 
                                       header.encryption_type(),
                                       header.encryption_iv)

        fp = open(outfilename,'w')
        fp.write(header.encode())
        fp.write(payload)
        fp.close()
        return

    def group(self,field,value):
        'Return the group which has the given field and value'
        for group in self.groups:
            if group.__dict__[field] == value: return group
            continue
        return None

    def dump_entries(self,format,show_passwords=False):
        for ent in self.entries:
            group = self.group('groupid',ent.groupid)
            if not group:
                sys.stderr.write("Skipping missing group with ID %d\n"%
                                 ent.groupid)
                continue
            dat = dict(ent.__dict__) # copy
            if not show_passwords:
                dat['password'] = '****'
            for what in ['group_name','level']:
                nick = what
                if 'group' not in nick: nick = 'group_'+nick
                dat[nick] = group.__dict__[what]

            print format%dat
            continue
        return

    def hierarchy(self):
        '''Return database with groups and entries organized into a
        hierarchy'''
        from hier import Node

        top = Node()
        breadcrumb = [top]
        node_by_id = {None:top}
        for group in self.groups:
            n = Node(group)
            node_by_id[group.groupid] = n

            #print group.group_name,group.level,group.groupid,breadcrumb[-1].level()

            while group.level - breadcrumb[-1].level() != 1:
                pn = breadcrumb.pop()
                #print '\tpopped node:',pn.name()
                continue

            breadcrumb[-1].nodes.append(n)
            breadcrumb.append(n)
            continue

        for ent in self.entries:
            n = node_by_id[ent.groupid]
            n.entries.append(ent)

        return top

    def update(self,hierarchy):
        '''
        Update the database using the given hierarchy.  
        This replaces the existing groups and entries.
        '''
        import hier
        collector = hier.CollectVisitor()
        hierarchy.visit(collector)
        self.update(collector.groups,collector.entries)
        return

    def update(self,groups,entries):
        '''
        Update the database using the given groups and entries.  This
        replaces the existing groups and entries.
        '''
        self.groups = groups
        self.entries = entries
        return

    def gen_uuid(self):
        "Generate 16 bytes of randomness suitable for an entry's UUID"
        return 4                # only call once

    def gen_groupid(self):
        "Generate 4 bytes of randomness suitable for a group's unique group id"
        groupid = randrange(1, 2**32-1)
        if groupid in [g.groupid for g in self.groups]:
            return self.gen_groupid()
        else:
            return groupid                # only call once

    def add_entry(self,path,title,username,password,url="",notes="",imageid=1,append=True):
        '''
        Add an entry to the current database at with given values.  If
        append is False a pre-existing entry that matches path, title
        and username will be overwritten with the new one.
        '''
        import hier, infoblock

        top = self.hierarchy()
        node = hier.mkdir(top,path)

        # fixme, this should probably be moved into a new constructor
        def make_entry():
            new_entry = infoblock.EntryInfo()
            new_entry.uuid = self.gen_uuid()
            new_entry.groupid = group.groupid
            new_entry.imageid = imageid
            new_entry.title = title
            new_entry.url = url
            new_entry.username = username
            new_entry.password = password
            new_entry.notes = notes
            #fixme, deal with times
            return new_entry

        if append:
            self.entries.append(make_entry())
            return

        for ent in self.entries:
            if ent.title != title: continue
            if ent.username != username: continue
            ent = make_entry()
            return

        self.entries.append(make_entry())
        
    pass

