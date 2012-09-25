'''
Classes and functions for the GroupInfo and EntryInfo blocks of a keepass file
'''

import struct, uuid
from collections import OrderedDict
from datetime import datetime
from random import randrange

from coder import *


class InfoBase(object):
    'Base class for info type blocks'

    def __init__(self, format, string=None):
        self.format = format
        self.order = []
        if string:
            self.decode(string)
        else:
            string = self.encode(set_default=True)
            self.decode(string)
        return

    def __str__(self):
        ret = [self.__class__.__name__ + ':']
        for num,form in self.format.iteritems():
            try:
                value = self.__dict__[form[0]]
            except KeyError:
                continue
            ret.append('\t%s %s'%(form[0], value))
        return '\n'.join(ret)

    def __len__(self):
        length = 0
        for typ,siz in self.order:
            length += 2+4+siz
        return length

    def decode(self, string):
        'Fill self from binary string'
        index = 0
        while True:
            substr = string[index:index+6]
            index += 6

            typ, siz = struct.unpack('<H I', substr)
            self.order.append((typ, siz))

            substr = string[index:index+siz]
            index += siz

            name, coder, default = self.format[typ]
            buf = struct.unpack('<%ds'%siz, substr)[0]

            if name is None: break

            try:
                value = coder.decode(buf)
            except struct.error,msg:
                msg = '%s, typ = %d[%d] -> %s buf = "%s"'%\
                    (msg,typ,siz,self.format[typ], buf)
                raise struct.error, msg

            self.__dict__[name] = value
            continue
        return

    def encode(self, set_default=False):
        string = ""
        for typ, item in self.format.items():
            name = item[0]
            coder = item[1]
            default = item[2]

            if typ == 0xFFFF:
                encoded = None
            else:
                if hasattr(self, name):
                    value = self.__dict__[name]
                else:
                    if default is None:
                        value = None
                    else:
                        value = default()
                encoded = coder.encode(value)
            
            if encoded is None:
                siz = 0
            else:
                siz = len(encoded)

            if siz > 200000:
                raise Exception("Size too big")

            buf = struct.pack('<H I', typ, siz)
            typ, siz = struct.unpack('<H I', buf)

            if encoded is not None:
                buf += struct.pack('<%ds'%siz, encoded)

            string += buf
            continue
        return string

    pass



class GroupInfo(InfoBase):
    '''One group: [FIELDTYPE(FT)][FIELDSIZE(FS)][FIELDDATA(FD)]
           [FT+FS+(FD)][FT+FS+(FD)][FT+FS+(FD)][FT+FS+(FD)][FT+FS+(FD)]...

[ 2 bytes] FIELDTYPE
[ 4 bytes] FIELDSIZE, size of FIELDDATA in bytes
[ n bytes] FIELDDATA, n = FIELDSIZE

Notes:
- Strings are stored in UTF-8 encoded form and are null-terminated.
- FIELDTYPE can be one of the following identifiers:
  * 0000: Invalid or comment block, block is ignored
  * 0001: Group ID, FIELDSIZE must be 4 bytes
          It can be any 32-bit value except 0 and 0xFFFFFFFF
  * 0002: Group name, FIELDDATA is an UTF-8 encoded string
  * 0003: Creation time, FIELDSIZE = 5, FIELDDATA = packed date/time
  * 0004: Last modification time, FIELDSIZE = 5, FIELDDATA = packed date/time
  * 0005: Last access time, FIELDSIZE = 5, FIELDDATA = packed date/time
  * 0006: Expiration time, FIELDSIZE = 5, FIELDDATA = packed date/time
  * 0007: Image ID, FIELDSIZE must be 4 bytes
  * 0008: Level, FIELDSIZE = 2
  * 0009: Flags, 32-bit value, FIELDSIZE = 4
  * FFFF: Group entry terminator, FIELDSIZE must be 0
  '''

    format = OrderedDict([
        (0x0, ('ignored', NullCoder(), None)),
        (0x1, ('groupid', IntCoder(), lambda: randrange(1, 2**(4*8)-1))),
        (0x2, ('group_name', StringCoder(), lambda: "Unknown")),
        (0x3, ('creation_time', DatetimeCoder(), datetime.now)),
        (0x4, ('lastmod_time', DatetimeCoder(), datetime.now)),
        (0x5, ('lastacc_time', DatetimeCoder(), datetime.now)),
        (0x6, ('expire_time', DatetimeCoder(), lambda: datetime(2999, 12, 28, 23, 59))),
        (0x7, ('imageid', IntCoder(), lambda: 0)),
        (0x8, ('level', ShortCoder(), lambda: 0)),
        (0x9, ('flags', IntCoder(), lambda: 0)),
        (0xFFFF, (None, None, None)),
        ])

    def __init__(self,string=None):
        super(GroupInfo, self).__init__(GroupInfo.format, string)
        return

    def name(self):
        'Return the group_name'
        return self.group_name

    pass


class EntryInfo(InfoBase):
    '''One entry: [FIELDTYPE(FT)][FIELDSIZE(FS)][FIELDDATA(FD)]
           [FT+FS+(FD)][FT+FS+(FD)][FT+FS+(FD)][FT+FS+(FD)][FT+FS+(FD)]...

[ 2 bytes] FIELDTYPE
[ 4 bytes] FIELDSIZE, size of FIELDDATA in bytes
[ n bytes] FIELDDATA, n = FIELDSIZE

Notes:
- Strings are stored in UTF-8 encoded form and are null-terminated.
- FIELDTYPE can be one of the following identifiers:
  * 0000: Invalid or comment block, block is ignored
  * 0001: UUID, uniquely identifying an entry, FIELDSIZE must be 16
  * 0002: Group ID, identifying the group of the entry, FIELDSIZE = 4
          It can be any 32-bit value except 0 and 0xFFFFFFFF
  * 0003: Image ID, identifying the image/icon of the entry, FIELDSIZE = 4
  * 0004: Title of the entry, FIELDDATA is an UTF-8 encoded string
  * 0005: URL string, FIELDDATA is an UTF-8 encoded string
  * 0006: UserName string, FIELDDATA is an UTF-8 encoded string
  * 0007: Password string, FIELDDATA is an UTF-8 encoded string
  * 0008: Notes string, FIELDDATA is an UTF-8 encoded string
  * 0009: Creation time, FIELDSIZE = 5, FIELDDATA = packed date/time
  * 000A: Last modification time, FIELDSIZE = 5, FIELDDATA = packed date/time
  * 000B: Last access time, FIELDSIZE = 5, FIELDDATA = packed date/time
  * 000C: Expiration time, FIELDSIZE = 5, FIELDDATA = packed date/time
  * 000D: Binary description UTF-8 encoded string
  * 000E: Binary data
  * FFFF: Entry terminator, FIELDSIZE must be 0
  '''

    format = OrderedDict([
        (0x0, ('ignored', NullCoder(), lambda: None)),
        (0x1, ('uuid', AsciiCoder(), lambda: uuid.uuid4().hex)),
        (0x2, ('groupid', IntCoder(), lambda: 0)),
        (0x3, ('imageid', IntCoder(), lambda: 0)),
        (0x4, ('title', StringCoder(), lambda: "Unknown")),
        (0x5, ('url', StringCoder(), lambda: "")),
        (0x6, ('username', StringCoder(), lambda: "")),
        (0x7, ('password', StringCoder(), lambda: "")),
        (0x8, ('notes', StringCoder(), lambda: "")),
        (0x9, ('creation_time', DatetimeCoder(), datetime.now)),
        (0xa, ('last_mod_time', DatetimeCoder(), datetime.now)),
        (0xb, ('last_acc_time', DatetimeCoder(), datetime.now)),
        (0xc, ('expiration_time', DatetimeCoder(), lambda: datetime(2999, 12, 28, 0, 0))),
        (0xd, ('binary_desc', StringCoder(), lambda: "")),
        (0xe, ('binary_data', ShuntCoder(), lambda: "")),
        (0xFFFF, (None, None, None)),
    ])

    def __init__(self,string=None):
        super(EntryInfo, self).__init__(EntryInfo.format, string)
        return

    def name(self):
        'Return the title'
        return self.title

    pass

