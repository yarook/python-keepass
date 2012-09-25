import struct
from datetime import datetime
from binascii import b2a_hex, a2b_hex



class Coder(object):
	def __call__(self):
		return [self.__class__.decode, self.__class__.encode]

	def decode(self, buf):
		return self.__class__.decode(buf)

	def encode(self, val):
		return self.__class__.encode(val)


class ShuntCoder(Coder):
	@staticmethod
	def decode(buf):
		return buf

	@staticmethod
	def encode(val):
		return val


class NullCoder(Coder):
	@staticmethod
	def decode(buf):
		return None

	@staticmethod
	def encode(val):
		return None


class StringCoder(Coder):
	@staticmethod
	def decode(buf):
		return buf.replace('\0', '')

	@staticmethod
	def encode(val):
		return str(val) + '\0'
	

class AsciiCoder(Coder):
	@staticmethod
	def decode(buf):
		return StringCoder.decode(b2a_hex(buf))

	@staticmethod
	def encode(val):
		return StringCoder.encode(a2b_hex(val))

	
class ShortCoder(Coder):
	@staticmethod
	def decode(buf):
		return struct.unpack('<H', buf)[0]

	@staticmethod
	def encode(val):
		return struct.pack('<H', int(val))


class IntCoder(Coder):
	@staticmethod
	def decode(buf):
		return struct.unpack('<I', buf)[0]

	@staticmethod
	def encode(val):
		return struct.pack('<I', int(val))


class DatetimeCoder(Coder):
	@staticmethod
	def decode(buf):
		b = struct.unpack('<5B', buf)
		year = (b[0] << 6) | (b[1] >> 2);
		mon  = ((b[1] & 0b11)     << 2) | (b[2] >> 6);
		day  = ((b[2] & 0b111111) >> 1);
		hour = ((b[2] & 0b1)      << 4) | (b[3] >> 4);
		min  = ((b[3] & 0b1111)   << 2) | (b[4] >> 6);
		sec  = ((b[4] & 0b111111));
		return datetime(year, mon, day, hour, min, sec)

	@staticmethod
	def encode(val):
		year, mon, day, hour, min, sec = val.timetuple()[:6]
		b0 = 0x0000FFFF & ( (year>>6)&0x0000003F )
		b1 = 0x0000FFFF & ( ((year&0x0000003f)<<2) | ((mon>>2) & 0x00000003) )
		b2 = 0x0000FFFF & ( (( mon&0x00000003)<<6) | ((day&0x0000001F)<<1) \
			| ((hour>>4)&0x00000001) )
		b3 = 0x0000FFFF & ( ((hour&0x0000000F)<<4) | ((min>>2)&0x0000000F) )
		b4 = 0x0000FFFF & ( (( min&0x00000003)<<6) | (sec&0x0000003F))
		return struct.pack('<5B',b0,b1,b2,b3,b4)

