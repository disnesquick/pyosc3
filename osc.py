import struct, math, datetime, sys, socket, re, time
from threading import Thread

def printBin(byteString):
	a = []
	for i in byteString:
		a.append("%.02X"%i)
	return "".join(a)

class Exception(Exception):
	pass

class OSCBase(object):
	def __getattr__(self, name):
		if name == "bin":
			return self.getBinary()
		else:
			return self.__getattribute__(name)

class Atom(OSCBase):
	toOSCMapping = []
	
	@classmethod
	def announce(cls, thingTo, thingFrom=None):
		#TODO: Automaagically detect whether an announced object is a subclass
		#or superclass of an extant announced object and place it in the list accordingly
		if thingFrom != None:
			cls.toOSCMapping.append((thingFrom, thingTo))
	
	def __new__(cls, inThing, bin=None):
		if cls == Atom:
			for pyCls, OSCCls in cls.toOSCMapping:
				if isinstance(inThing, pyCls):
					cls = OSCCls
					break
		if cls == Atom:
			raise(TypeError(str(type(inThing)) + " Cannot be encoded as an OSC type so fuck you very much."))
		else:
			neonate = OSCBase.__new__(cls)
			neonate.__init__(inThing)
			return neonate
	
	def __init__(self, inThing):
		self.val = inThing
		self.bin = self.OSCEncode()

	def __eq__(self, other):
		return self.val == other.val

	def __repr__(self):
		return "osc"+self.__class__.__name__+"("+repr(self.val)+")"

	def getBinary(self):
		raise(Exception("Atom should never not have a binary representation, what the hell!"))

	def deOSC(self):
		return self.val

class String(Atom):
	""" The length of the resulting string is always a multiple of 4 bytes.
	The string ends with 1 to 4 zero-bytes ('\x00') 
	"""
	tag = "s"
	def OSCEncode(self):
		stringLength = math.ceil((len(self.val)+1) / 4.0) * 4
		return struct.pack(">%ds" % (stringLength), bytes(self.val,encoding="ASCII"))


class Boolean(Atom):
	def __init__(self, inThing):
		self.val = inThing
		if inThing:
			self.tag = "T"
		else:
			self.tag = "F"
		self.bin = b""
	def OSCEncode(self):
		return b""

class Blob(Atom):
	""" An OSC-Blob is a binary encoded block of data, prepended by a 'size' (int32).
	The size is always a mutiple of 4 bytes. 
	The blob ends with 0 to 3 zero-bytes ('\x00') 
	"""
	tag = "b"
	def OSCEncode(self):
		if isinstance(self.val, OSCBase):
			val = self.val.bin
		else:
			val = self.val
		blobLength = math.ceil((len(val)) / 4.0) * 4
		return struct.pack(">i%ds" % (blobLength), blobLength, val)


class Float(Atom):
	""" A 32-bit floating-point value
	"""
	tag = "f"
	def OSCEncode(self):
		return struct.pack(">f", self.val)

class Double(Atom):
	#Don't announce this one
	""" A 64-bit floating-point value
	"""
	tag = "d"
	def OSCEncode(self):
		return struct.pack(">d", self.val)

class Int(Atom):
	""" A 32-bit integer value
	"""
	tag = "i"
	def OSCEncode(self):
		return struct.pack(">i", self.val)

class Long(Atom):
	#Don't announce this one
	""" A 64-bit integer value
	"""
	tag = "h"
	def OSCEncode(self):
		return struct.pack(">q", self.val)

class TimeTag(Atom):
	tag = "t"
	def OSCEncode(self):
		NTP_epoch = datetime.datetime(1900,1,1,0,0)
		NTP_units_per_second = 0x100000000
		delta = self.val - NTP_epoch 
		secs = delta.total_seconds()
		fract, secs = math.modf(secs)
		if secs > 0:
			binary = struct.pack('>LL', int(secs), int(fract * NTP_units_per_second))
		else:
			binary = struct.pack('>LL', 0, 1)
		return binary
	
	def __repr__(self):
		return "osc"+self.__class__.__name__+"("+str(self.val)+")"
Atom.announce(String, str)
Atom.announce(Blob, bytes)
Atom.announce(Boolean, bool)	#Bool must go before int because of subclass issues
Atom.announce(Float, float)
Atom.announce(Double)
Atom.announce(Int, int)
Atom.announce(TimeTag, datetime.datetime)

#TODO: Cache the binary of the message
class Message(OSCBase):
	def __init__(self, *args, address=""):
		"""Instantiate a new OSCMessage.
		The OSC-address can be specified with the 'address' argument.
		The rest of the arguments are appended as data.
		"""
		self.message = []
		self.setAddress(address)
		for arg in args:
			self.append(arg)


	def __repr__(self):
		return repr(self.address)+" - "+repr(self.message)

	def __str__(self):
		return "%s: %s" % (self.address, str(self.message))

	def __iadd__(self, thing):
		for i in thing:
			self.append(i)
		return self

	def clearCache(self):
		self.bin = None
		delattr(self, "bin")

	def setAddress(self, address):
		"""Set or change the OSC-address
		"""
		self.clearCache()
		if isinstance(address, String):
			self.address = address
		else:
			self.address = String(address)

	def clear(self):
		"""Clear any arguments appended so far
		"""
		self.clearCache()
		self.message  = []

	def append(self, argument):
		"""Appends data to the message, converting into an OSC Atom if necessary
		"""
		self.clearCache()
		if not isinstance(argument, Atom):
			argument = Atom(argument)
		
		self.message.append(argument)

	def getBinary(self):
		"""Returns the binary representation of the message
		"""
		binary = self.address.bin
		tags = ","
		binMsg = b""
		for i in self.message:
			tags += i.tag
			binMsg += i.bin
		binary += String(tags).bin
		binary += binMsg
		self.bin = binary
		
		return binary

	def decode(self):
		if not hasattr(self, "message"):
			self._decodeBinary()

		return self.address, list(self._yieldMessage)

	def _yieldMessage(self):
		for i in self.message:
			yield i.val



class MessageFromBinary(Message):
	def __init__(self, bin):
		self.bin = bin
		self.__class__ = Message

Message.fromBinary = MessageFromBinary

class Bundle(Message):
	headerString = String("#bundle")
	def __init__(self, *args, address="", time=None):
		self.address = address
		self.setTime(time)
		self.members = []
		for arg in args:
			self.append(arg)

	def __repr__(self):
		return repr(self.time)+" - "+repr(self.members)

	def __str__(self):
		return "%s: %s" % (str(self.time), str(self.members))

	def clear(self):
		self.clearCache()
		self.members = []
	
	def setTime(self, time):
		self.clearCache()
		if not isinstance(time, TimeTag):
			self.time = TimeTag(time)
		else:
			self.time = time

	def append(self, argument):
		self.clearCache()
		if not isinstance(argument, Message):
			try:
				argument = Message(*argument, address = self.address)
			except TypeError:
				argument = Bundle(*argument, address = self.address, time = self.time)
		self.members.append(argument)

	def getBinary(self):
		"""Returns the binary representation of the message
		"""
		binary = type(self).headerString.bin
		binary += self.time.bin
		for i in self.members:
			binary += struct.pack(">i" , len(i.bin))
			binary += i.bin
		self.bin = binary
		
		return binary

class RecvBundle(list):
	def __init__(self, time):
		self.time = time

class RecvMessage(list):
	def __init__(self, address):
		self.address = address

class BinaryDecoder:
	def __init__(self, binary, pos = 0):
		self.data = binary
		self.pos = pos
	
	def _checkPos(self, length):
		if self.pos+length > len(self.data):
			raise(IndexError( "Bytestream is truncated '%s'"%self.data[self.pos:]))
	
	def _readString(self):
		"""Reads the next (null-terminated) block of data
		"""
		pos = self.pos
		nextPos = self.data.find(b"\0",pos)
		if nextPos == -1:
			raise(IndexError("Bytestream is truncated"))
		ret = self.data[pos:nextPos].decode("ASCII")
		self.pos = pos + int(math.ceil((nextPos-pos+1) / 4.0) * 4)
		return ret
	
	def _readBlob(self):
		"""Reads the next (numbered) block of data
		"""
		self._checkPos(4)
		pos = self.pos
		length,  = struct.unpack(">i", self.data[pos:(pos+4)])
		pos += 4
		self._checkPos(length)
		nextData = int(math.ceil((length) / 4.0) * 4) + 4
		ret = self.data[pos:pos+length]
		self.pos = pos + length
		return ret
	
	def _readTrue(self):
		return True

	def _readFalse(self):
		return False

	def _readInt(self):
		"""Tries to interpret the next 4 bytes of the data
		as a 32-bit integer. """
		self._checkPos(4)
		pos = self.pos
		ret, = struct.unpack(">i", self.data[pos:(pos+4)])
		self.pos += 4		
		return ret
	
	def _readLong(self):
		"""Tries to interpret the next 8 bytes of the data
		as a 64-bit signed integer.
		 """
		self._checkPos(8)
		pos = self.pos
		high, low = struct.unpack(">ll", self.data[pos:(pos+8)])
		big = (high << 32) + low
		self.pos += 8
		return big
	
	def _readTimeTag(self):
		"""Tries to interpret the next 8 bytes of the data
		as a TimeTag.
		 """
		self._checkPos(8)
		NTPEpoch = datetime.datetime(1900,1,1,0,0)
		NTPUnitsPerMicrosecond = 0x100000000 / 1000000
		pos = self.pos
		high, low = struct.unpack(">LL", self.data[pos:(pos+8)])
		time = NTPEpoch + datetime.timedelta(seconds = high, microseconds = low / NTPUnitsPerMicrosecond)
		self.pos += 8
		return time
	
	def _readFloat(self):
		"""Tries to interpret the next 4 bytes of the data
		as a 32-bit float. 
		"""
		self._checkPos(4)
		pos = self.pos
		ret, = struct.unpack(">f", self.data[pos:(pos+4)])
		self.pos+=4
		return ret
	
	def _readDouble(self):
		"""Tries to interpret the next 8 bytes of the data
		as a 64-bit float. 
		"""
		self._checkPos(8)	
		pos = self.pos
		ret, = struct.unpack(">d", self.data[pos:(pos+8)])
		self.pos+=8
		return ret
		

	table = {"i":_readInt, "h":_readLong, "f":_readFloat, "d":_readDouble, "s":_readString, "b":_readBlob, "d":_readDouble, "t":_readTimeTag, "T":_readTrue, "F":_readFalse}
	
	def decodeFromTags(self, tags, inArray=False):
		ary = []
		for tag in tags:
			#Array is a special case
			if tag == "[":
				self.decodeFromTags(self, tags, True)
			elif tag == "]":
				if inArray:
					return ary
				else:
					raise(Exception("End of array found but was not processing an array"))
			else:
				try:
					result = self.table[tag](self)
					ary.append(result)
				except:
					raise(Exception("Error on tag '%s' at '%s' in '%s' with '%s'"%(tag,printBin(self.data[self.pos:]), printBin(self.data), repr(decoded))))
		return ary

	def decode(self):
		address = self._readString()
		if address.startswith(","):
			typetags = address
			address = ""
		else:
			typetags = ""
		if address == "#bundle":
			decoded = RecvBundle(self._readTimeTag())
			while self.pos < len(self.data):
				length = self._readInt()
				decoded.append(BinaryDecoder(self.data,self.pos).decode())
				self.pos += length
			self.decoded = decoded
		else:
			decoded = RecvMessage(address)
			if typetags == "":
				typetags = self._readString()
			if typetags.startswith(","):
				tagiter = iter(typetags[1:])
				for i in self.decodeFromTags(tagiter):
					decoded.append(i)
			else:
				raise (Exception("Message's typetag-string lacks the magic."))
		return decoded

class SocketSendProxy:
	def __init__(self, socket, dest=None, destaddr=None):
		self.sock = socket
		self.dest = dest
		self.destaddr = destaddr
	def __getitem__(self, destaddr):
		if self.destaddr:
			raise(Exception("Destination address has already been specified"))
		else:
			return SocketSendProxy(self.sock, self.dest, destaddr)
	def __lshift__(self, thing):
		if self.destaddr:
			thing = Message(thing, address=self.destaddr)
		if self.dest:
			self.sock.outSocket.sendto(thing.bin, self.dest)
		else:
			self.sock.sendall(thing)

class Socket:
	# set socket buffer sizes (32k)
	sendBufSize = 4096 * 8
	recvBufSize = 4096 * 8
	def __init__(self, inPort=None, parallelMessages = False, addressFamily = socket.AF_INET):
		self.prlMsg = parallelMessages
		self.running = False
		self.connectOutUDP(addressFamily)
		self.outAddresses = set()
		if inPort != None:
			self.targets = AddressTree()
			self.connectInUDP(inPort)
		else:
			self.targets = None

	def __lshift__(self, thing):
		self.sendall(thing)
	
	def __call__(self, address, port):
		return SocketSendProxy(self, dest=(address,port))

	def __getitem__(self, arg):
		return SocketSendProxy(self, destaddr=arg)

	def __setitem__(self, target, handle):
		self.addTarget(target, handle)
	
	def __del__(self):
		if self.running:
			self.close()
	
	def registerDestination(self, address, port):
		self.outAddresses.add((address, port))
	
	def sendall(self, thing):
		if isinstance(thing, Message):
			for dest in self.outAddresses:
				self.outSocket.sendto(thing.bin, dest)
		else:
			raise(Exception("Invalid thing being sent down the tubes: "+repr(thing)))

	def connectOutUDP(self, addressFamily):
		self.outSocket = socket.socket(addressFamily, socket.SOCK_DGRAM)
		self.outSocket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.sendBufSize)
		#self.fd = self.outSocket.fileno()    -- Not sure what this was for...
	
	def getOutAddress(self):
		return self.socket.getpeername()

	def addTarget(self, target, handle):
		if self.targets:
			self.targets[target] = handle
		else:
			raise(Exception("Socket was not set up as a listening socket"))

	def connectInUDP(self, inPort):
		addressFamily = socket.AF_INET
		self.inSocket = socket.socket(addressFamily, socket.SOCK_DGRAM)
		self.inSocket.settimeout(1)
		self.inSocket.bind(("",inPort))
		self.thread = Thread(target=self.listenThread)
		self.thread.start()
	
	def logMessageException(self, packet, exception):
		print(self, packet.address, packet, exception)

	def runMessage(self, handle, args, source):
		try:
			handle(self, *args, source=source)
		except Exception as E:
			self.logMessageException(args, E)

	def _handleMessage(self, packet, source):
		if isinstance(packet, RecvBundle):
			delta = (datetime.datetime.now() - packet.time).total_seconds()
			if delta > 0:
				sleep(delta)
			for i in packet:
				self.handleMessage(i, source)
		elif isinstance(packet, RecvMessage):
			handles = self.targets[packet.address]
			if len(handles) == 0:
				self.logMessageException(packet, Exception("Message has no targets"))
			else:
				if self.prlMsg:
					for handle in handles[1:]:
						Thread(target=self.runMessage, args = (handle, packet, source)).start()
					self.runMessage(handles[0], packet, source)
				else:
					for handle in handles:
						self.runMessage(handle, packet, source)
				

	def handleMessage(self, packet, source):
		newThread = Thread(target=self._handleMessage, args=(packet,source))
		newThread.start()

	def listenThread(self):
		self.running = True
		while self.running:
			try:
				data = self.inSocket.recvfrom(self.recvBufSize)
				packet = BinaryDecoder(data[0]).decode()
				self.handleMessage(packet, data[1])
			except socket.error:
				pass

	def close(self):
		self.running = False
		


# A translation-table for mapping OSC-address expressions to Python 're' expressions
OSCtrans = str.maketrans("{,}?","(|).")
reDict = {}

def getRegEx(pattern):
	"""Compiles and returns a 'regular expression' object for the given address-pattern."""
	if not pattern in reDict:
		pattern = pattern.replace(".", r"\.")		# first, escape all '.'s in the pattern.
		pattern = pattern.replace("(", r"\(")		# escape all '('s.
		pattern = pattern.replace(")", r"\)")		# escape all ')'s.
		pattern = pattern.replace("*", r".*")		# replace a '*' by '.*' (match 0 or more characters)
		pattern = pattern.translate(OSCtrans)		# change '?' to '.' and '{,}' to '(|)'
		reDict[pattern] = re.compile(pattern)
	return reDict[pattern]

badList=" #*,/?[]{}"
def _stringCheck(string):
	for i in badList:
		if i in string:
			return True
	return False


class AddressNode:
	def __init__(self):
		self.children = []
		self.leaf = tuple()
	def match(self, matchList, pos):
		if pos == len(matchList):
			return self.leaf
		matcher = matchList[pos]
		matches = tuple()
		for string, node in self.children:
			if matcher.match(string):
				matches += node.match(matchList,pos+1)
		return matches

class AddressTree(AddressNode):
	def __getitem__(self, string):
		matchList = string.split("/")[1:]
		for i in range(len(matchList)):
			matchList[i] = getRegEx(matchList[i])
		return tuple(set(super().match(matchList,0)))
	def __setitem__(self, string, value):
		matchList = string.split("/")[1:]
		curNode = self
		for curString in matchList:
			foundNode = None
			for string, node in self.children:
				if curString == string:
					foundNode = node
					break
			if foundNode == None:
				if _stringCheck(curString):
					raise(Exception("Bad character in %s"%curString))
				foundNode = AddressNode()
				curNode.children.append((curString, foundNode))
			curNode = foundNode
		curNode.leaf = value,

"""
Dummied out for now...
class RegexNode:
	reDict = {}
	def __init__(self, regex):
		self.re = regex
		self.children = []
	
class RegexTree:
	def __init__(self):
		self.children = []
	
	def append(self, stringList, value):
		node = self
		for i in stringList:
			curRE = getRegEx(i)
			foundNode = None
			for child in node.children:
				if child.re == curRE:
					foundNode = child
					break
			if foundNode == None:
				foundNode = RegexNode(curRE)
			node = foundNode
"""


def header(p):
	print("\n")
	print(p)
	print("".join(["*"]*len(p)))
	print()

def testEcho(server, message,source):
	message = "ECHO: "+message
	server << Message(message, address="/print")

def testPrint(server, message, source):
	print(source)
	print(message)

def unitTests():
	header("Test the direct creation of various Atoms")
	print(Float(1.0))
	print(Double(1.0))
	print(Int(1))
	print(Long(1))
	print(Blob(b"asdasd"))
	print(String("asdasd"))
	print(TimeTag(datetime.datetime.now()))

	header("Test the direct creation of a message")
	m = Message(address="/")
	m.append(Float(1.0))
	m += [Double(1.0), Int(1), Long(1), Blob(b"asdasd"), String("asdasd")]
	print(m)

	header("Test the indirect creation of various Atoms")
	print(Atom(1.0))
	print(Atom(1))
	print(Atom(True))
	print(Atom(False))
	print(Atom(b"asdasd"))
	print(Atom("asdasd"))
	print(Atom(datetime.datetime.now()))

	header("Test the indirect creation of a bundle")
	b = Bundle(time=datetime.datetime.now(), address="/unitTest")
	b.append([1,2,3,4, True])
	b.append([1.0,"hello"])
	b.append(m)
	print(b)

	header("Test the binarization of a message")
	print(m.bin)

	header("Test the binarization of a bundle")
	print(b.bin)

	header("Test the manual de-binarization of a message")
	mbd = BinaryDecoder(m.bin)
	print(mbd.decode())

	header("Test the manual de-binarization of a bundle")
	bdb = BinaryDecoder(b.bin)
	print(bdb.decode())

	header("Test the address tree creation")
	adt = AddressTree()
	adt["/test1/subtest1"] = 1
	adt["/test1/subtest2"] = 2
	adt["/test2/subtest1"] = 3
	adt["/test2/subtest2"] = 4
	adt["/test2/subtest3"] = 5
	print(adt)

	header("Test retrieving values from the address tree")
	print(adt["/test1/subtest1"])
	print(adt["/test?/subtest1"])
	print(adt["/test2/subtest*"])
	print(adt["/*/subtest{1,2}"])
	print(adt["/*/subtest8"])

	header("Test setting up a server")
	oscServe = Socket(inPort=9000)
	#oscServe.registerDestination("localhost", 9001)
	#oscServe["/echo"] = testEcho
	oscServe["/print"] = testPrint
	oscServe("localhost",9013)["/group3/bool/a"]  << True
	try:
		while True:
			pass
	except:
		oscServe.close()
