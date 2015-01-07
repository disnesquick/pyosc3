"""
Open Sound Control for Python 3
Copyright (C) 2013 Trevor Hinkley, University of Glasgow

This library is free software; you can redistribute it and/or modify it under
the terms of the GNU Lesser General Public License as published by the Free
Software Foundation; either version 2.1 of the License, or (at your option) any
later version.

This library is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
details.

You should have received a copy of the GNU Lesser General Public License along
with this library; if not, write to the Free Software Foundation, Inc., 59
Temple Place, Suite 330, Boston, MA  02111-1307  USA

For questions regarding this module contact Trevor Hinkley (trevor.hinkley@glasgow.ac.uk)
"""

import struct, math, datetime, sys, socket, re, time, base64
from threading import Thread
import types
from select import select
from queue import Queue

SOCKET_BUF_SIZE = 4096 * 8


def printBin(byteString):
	a = []
	for i in byteString:
		a.append("%.02X"%i)
	return "".join(a)

class Exception(Exception):
	pass

class Binarize(object):
	def __getattr__(self, name):
		if name == "bin":
			return self.getBinary()
		else:
			return self.__getattribute__(name)

class MetaAtom(type):
	def __init__(cls, name, baseClasses, nameSpace):
		if "pythonClass" in nameSpace:
			Atom.mapPythonToOSC(nameSpace["pythonClass"], cls)
		if "tag" in nameSpace:
			Atom.mapTagToOSC(nameSpace["tag"], cls)



################
#
#   OSC atomic types, which can be encoded into a binary format
#


class Atom(Binarize, metaclass = MetaAtom):
	"""Atom is basic class for encodable OSC types, from which the rest of the OSC data-types are derived
	"""
	toOSCMapping = []
	tagMap = {}
	
	@classmethod
	def mapPythonToOSC(cls, thingFrom, thingTo):
		cls.toOSCMapping.append((thingFrom, thingTo))
	
	@classmethod
	def mapTagToOSC(cls, tag, thingTo):
		cls.tagMap[tag] = thingTo

	def __new__(cls, inThing, bin=None):
		if cls == Atom:
			for pyCls, OSCCls in cls.toOSCMapping:
				if isinstance(inThing, pyCls):
					cls = OSCCls
					break
		if cls == Atom:
			raise(TypeError(str(type(inThing)) + " Cannot be encoded as an OSC type."))
		else:
			neonate = object.__new__(cls)
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
		raise(Exception("Atom should never not have a binary representation."))

	@classmethod
	def reprCType(cls, typeStream):
		""" Return a C representation of the type
		"""
		return cls.cType



class String(Atom):
	""" The length of the resulting string is always a multiple of 4 bytes.
	    The string ends with 1 to 4 zero-bytes ('\x00') 
	"""
	tag = "s"
	pythonClass = str
	def OSCEncode(self):
		stringLength = math.ceil((len(self.val)+1) / 4.0) * 4
		return struct.pack(">%ds" % (stringLength), bytes(self.val,encoding="ASCII"))
	
	@classmethod
	def readBinary(cls, binaryReader):
		"""Reads the next (null-terminated) block of data
		"""
		return binaryReader.readString()

class Blob(Atom):
	""" An OSC-Blob is a binary encoded block of data, prepended by a 'size' (int32).
	    The size is always a mutiple of 4 bytes. 
	    The blob ends with 0 to 3 zero-bytes ('\x00') 
	"""
	tag = "b"
	pythonClass = bytes
	def OSCEncode(self):
		if isinstance(self.val, Atom):
			val = self.val.bin
		else:
			val = self.val
		blobLength = math.ceil((len(val)) / 4.0) * 4
		return struct.pack(">i%ds" % (blobLength), blobLength, val)

	@classmethod
	def readBinary(cls, binaryReader):
		length, = struct.unpack(">i", binaryReader.readData(4))
		return binaryReader.readData(length)



class Boolean(Atom):
	""" A boolean value, this will be encoded as a type-tag only
	"""
	pythonClass = bool
	def __init__(self, inThing):
		self.val = inThing
		if inThing:
			self.tag = "T"
		else:
			self.tag = "F"
		self.bin = b""
	def OSCEncode(self):
		return b""
	

class TrueBool(Boolean):
	tag = "T"
	@classmethod
	def readBinary(cls, binaryReader):
		return True

class FalseBool(Boolean):
	tag = "F"
	@classmethod
	def readBinary(cls, binaryReader):
		return False

class Float(Atom):
	""" A 32-bit floating-point value
	"""
	tag = "f"
	pythonClass = float
	def OSCEncode(self):
		return struct.pack(">f", self.val)

	@classmethod
	def readBinary(cls, binaryReader):
		return struct.unpack(">f", binaryReader.readData(4))[0]

class Double(Atom):
	#Don't announce this one
	""" A 64-bit floating-point value
	"""
	tag = "d"
	def OSCEncode(self):
		return struct.pack(">d", self.val)
	
	@classmethod
	def readBinary(cls, binaryReader):
		return struct.unpack(">d", binaryReader.readData(8))[0]

class Int(Atom):
	""" A 32-bit integer value
	"""
	tag = "i"
	pythonClass = int
	def OSCEncode(self):
		return struct.pack(">i", self.val)

	@classmethod
	def readBinary(cls, binaryReader):
		return struct.unpack(">i", binaryReader.readData(4))[0]

class Long(Atom):
	#Don't announce this one
	""" A 64-bit integer value
	"""
	tag = "h"
	def OSCEncode(self):
		return struct.pack(">q", self.val)
	
	@classmethod
	def readBinary(cls, binaryReader):
		return struct.unpack(">q", binaryReader.readData(8))[0]

class TimeTag(Atom):
	""" A time tag, this will encoded into a 64-bit NTP value
	"""
	tag = "t"
	pythonClass = datetime.datetime
	NTPEpoch = datetime.datetime(1900,1,1,0,0)
	NTPUnitsPerSecond = 0x100000000
	NTPUnitsPerMicrosecond = 0x100000000 / 1000000
	def OSCEncode(self):
		delta = self.val - self.NTPEpoch 
		secs = delta.total_seconds()
		fract, secs = math.modf(secs)
		binary = struct.pack('>LL', int(secs), int(fract * self.NTPUnitsPerSecond))
		return binary
	
	def __repr__(self):
		return "osc"+self.__class__.__name__+"("+str(self.val)+")"
	
	@classmethod
	def readBinary(cls, binaryReader):
		high, low = struct.unpack(">LL", binaryReader.readData(8))
		if high == 0 and low == 1:
			return cls.now
		return cls.NTPEpoch + datetime.timedelta(seconds = high, microseconds = low / cls.NTPUnitsPerMicrosecond)

class Immediately(TimeTag):
	""" A special timetag specifying immediate execution
	"""
	instance = None
	def __init__(self):
		self.bin = self.OSCEncode()

	def __new__(cls):
		if not cls.instance:
			cls.instance =  object.__new__(cls)
			cls.instance.__init__()
		return cls.instance

	def OSCEncode(self):
		binary = struct.pack('>LL', 0, 1)
		return binary

	def __repr__(self):
		return "<NOW!>"

TimeTag.now = Immediately()

class Array(Atom):
	""" An implementation of the python "list", as opposed to the python tuple, which gets encoded as a message
	"""
	tag = "["
	pythonClass = list
	cType = "OSCArray"
	def __init__(self, inThing):
		self.val = [i if isinstance(i,Atom) else Atom(i) for i in inThing]
		self.tag = "[%s]"%"".join([i.tag for i in self.val])
		self.bin = self.OSCEncode()
	
	def OSCEncode(self):
		return b"".join([i.bin for i in self.val])

	@classmethod
	def readBinary(cls, binaryReader):
		ary = []
		for tag in binaryReader.typeTags:
			#Array is a special case
			if tag == "]":
				return ary
			else:
				ary.append(binaryReader.decodeByTag(tag))
		raise(Exception("Array does not end"))


#TODO: Consider making this take a subsequent representation
class MessageTag(Atom):
	"""Tag appended to a message so that it can be uniquely identified
	"""
	tag = "#"
	@classmethod
	def readBinary(cls, binaryReader):
		return cls(Int.readBinary(binaryReader))



################
#
#   OSC encapsulation types
#



class Message(Atom):
	def __init__(self, address, *args):
		"""Instantiate a new OSCMessage.
		The OSC-address can be specified with the 'address' argument.
		The rest of the arguments are appended as data.
		"""
		self.message = []
		self.setAddress(address)
		for arg in args:
			self.append(arg)

	def __new__(cls, address, *args):
		neonate = object.__new__(cls)
		neonate.__init__(address, *args)
		return neonate
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



class Bundle(Message):
	headerString = String("#bundle")
	def __init__(self, time, *args):
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
		if not isinstance(argument, (Message, Bundle)):
			raise(TypeError("Can only add a Message or a Bundle to a Bundle"))
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
	def __repr__(self):
		return "bundle:%s"%super().__repr__()

class RecvMessage(list):
	messageTag = None

	def __init__(self, address):
		self.address = address
	def __repr__(self):
		return "message:%s"%super().__repr__()

class OSCZeroDataError(Exception):
	""" This class is the exception for cases where a zero data blob
	    is received which some clients use to signal socket disconnection (aka LabView Fuckup) 
        """
	pass

class OSCDecoder:
	align = 4
	def __init__(self, data, pos = 0, remnantStream = None):
		self.data = data
		self.pos = pos
		self.remnant = remnantStream

	def bufferEmpty(self):
		if self.pos >= len(self.data):
			self.data = b""
			self.pos = 0
			return True
		else:
			return False

	def fillFromRemnant(self):
		if not self.remnant:
			raise(IndexError( "Bytestream is truncated '%s'"%self.data[self.pos:]))
		self.data = self.data[self.pos:]
		self.pos = 0
		newData = self.remnant.read(SOCKET_BUF_SIZE)
		if len(newData) == 0:
			raise(OSCZeroDataError)
		self.data = self.data + newData

	def _checkPos(self, length):
		while self.pos+length > len(self.data):
			self.fillFromRemnant()

	def alignPos(self, pos):
		align = pos % self.align
		if align:
			return pos - align + self.align
		else:
			return pos

	def readData(self, length):
		nextPos = self.pos + length
		while nextPos > len(self.data):
			self.fillFromRemnant()
			nextPos = self.pos + length
		ret = self.data[self.pos:nextPos]
		self.pos = self.alignPos(nextPos)
		return ret

	def readString(self):
		nextPos = self.data.find(b"\0",self.pos)
		while nextPos == -1:
			self.fillFromRemnant()
			nextPos = self.data.find(b"\0",self.pos)
		ret = self.data[self.pos:nextPos]
		self.pos = self.alignPos(nextPos+1)
		return ret.decode("ASCII")

	def decodeByTag(self, tag):
		if not tag in Atom.tagMap:
			raise(Exception("Error on tag '%s' at '%s' with %s "%(tag,printBin(self.data[self.pos:]), printBin(self.data))))
		return Atom.tagMap[tag].readBinary(self)

	def decode(self):
		address = self.readString()
		if address == "#bundle":
			return self.decodeBundle()
		else:
			return self.decodeMessage(address)

	def decodeBundle(self):
		decoded = RecvBundle(TimeTag.readBinary(self))
		while self.pos < len(self.data):
			length = Int.readBinary(self)
			decoded.append(OSCDecoder(self.data,self.pos).decode())
			self.pos += length
		return decoded

	def decodeMessage(self, address):
		decoded = RecvMessage(address)
		typeTags = String.readBinary(self)
		self.typeTags = iter(typeTags)
		if next(self.typeTags) != ",":
			raise (Exception("Message's typetag-string lacks the magic ','."))
		else:
			for tag in self.typeTags:
				datum = self.decodeByTag(tag)
				if isinstance(datum, MessageTag):
					decoded.responseTag = datum.val
				else:
					decoded.append(datum)
		return decoded

class SocketWrapper:
	""" SocketWrapper is a class which acts as an intermediate
	    between the OSC decoder and the actual socket
	"""
	def __init__(self, socket):
		self.sock = socket
	def read(self, n):
		return self.sock.recv(n)

class SocketWrapperSLIP:
	def __init__(self, socket):
		self.sock = socket
	def read(self, n):
		return self.sock.recv(n)

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
		reDict[pattern] = re.compile(pattern+"$")
	return reDict[pattern]

badList=" #*,/?[]{}"
def _stringCheck(string):
	for i in badList:
		if i in string:
			return True
	return False


class OSCSelector:
	def matchFull(self, stringList):
		if len(self) != len(stringList):
			return False
		for i,j in zip(self.matchList, stringList):
			if not i.match(j):
				return False
		return True
	def __init__(self, string):
		self.matchString = string
		self.matchList = [getRegEx(i) for i in string.split("/")[1:]]
	def __len__(self):
		return len(self.matchList)
	def __getitem__(self, idx):
		return self.matchList[idx]

class AddressResolver:
	def retrieveAddress(self, string):
		matchList = OSCSelector(string)
		return tuple(set(self.match(matchList,0)))


class AddressNode(AddressResolver):
	def __init__(self):
		self.children = []
		self.leaf = ()
		self.subs = []
	def match(self, matchList, pos):
		if pos == len(matchList):
			return self.leaf
		matcher = matchList[pos]
		matches = tuple()
		for string, node in self.children:
			if matcher.match(string):
				matches += node.match(matchList,pos+1)
		for sub in self.subs:
			matches += sub.match(matchList[pos:], 0)
		return matches


class AddressTree(AddressNode):
	""" Address tree is used to store the response-address tree for a Responder/Socket
	"""
	def __getitem__(self, string):
		return self.retrieveAddress(string)
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
		if isinstance(value, (AddressTree, Responder)):
			curNode.subs.append(value)
		else:
			curNode.leaf = (value,) + curNode.leaf


class MetaResponder(type, AddressResolver):
	class Exposure:
		def __init__(self, func, path):
			self.func = func
			self.path = path
	
	@classmethod
	def expose(cls, path):
		def inner(func):
			return cls.Exposure(func, path)
		return inner
	
	def __new__(cls, name, bases, nameSpace):
		del nameSpace["expose"]
		targets = list()
		for i in nameSpace:
			e = nameSpace[i]
			if isinstance(e, MetaResponder.Exposure):
				targets.append(e)
				nameSpace[i] = e.func
		nameSpace["classTargets"] = targets
		return super().__new__(cls, name, bases, nameSpace)
	
	def __init__(self, name, bases, nameSpace):
		targets = AddressTree()
		for i in nameSpace["classTargets"]:
			targets[i.path] = i.func
		self.classTargets = targets
	
	@classmethod
	def __prepare__(meta, name, bases):
		return dict(expose=meta.expose)

class Responder(metaclass = MetaResponder):
	@classmethod
	def match(cls, matchList, pos):
		"""Used to retrieve a split address from this object"""
		response = cls.classTargets.match(matchList, pos)
		for sup in cls.__bases__:
			if isinstance(sup, Responder):
				response = response + sup.match(matchList, pos)
		return response

	@classmethod
	def getResponse(cls, address):
		response = cls.classTargets[address]
		for sup in cls.__bases__:
			if issubclass(sup, Responder):
				response = response + sup.getResponse(address)
		return response




class SocketSend:
	def __init__(self, socket, IPAddr = None, OSCAddr = None, sendTag = None):
		self.sock = socket
		self.IPAddr = IPAddr
		self.OSCAddr = OSCAddr
		self.OSCSendTag = sendTag

	def __getitem__(self, OSCAddr):
		if self.OSCSendTag:
			raise(Exception("Tagged send cannot be further subsetted"))
		origin = None
		if self.OSCAddr:
			OSCAddr = self.OSCAddr = OSCAddr
		return SocketSend(self.sock, self.IPAddr, OSCAddr)
	
	def __lshift__(self, thing):
		return self.send(thing)

	def send(self, thing):
		if not self.OSCAddr:
			raise(Exception("No OSC destination has been specified"))
		if None is thing:
			thing = Message(self.OSCAddr)
		elif not isinstance(thing, tuple):
			thing = Message(self.OSCAddr, thing)
		else:
			thing = Message(self.OSCAddr, *thing)
		if self.IPAddr:
			self.sock.sendto(thing.bin, self.IPAddr)
		else:
			self.sock.sendall(thing.bin)



class OSCDeviceResponder(Responder):
	def __init__(self, parallelMessages = False):
		self.prlMsg = parallelMessages
		self.targets = None

	def __setitem__(self, target, handle):
		self.addTarget(target, handle)
	
	def addTarget(self, target, handle):
		""" Add an instance target to this OSC socket
		"""
		if self.targets:
			self.targets[target] = handle
		else:
			raise(Exception("Socket was not set up as a listening socket"))

	def logMessageException(self, packet, exception):
		print(self, packet.address, packet, exception)

	def runMessage(self, handle, packet, source):
		response = self.makeResponse(packet, source)
		try:
			handle(response, *packet)
		except Exception as E:
			self.logMessageException(args, E)

	def makeResponse(self, packet, source):
		if packet.messageTag:
			response = SocketResponse(self, packet.messageTag, source)
		else:
			response = SocketSend(self, source)
		return response

	def handleMessage(self, packet, source):
		if isinstance(packet, RecvBundle):
			Thread(target=self.handleBundle, args=(packet,source)).start()
		elif isinstance(packet, RecvMessage):
			handles = self.getResponse(packet.address)
			if self.targets != None:
				handles = handles + self.targets[packet.address]
			if len(handles) == 0:
				self.logMessageException(packet, Exception("Message has no targets"))
			else:
				if self.prlMsg:
					for handle in handles:
						Thread(target=self.runMessage, args = (handle, packet, source)).start()
				else:
					for handle in handles:
						self.runMessage(handle, packet, source)
	
	#TODO: This probably shouldn't be done this way
	#      it would be better to have a priority queue so a bazillion threads aren't made?
	def handleBundle(self, packet, source):
		delta = (datetime.datetime.now() - packet.time).total_seconds()
		if delta > 0:
			sleep(delta)
		for i in packet:
			self.handleMessage(i, source)


class OSCDevice(OSCDeviceResponder):
	def __init__(self, parallelMessages = False):
		super().__init__(parallelMessages)
		self.baseProxy = SocketSend(self)
		self.tagCount = 0
		self.running = False
		self.outAddresses = set()
		self.whiteList = []

	def __getitem__(self, arg):
		return self.baseProxy[arg]
	
	def __call__(self, address, port):
		return SocketSend(self, IPAddr=(address,port))

	def __del__(self):
		if self.running:
			self.close()
	
	def generateTag(self, responseAddress):
		self.tagCount += 1
		return self.tagCount

	def addToWhiteList(self, address):
		""" Add an address to the white-list. If there is currently no
		    white-list then this function will create the white-list
		"""
		if not ":" in address:
			address = address+":[0-9]+"
		self.whiteList.append(re.compile(address+"$"))
	
	def isWhiteListed(self, source):
		""" If a white-list has been added to this OSC socket then this
		    function will check whether the source is registerd in that
		    list and return the results. Returns True if there is no
		    white-list
		"""
		if not self.whiteList:
			return True
		for wl in self.whiteList:
			if wl.match("%s:%d"%source):
				return True
		return False
	
	def registerDestination(self, address, port):
		""" Add an address to the broadcast list for this socket, all messages
		    sent out in broadcast mode will now be sent to this address.
		"""
		self.outAddresses.add((address, port))
	
	def sendall(self, thing):
		""" Send a message out in broadcast mode
		"""
		if isinstance(thing, Message):
			for dest in self.outAddresses:
				self.sendto(thing, dest)
		else:
			raise(Exception("Invalid thing being sent down the tubes: "+repr(thing)))
	
	def close(self):
		self.running = False

	def __lshift__(self, thing):
		self.sendall(thing)
	
class DecodingError(Exception):
	pass

class HandlingError(Exception):
	pass


class OSCDeviceUDP(OSCDevice):
	# set socket buffer sizes (32k)

	def __init__(self, inPort=None, parallelMessages = False, addressFamily = socket.AF_INET):
		super().__init__(parallelMessages = parallelMessages)
		if inPort != None:
			self.targets = AddressTree()
			self.connectInUDP(inPort,addressFamily)
			self.outSocket = self.inSocket
		else:
			self.connectOutUDP(addressFamily)
			self.inSocket = None
		self.outSocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
		self.outSocket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_BUF_SIZE)

	def connectInUDP(self, inPort, addressFamily):
		""" Called during initialization to create a UDP socket in listen
		    mode. This socket is create asynchronously.
		"""
		self.inSocket = socket.socket(addressFamily, socket.SOCK_DGRAM)
		self.inSocket.settimeout(1)
		self.inSocket.bind(("",inPort))
		self.thread = Thread(target=self.listenUDPThread)
		self.thread.start()

	def connectOutUDP(self, addressFamily):
		""" Called during initialization to create a UDP socket if this
		    OSC socket has not been created in listen mode
		"""
		self.outSocket = socket.socket(addressFamily, socket.SOCK_DGRAM)
		self.outSocket.bind(("",0))

	def listenUDPThread(self):
		self.running = True
		while self.running:
			try:
				data,source = self.inSocket.recvfrom(SOCKET_BUF_SIZE)
				if self.isWhiteListed(source):
					try:
						packet = OSCDecoder(data).decode()
					except:
						raise(DecodingError())
					try:
						self.handleMessage(packet, source)
					except Exception as e:
						raise(HandlingError(e))
				else:
					print("Invalid attempt to access from %s"%repr(data[1]))
			except socket.error:
				pass
			except DecodingError:
				print("Invalid message from (%s,%s)"%source)
			except HandlingError as e:
				print("Error handling message %s with %s"%(data, e))
				
	def close(self):
		super().close()
		self.outSocket.close()

	def sendto(self, thing, address):
		""" Send a message out to a specific address
		"""
		return self.outSocket.sendto(thing, address)


class SLIPException(Exception):
	pass

SLIP_END = 0xC0
SLIP_ESC = 0xDB
SLIP_ESC_END = 0xDC
SLIP_ESC_ESC = 0xDD
class SLIPEncoderDecoder:
	""" This class acts as an intermediary to a socket, it sends data packets in
	    SLIP format and processes incoming (in SLIP) to normal datagrams
	"""
	def __init__(self, socket):
		self.socket = socket
		self.inPacketBuf = Queue()
		self.workingRetrievalBuffer = None

	def sendPacket(self, packet):
		tempSLIPBuffer = bytearray()  
		tempSLIPBuffer.append(SLIP_END)  
		for i in packet:  
			if i == SLIP_END:  
				tempSLIPBuffer.append(SLIP_ESC)  
				tempSLIPBuffer.append(SLIP_ESC_END)  
			elif i == SLIP_ESC:  
				tempSLIPBuffer.append(SLIP_ESC)  
				tempSLIPBuffer.append(SLIP_ESC_ESC)  
			else:  
				tempSLIPBuffer.append(i)  
		tempSLIPBuffer.append(SLIP_END)
		self.socket.send(bytes(tempSLIPBuffer))

	def getPacket(self):
		if self.inPacketBuf.empty():
			self.retrieveData()
		return self.inPacketBuf.get()

	def dataWaiting(self):
		return not self.inPacketBuf.empty()

	def retrieveData(self):
		workingBuf = self.workingRetrievalBuffer
		while self.inPacketBuf.empty():
			newData = self.socket.recv(SOCKET_BUF_SIZE)
			newData = iter(newData)
			for i in newData:
				if i == SLIP_END:
					if workingBuf is None:
						workingBuf = bytearray()
					else:
						self.inPacketBuf.put(bytes(workingBuf))
						workingBuf = None
					
				elif i == SLIP_ESC:
					i = newData.__next__()
					if i == SLIP_ESC_END:
						workingBuf.append(SLIP_ESC)
					elif i == SLIP_ESC_ESC:
						workingBuf.append(SLIP_ESC)
					else:
						raise(SLIPException("Unexpected byte %x following ESCAPE character"%i))
				else:
					workingBuf.append(i)
		self.workingRetrievalBuffer = workingBuf
					

class OSCDeviceTCP(OSCDevice):
	def __init__(self, inPort=None, parallelMessages = False, addressFamily = socket.AF_INET):
		super().__init__(parallelMessages = parallelMessages)
		if inPort != None:
			self.targets = AddressTree()
			self.connectInTCP(inPort,addressFamily)
		self.sockets = {}
		self.decoders = {}

	def connectInTCP(self, inPort, addressFamily):
		self.inSocket = socket.socket(addressFamily, socket.SOCK_STREAM)
		self.inSocket.settimeout(1)
		self.inSocket.bind(("",inPort))
		self.thread = Thread(target=self.listenTCPThread)
		self.thread.start()

	def connectOutTCP(self, destIP, destPort, addressFamily = socket.AF_INET):
		if (destIP,destPort) in self.sockets:
			return self.sockets[(destIP,destPort)]
		outSocket = socket.socket(addressFamily, socket.SOCK_STREAM)
		outSocket.settimeout(1)
		outSocket.connect((destIP,destPort))
		self.handleNewConnection((destIP,destPort),outSocket)
		return outSocket

	def closeOutTCP(self, destIP, destPort):
		if (destIP,destPort) in self.sockets:
			self.sockets[(destIP,destPort)].close()
			del self.sockets[(destIP,destPort)]

	def getSocketAddress(self, sock):
		for k,v in self.sockets.items():
			if v == sock:
				return k


	def listenTCPThread(self):
		""" The main listening thread, this thread listens for new connections and sends them
		    to handleNewConnection for filtering. If they pass muser (default is to auto-accept)
		    then they can be added to the list of sockets to listen for data on. Because TCP
		    is stream-oriented, data is handled differently than in UDP.
		"""
		self.inSocket.listen(10)
		allSockets = [self.inSocket]
		while True:
			readSockets,_,errorSockets = select(allSockets,[],allSockets)
			for sock in readSockets:
				#Handle new connecting socket
				if sock is self.inSocket:
					neonateSocket, addr = self.inSocket.accept()
					if self.handleNewConnection(addr, neonateSocket):
						allSockets = [self.inSocket]+list(self.sockets.values())
				else:
					try:
						decoder = self.decoders[sock]
						data = decoder.getPacket()
						try:
							packet = OSCDecoder(data).decode()
						except OSCZeroDataError:
							raise(socket.error)
						except Exception as e:
							raise(DecodingError(e))
						try:
							self.dispatchHandleMessage(packet, sock)
						except Exception as e:
							raise(HandlingError(e))
						if decoder.dataWaiting():
							readSockets.append(sock)
					# TODO: All of the below should be moved to some kind of status
					#       log stream.
					except socket.error:
						print("Connection closed by peer")
						errorSockets.append(sock)
					except DecodingError:
						print("Invalid message from (%s,%s)"%self.getSocketAddress(sock))
						errorSockets.append(sock)
					except HandlingError:
						print("Error handling message %s"%data)
						errorSockets.append(sock)
			#Handle disconnections
			for sock in errorSockets:
				self.closeConnection(sock)
				allSockets = [self.inSocket]+list(self.sockets.values())

	def handleNewConnection(self, addr, neonateSocket):
		self.sockets[addr] = neonateSocket
		self.decoders[neonateSocket] = SLIPEncoderDecoder(neonateSocket)
		return True

	def closeConnection(self, socket):
		err = self.getSocketAddress(socket)
		del self.sockets[err]
		del self.decoders[socket]		
		socket.close()

	def sendto(self, thing, address):
		""" Send a message out to a specific address
		    The connection to the address will be kept until it is manually closed
		"""
		outSocket = self.connectOutTCP(*address)
		outDecoder = self.decoders[outSocket]
		outDecoder.sendPacket(thing)


	def dispatchHandleMessage(self, packet, sock):
		source = self.getSocketAddress(sock)
		self.handleMessage(packet, source)

	def close(self):
		super().close()
		for i in self.sockets.items():
			i.close()
		self.inSocket.close()

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
	print(Array(["asdasd","mooop"]))
	print(TimeTag(datetime.datetime.now()))

	header("Test the direct creation of a message")
	m = Message("/")
	m.append(Float(1.0))
	m += [Double(1.0), Int(1), Long(1), Blob(b"asdasd"), String("asdasd"),Array(["asdasd","mooop"])]
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
	b = Message("/unitTest")
	b.append([1,2,3,4, True])
	b.append([1.0,["hello"]])
	b = Bundle(Immediately(), b)
	print(b)

	
	header("Test the binarization of a message")
	print(m.bin)

	header("Test the binarization of a bundle")
	print(b.bin)

	header("Test the manual de-binarization of a message")
	mbd = OSCDecoder(m.bin)
	print(mbd.decode())

	header("Test the manual de-binarization of a bundle")
	bdb = OSCDecoder(b.bin)
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
	oscServe = Socket(inPort=9001)
	#oscServe.registerDestination("localhost", 9001)
	#oscServe["/echo"] = testEcho
	#oscServe["/print"] = testPrint
	oscServe("localhost",9013)["/group3/bool/a"]  << True
	try:
		while True:
			pass
	except:
		oscServe.close()
