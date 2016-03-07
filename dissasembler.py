import csv
import string
from registers import regs
import pprint 
import itertools, collections
import re

#binaryPath="test1"
#binaryPath="res/example1.o"
#binaryPath="res/example2.o"
binaryPath="res/ex2"
INSTRUCTIONS_PATH="Instructions.csv"

opcodeInfoMap={'cb':1,'cd':4,'ib':1,'iw':2,'id':4}
rangeMap={'inc':range(0x40,0x48),'dec':range(0x48,0x50),
'push':range(0x50,0x58),'pop':range(0x58,0x60),
'mov':range(0xB8,0xC0),'bswap':range(0xFC9,0xFD0)}

def bigEndian(byteList):
	byteList = byteList[::-1]
	return byteList
def consume(iterator,n):
	if n is None:
		collections.deque(iterator,maxlen=0)
	else:
		next(itertools.islice(iterator, n, n), None)
def take(n,iterable):
	return list(itertools.islice(iterable,n))

def findOperandsLabel(opcode,offset):
	if isinstance(offset,list):
		offset=bigEndian(['{:02x}'.format(ord(b)) for b in offset])
	else:
		offset=[hex(offset)]

#	print offset
	notfound=-1
	dst=""
	src=""
	opcodeInfo=csvDict[opcode][0]
	if opcodeInfo.find("rd")!=notfound:
		#case (+):
		if opcodeInfo.find("+")!=notfound:
			#print rangeMap
			opcode=int(opcode,16)
			regNum=[value.index(opcode) for key,value in rangeMap.iteritems() if opcode in value]
			regNum=regNum.pop()
			regNum='{:03b}'.format(regNum)
			dst=regs[regNum]
			#print bigEndian(offset)
			src=''.join(offset)
			src=src
			if bool(src.strip()):	#not empty
				print dst +", "+ src
			else:
				print dst
	else:
	#offset		
		print ''.join(offset)
	
def extendedRegDigitOpcode(infoOp):
	#print infoOp
	infoField=re.split('[/|\W]',infoOp)
	#print infoField
	regDigit=infoField[1]
	return regDigit
	
	
def access(modrm):
	if (modrm[0],modrm[1])==('1','1'):
		return "direct"
	else:
		return "memory"
def hasSIB(modrm,rm):
	modrm= '{:08b}'.format(ord(modrm))
	#print "modrm: " + str(modrm[0])+str(modrm[1])
	# operands is 8 bits
	if (modrm[0],modrm[1])==('0','1'):
		if rm=='100':
			return True
	if(modrm[0],modrm[1])==('1','0'):
		if rm=='100':
			return True
	if(modrm[0],modrm[1])==('0','0'):
		if rm== '100':
			return True
	if (modrm[0],modrm[1])==('1','1'):
		return False

def calculateOffset(opcode,currentAddress,size,offset1):
	if bool(offset1):
		#print offset
		#print type(offset)
		#print "Passed OFFSET:",
		offset=bigEndian(['{:02x}'.format(ord(b)) for b in offset1])
		
		offset="".join(offset)
		offset=int(offset,16)
		#print offset
		encoding=csvDict[opcode][1]
		opcodeSize=len(opcode)/2
		
		if encoding in ['D','M']:
			
		
			#hiByte=ord(offset1[0])
			#mask=0x80
			#highest order bit is 1
			#print hiByte
			#if mask&hiByte==128:
			#	currentAddress=currentAddress-opcodeSize
		#		newOffset=currentAddress+opcodeSize+size-offset
		#	else:
			currentAddress=currentAddress-opcodeSize
			newOffset=currentAddress+opcodeSize+size+offset			#		print currentAddress," ",opcodeSize," ",size," ",offset
#			print currentAddress
#			print newOffset
			#print newOffset
				
			return newOffset
		else:
			return 0
def findOperandsLabelMODRM(opcode, modrm1,size,iterable,address):
	modrm = '{:08b}'.format(ord(modrm1))
	encoding=csvDict[opcode][1]
	#dst=reg  bits[3-5]i
	
	rm=modrm[5]+modrm[6]+modrm[7]
 #r/m 
	if hasSIB(modrm1,rm):
		#print "HasSIB"
		SIB=take(1,iterable)	
		#print SIB
		address+=1
		sib = '{:08b}'.format(ord(SIB))
		#scale
		ss=sib[0]+sib[1]
		#index
		index=sib[2]+sib[3]+sib[4]
		#base
		base=sib[5]+sib[6]+sib[7]
		#do something
	if encoding == "MR":
		#dst=r/m
		dst=modrm[5]+modrm[6]+modrm[7]
		dst=regs[dst]
		src=modrm[2]+modrm[3]+modrm[4]
		src=regs[src]

		if access(modrm)!="direct":
			print '['+dst+'],'+src
		else:
			
			print dst+','+src

	if encoding =="RM":
		#dst=reg  bits[3-5]
		dst=modrm[2]+modrm[3]+modrm[4]
		dst=regs[dst]
		src=modrm[5]+modrm[6]+modrm[7]
		src=regs[src]
		rm=src  #r/m 
		if hasSIB(modrm1,rm):
			print "SIB clause"
			#SIB=take(size,iterable)	
			#address+=1
			#scale
			#index
			#base
			#do something	
	
		else:
			
			if size == 0:
				if access(modrm)=="direct":
					#reg,reg
					print dst+','+src
				else:
					#reg,r/m
					print dst+',['+src+']'
			if size == 1:
				#reg + disp8
				offset=take(size,iterable)
				offset=['{:02x}'.format(ord(b)) for b in offset]
				offset = ''.join(offset)
				print dst+',DWORD PTR ['+src+'+0x'+offset+']'

			if size == 4:
				#print (modrm[5],modrm[6],modrm[7])
				#print (modrm[0]+modrm[1])
				if(modrm[5],modrm[6],modrm[7])==('1','0','1') and (modrm[0],modrm[1])==('0','0'):
			
					offset=take(size,iterable)
					offset=bigEndian(['{:02x}'.format(ord(b)) for b in offset])
					offset = ''.join(offset)
					print dst+',0x'+offset
				else:	
				#reg + disp32
					
					offset=take(size,iterable)
					offset=['{:02x}'.format(ord(b)) for b in offset]
					offset = ''.join(offset)
					print dst+',DWORD PTR ['+src+'+0x'+offset+']'
	
	#modr/m may refer only to memory
	if encoding =="M":
			
		opInfo=csvDict[opcode][0]
		#print opcode
		#print opInfo
		#print csvDict[opcode][3]
		#print opInfo.find('/')
		if opInfo.find('/') ==-1:
			#print size
			#only take 3 more bytes	
			print size
			amount=size-1
			offset=take(amount,iterable)
			offset.insert(0,modrm1)
			print offset
			#print offset
			tempOff=calculateOffset(opcode,address,size,offset)
			print tempOff
			#if offset calculation needed
			if bool(tempOff):
				offset=tempOff
				#print"test OFFSET: "+ str(offset)
			findOperandsLabel(opcode,offset)
			
		else:
			dst=modrm[5]+modrm[6]+modrm[7]		
			print'['+ regs[dst]+']'
	if encoding=="MI":
		offset=take(size,iterable).pop()
		if size==1:
			#sign extend 8 bits
			offsetbits=ord(offset)
			#print hex(offsetbits)
			#offsetbits='{:08b}'.format(ord(offset))
			mask=0x80
			#highest order bit is 1
			if mask&offsetbits==128:
				extend=0xFFFFFF00
				signExtended=offsetbits|extend
			else:
				extend=0x00000000
				signExtended=offsetbits|extend
			#print "Sign Extended: ",
			dst=modrm[5]+modrm[6]+modrm[7]
			dst=regs[dst]
			print dst+',',
			
			offset='{:08x}'.format(signExtended)
			print '0x'+ offset.strip()
	return 

def sizeOfInstructionMODRM(modrm,opcode,iterable):
	modrm= '{:08b}'.format(ord(modrm))
	#print "modrm: " + str(modrm[0])+str(modrm[1])
	# operands is 8 bits
	if (modrm[0],modrm[1])==('0','1'):
	#	if hasSIB(modrm,rm):
		return 1
	if(modrm[0],modrm[1])==('1','0'):
		return 4
	if(modrm[0],modrm[1])==('0','0'):	
#		if hasSIB(modrm,rm):
			#do something
		#encoding=csvDict[opcode][1]
		#modr/m may refer only to memory
		if(modrm[5],modrm[6],modrm[7])==('1','0','1'):
			#addressing mode=displacement only
			return 4

		return 0

	if (modrm[0],modrm[1])==('1','1'):
		encoding=csvDict[opcode][1]
		if encoding == "MI":
			info=csvDict[opcode][0]
			BYTES=[value for key,value in opcodeInfoMap.iteritems() if info.find(key)!=-1].pop()
			return int(BYTES)
		else:
			#do not advance iterator
			return 0
	
def sizeOfInstruction(opcode):
	encoding=csvDict[opcode][1]
	#print encoding	
	if encoding == "O":
		return 0

	elif hasImmediate(opcode):
		if encoding == "OI":
			info=csvDict[opcode][0]
			BYTES=[value for key,value in opcodeInfoMap.iteritems() if info.find(key)!=-1].pop()
			return int(BYTES)
		else:
	#		print "has immediate"		
			info=csvDict[opcode][0]
			BYTES=[value for key,value in opcodeInfoMap.iteritems() if info.find(key)!=-1].pop()
			return int(BYTES)
	elif encoding == "D":
		info=csvDict[opcode][0]
		BYTES=[value for key,value in opcodeInfoMap.iteritems() if info.find(key)!=-1].pop()
		
		return int(BYTES)
	elif encoding =="NP":
		global no_Offset
		no_Offset=True
		return 0

def instructionDirection(modrm):
	if modrm[1]==0:
		#destination operand is memory location
		return 1
	else:
		#destination operan is register
		return 0
	
	
def hasImmediate(opcode):
	immediateEncoding="I"
	encoding=csvDict[opcode][1]
	if encoding.find("I") != -1:
		return True
	return False
def hasMODRM(byteSequence):
	notMODRMlist=["O","I","OI","D","NP"]
	opcode=byteSequence
	encoding=csvDict[opcode][1]
	if encoding not in notMODRMlist:
		return True
	return False

def unknownOpcode(byteSequence):
	print "Unknown Opcode: "+ byteSequence
	exit()

def isOpcode(byteSequence):
	global modrmTaken
	#check if first byte of opcode is a legal opcode	
	if byteSequence in csvDict:
		#print csvList
		opcodes=[[a,b,c,d,e] for a,b,c,d,e in csvList if b==byteSequence]
		#print opcodes
		#print "lenght :"+str(len(opcodes))
		if len(opcodes) <=1:
			modrmTaken=False
			opcode = byteSequence
			mnemonic=csvDict[opcode][2] #opcode mnemonic
			#print mnemonic  + "-- Opcode: " + opcode
				
			print mnemonic, 
			print "   ", 
			return True
		else:
			modrm=take(1,iterator)
			global address
			address = address + 1
			modrmTaken = True
			modrm = '{:08b}'.format(ord(modrm.pop()))
			digit=modrm[2]+modrm[3]+modrm[4]
			for inst in opcodes:	
				#print inst[1],inst[0]
				infoOp=inst[2]
			 	d=extendedRegDigitOpcode(infoOp)
				if int(digit,2)==int(d):
					op=inst[1]
					ex=inst[2]
					en=inst[3]
					mn=inst[0]
					csvDict[op]=[ex,en,mn]
					opcode=byteSequence
					mnemonic = csvDict[opcode][2]
					print mnemonic, 
					print "   ",
					#print mnemonic +"-- Opcode: "+ opcode
					return True
		
	else:	
		return False
def loadInstructions(instructionsPath):
	global csvList
	csvDict={}
	try:
		instructions = open(instructionsPath,"rb")
	except Exception, e:
		print "Error: Cannot open instructions Path"
		print  e
		print "-----------------------------------"
	with instructions as csvfile:
		CSV = csv.reader(csvfile, delimiter=",", quotechar='"')
		"""for row in CSV:  #each row is a list
			mnemonic=row[0]
			opcode=row[1]
			extendedOpcode=row[2]
			encoding=row[3]
			print mnemonic + str(len(row))"""
		csvList=[[a,b,c,d,e] for a,b,c,d,e in CSV if b.strip()!="Opcode"]
		instructions.seek(0,0)		
		csvDict={opcode:[extendedOpcode, encoding, mnemonic,description] for mnemonic,opcode,extendedOpcode, encoding, description in CSV if opcode.strip() != "Opcode"}
		
		
	#print csvDict
	#print regs
	#expand extended opcodes where '+' is found
	csvDict2 = {key:val for key, val in csvDict.iteritems() if val[0].find("+") is not -1}

	csvDict2={'{:02x}'.format(int(key,16)+i).upper():val for i in range(1,8) for key,val in csvDict2.iteritems()}
	csvDict = dict(csvDict , **csvDict2)
	#pprint.pprint(csvDict)
	return csvDict
global no_Offset
no_Offset=False
#global variable
#Used by: isOpcodei
global csvList
csvList=[]
global csvDict
csvDict=loadInstructions(INSTRUCTIONS_PATH)
byteSequence=""
#mandatory prefixes and escape opcode
prefixes=['66','F2','F3','OF']
global address
address=0
global modrmTaken
modrmTaken=False
with open(binaryPath,"rb") as f:
	
	#for each byte in our object file
	o_bytes=f.read()
	byteList=list(o_bytes)  #convert to list to use iterators
#	for counter in range(len(o_bytes)):
	#iterator = o_bytes.__getitem__(0)
	iterator= byteList.__iter__()

	for counter in iterator:
		
		print "Address: "+str(hex(address)),
		print"    ",
		address+=1 #add current byte
		#currentByte=ord(o_bytes[counter]) #returns an int from binary
		currentByte=ord(counter)
		#print '{:02x}'.format(currentByte).upper(),
		#print currentByte[0] first bit of byte to the left
		#opcode is generally 1 byte for 32-bit, but can be 2 and 3 bytes
		#depending on the prefixes
		byteSequence +='{:02x}'.format(currentByte).upper()
		#currentByte='{:08b}'.format(ord(byte))
		#print currentByte
		#'{:02x}'.format(currentByte).upper()
		if byteSequence not in prefixes: 	
			if isOpcode(byteSequence):
				opcode=byteSequence	
				if hasMODRM(opcode):
				#	print "hasMODRM"
					byteSequence=""
					if not modrmTaken:
						modrm=take(1,iterator).pop()
						address+=1  #modrm
					size=sizeOfInstructionMODRM(modrm,opcode,iterator)
					#print "SIZE: "+str(size)
					findOperandsLabelMODRM(opcode,modrm,size,iterator,address)			
					address+=size  #address of next instruction
					#consume(iterator,size)
					
				if not hasMODRM(opcode):
					offset=[]
					byteSequence=""
					size=sizeOfInstruction(opcode)
					#print "SIZE: "+str(size)
					#if size!=0:
					#print "offset status: "+str(no_Offset)
					if not no_Offset:
						offset=take(size,iterator)
					#	print "Offset exists"
					#	print offset
						tempOff=calculateOffset(opcode,address,size,offset)
						#if offset calculation needed
						if bool(tempOff):
							offset=tempOff
							#print offset
					no_Offset=False
					#print"test OFFSET: "+ str(offset)
					findOperandsLabel(opcode,offset)
					address+=size #address of next instruction
					#consume(iterator,size)			
				#find size of instruction
					
				#increment counter by size of instruction
				#disassemble 
			else:
				#Not opcode
				unknownOpcode(byteSequence)
		else:
			address+=1	
		
		
			
	 
	#print bin(currByte)

	#if opcode[

#define opcodeCheck
#return true if opcode exists in csvDict

#if opcodeCheck = false
#  print error : unknown opcode (opcode)

#opcode is true so continue to next byte
#pull opcode info (en, extOp)

#define MODRMbyte
#check if REG and R/M exists in table
