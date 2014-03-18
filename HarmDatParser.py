import re
import sys
from struct import *

subDir = 'extractedRaw\\'


PAKCED_FILE_TYPE_PLAIN 		= 1
PAKCED_FILE_TYPE_UNKNOWN2 	= 2
PAKCED_FILE_TYPE_COMPRESSED	= 3
PAKCED_FILE_TYPE_UNKNOWN4 	= 4

class PakcedFileHeader:
	def __init__(self,buf,offset):
		[self.packedFileName, self.fileType, self.fileRealSize, self.fileDataOffset] = unpack("=12sBII",buf[offset:offset+0x15])
		self.packedFileName = re.sub('[^A-Za-z0-9\.\-\!]+', '',self.packedFileName) # just make file name more beautiful ;)
		if self.fileType==PAKCED_FILE_TYPE_PLAIN:
			self.fileBuf = buf[self.fileDataOffset:self.fileDataOffset+self.fileRealSize]
			self.fileCompresedSize = self.fileRealSize
		elif self.fileType==PAKCED_FILE_TYPE_COMPRESSED:
			self.fileCompresedSize = unpack("<H",buf[self.fileDataOffset:self.fileDataOffset+2])[0]
			self.fileBuf = buf[self.fileDataOffset+2 : self.fileDataOffset+2+self.fileCompresedSize]
		else:
			self.fileBuf = ''
			self.fileCompresedSize = 0
	def getFileName(self):
		return self.packedFileName
	def getFileDataOffset(self):
		return self.fileDataOffset
	def getFileRealSize(self):
		return self.fileRealSize
	def getFileType(self):
		return self.fileType
	def getFileBuffer(self):
		return self.fileBuf
	def getFileCompresedSize(self):
		return self.fileCompresedSize
	def printInfo(self):
		print("fileName = "+str(self.packedFileName))
		print("fileType = "+str(self.fileType))
		print("fileDataOffset = "+hex(self.fileDataOffset))
		print("fileRealSize = "+hex(self.fileRealSize))
		print("fileCompresedSize = "+hex(self.fileCompresedSize))

class HarmParser:
	def __init__(self,fileName):
		self.HEADER = None
		self.numHeaders = 0
		self.packedFilesHeaders = []
		self.parseFile(fileName)
	def parseFile(self,fileName):
		with open(fileName,"rb") as hFile:
			self.fileBuf = hFile.read()
		self.parseHeader()
		self.parsePackedFilesHeaders()
	def parseHeader(self):
		[self.header, self.numHeaders] = unpack("=32sI",self.fileBuf[0:0x24])
	def parsePackedFilesHeaders(self):
		self.packedFilesHeaders = []
		for i in range(self.numHeaders):
			self.packedFilesHeaders.append(PakcedFileHeader(self.fileBuf,0x24+i*0x15))
	def getPackedFileHeader(self,headerId):
		return self.packedFilesHeaders[headerId]
	def getNumberPackedFileHeader(self):
		return self.numHeaders
	def printInfo(self):
		print('header = '+str(self.header))
		print('numPackedFilesHeaders = '+str(self.numHeaders))
		for i in range(self.numHeaders):
			print('\tfileId = '+str(i))
			packedFile = self.packedFilesHeaders[i]
			print('\tfileName = '+str(packedFile.getFileName()))
			print('\tfileType = '+hex(packedFile.getFileType()))
			print('\tfileDataOffset = '+hex(packedFile.getFileDataOffset()))
			print('\tfileDataSize = '+hex(packedFile.getFileRealSize()))
			if packedFile.getFileType()==PAKCED_FILE_TYPE_COMPRESSED:
				print('\tfileCompresedSize = '+hex(packedFile.getFileCompresedSize()))
			print("")
	def getPackedFileWithBiggerstSize(self):
		maxSize = 0
		packedFileMaxSize = None
		for packedFile in self.packedFilesHeaders:
			if packedFile.getFileRealSize() > maxSize:
				maxSize = packedFile.getFileRealSize()
				packedFileMaxSize = packedFile
		return packedFileMaxSize
	def extractAllFiles(self):
		for packedFile in self.packedFilesHeaders:
			with open(subDir+packedFile.getFileName(),"wb") as hFile:
				hFile.write(packedFile.getFileBuffer())

if __name__ == "__main__":
	if len(sys.argv)!=2:
		fileName = "HARM.DAT"
	else:
		fileName = sys.argv[1]
	
	hp = HarmParser(fileName)
	#hp.printInfo()
	t = hp.getPackedFileWithBiggerstSize()
	print("\n\n\n")
	t.printInfo()
	with open(t.getFileName(),"wb") as hFile:
		hFile.write(t.getFileBuffer())