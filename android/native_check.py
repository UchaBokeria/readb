"""Reject wrong-target or 4KiB-only JNI libraries before packaging."""
import struct

def validate(data: bytes):
    try:
        if len(data)<64 or data[:6]!=b'\x7fELF\x02\x01' or struct.unpack_from('<HH',data,16)!=(3,183):
            raise ValueError('Expected Android arm64 ELF shared library')
        offset=struct.unpack_from('<Q',data,32)[0]
        size,count=struct.unpack_from('<HH',data,54)
        if size!=56 or not 1<=count<=128 or offset+size*count>len(data):
            raise ValueError('Invalid ELF program header table')
        loads=0
        for i in range(count):
            kind,_,position,virtual,_,filesize,_,alignment=struct.unpack_from('<IIQQQQQQ',data,offset+i*size)
            if kind==1:
                loads+=1
                if alignment<16384 or alignment&(alignment-1) or position%16384!=virtual%16384 or position+filesize>len(data):
                    raise ValueError('JNI library needs 16KiB load alignment')
        if not loads:
            raise ValueError('ELF library has no load segments')
    except struct.error as error:
        raise ValueError('Truncated ELF library') from error
