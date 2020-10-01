#!/usr/bin/env python

"""
__author__ = "Axelle Apvrille"
__status__ = "Alpha"
__copyright__ = "Copyright 2017, Fortinet, Fortiguard Labs"
__license__ = "MIT License"
"""

import argparse
import string
import struct
import zlib
import hashlib

access_flags = { 0x1 : 'ACC_PUBLIC', 0x02 : 'ACC_PRIVATE', 0x04 : 'ACC_PROTECTED', 0x08 : 'ACC_STATIC', 0x10 : 'ACCESS_FINAL', 0x20 : 'ACC_SYNCHRONIZED', 0x40 : 'ACC_VOLATILE', 0x80 : 'ACC_TRANSIENT', 0x100 : 'ACC_NATIVE', 0x200 : 'ACC_INTERFACE', 0x400 : 'ACC_ABSTRACT', 0x1000 : 'ACC_SYNTHETIC', 0x2000 : 'ACC_ANNOTATION', 0x4000 : 'ACC_ENUM', 0x10000 : 'ACC_CONSTRUCTOR', 0x20000 : 'ACC_DECLARED_SYNCHRONIZED' }

class Dex:
    def __init__(self, buffer, verbose=False):
        '''Processes a buffer containing a DEX file and creates a Dex object'''

        self.buffer = buffer # save this
        self.warning_list = [] # processing warning and errors
        self.strings = {}
        self.types = []
        self.protos = []
        self.class_defs = []
        self.class_data = [] # 1 class data per class defs

        # Read the DEX header - uint 32-bit unsigned int, little-endian
        if verbose:
            print "Parsing DEX header..."
        self.magic = buffer[:3]
        self.version = buffer[4:7]
        self.adler32_checksum = struct.unpack('<L', self.buffer[8:0xC])[0]
        self.sha1 = self.buffer[0xC:0x20] # 20 bytes
        self.file_size = struct.unpack('<L', self.buffer[0x20:0x24])[0]
        self.header_size     = struct.unpack('<L', self.buffer[0x24:0x28])[0]
	self.endian_tag      = struct.unpack('<L', self.buffer[0x28:0x2C])[0]
	self.link_size       = struct.unpack('<L', self.buffer[0x2C:0x30])[0]
	self.link_off        = struct.unpack('<L', self.buffer[0x30:0x34])[0]
	self.map_off         = struct.unpack('<L', self.buffer[0x34:0x38])[0]
	self.string_ids_size = struct.unpack('<L', self.buffer[0x38:0x3C])[0]		
	self.string_ids_off  = struct.unpack('<L', self.buffer[0x3C:0x40])[0]
	self.type_ids_size   = struct.unpack('<L', self.buffer[0x40:0x44])[0]
	self.type_ids_off    = struct.unpack('<L', self.buffer[0x44:0x48])[0]
	self.proto_ids_size  = struct.unpack('<L', self.buffer[0x48:0x4C])[0]
	self.proto_ids_off   = struct.unpack('<L', self.buffer[0x4C:0x50])[0]
	self.field_ids_size  = struct.unpack('<L', self.buffer[0x50:0x54])[0]
	self.field_ids_off   = struct.unpack('<L', self.buffer[0x54:0x58])[0]
	self.method_ids_size = struct.unpack('<L', self.buffer[0x58:0x5C])[0]
	self.method_ids_off  = struct.unpack('<L', self.buffer[0x5C:0x60])[0]
	self.class_defs_size = struct.unpack('<L', self.buffer[0x60:0x64])[0]
	self.class_defs_off  = struct.unpack('<L', self.buffer[0x64:0x68])[0]
	self.data_size       = struct.unpack('<L', self.buffer[0x68:0x6C])[0]
        self.data_off = struct.unpack('<L', self.buffer[0x6C:0x70])[0]
        if verbose:
            print self.str_header()

    def in_data_section(self, offset):
        '''tests if a given offset is within the data section or not
        offset 0 is meaningless
        '''
        if offset > 0 and (offset < self.data_off or offset > (self.data_off + self.data_size)):
            return False
        return True


    def check_adler32(self):
        expected = zlib.adler32(self.buffer[0xc:]) & 0xffffffff
        if expected != self.adler32_checksum:
            self.warning_list.append("Wrong Adler32 checksum.\n\tExpecting %d.\n\tGot %d" % (expected, self.adler32_checksum))
            return False
        return True

    def check_sha1(self):
        m = hashlib.sha1()
        m.update(self.buffer[0x20:])
        expected = m.digest()
        if expected != self.sha1:
            self.warning_list.append("Wrong SHA1 digest.\n\tExpecting %s.\n\tGot %s" % (hexbuf_to_string(expected), hexbuf_to_string(self.sha1)))
            return False
        return True

    def check(self, verbose=False):
        '''Checks the consistency of the DEX file: that the header looks right, that
        the checksum and hash are okay, that sections are at the expected place etc'''
        if verbose:
            print "Checking DEX..."
        if self.buffer[3] != '\n':
            self.warning_list.append('newline not found before version')
        if self.buffer[7] != '\x00':
            self.warning_list.append('magic does not end with 0x00')
        self.check_adler32()
        self.check_sha1()
        if self.header_size != 0x70:
            self.warning_list.append("header size is not the expected 0x70")
        if self.endian_tag != 0x12345678:
            self.warning_list.append('This file is using reverse endian (we do not support this in dexview)')
        if self.link_size != 0:
            self.warning_list.append('This file is statically linked')
        if not self.in_data_section(self.map_off):
            self.warning_list.append('Map is beyond the data section')
        if (self.data_off + self.data_size > self.file_size):
            self.warning_list.append('Data section spans beyond file end')
        if  (self.string_ids_off + (self.string_ids_size * 4) > self.file_size):
            self.warning_list.append('String IDs section spans beyond file end')
        if  (self.type_ids_off + (self.type_ids_size *4) > self.file_size):
            self.warning_list.append('Type IDs section spans beyond file end')
        if  (self.proto_ids_off + (self.proto_ids_size *12)> self.file_size):
            self.warning_list.append('Proto IDs section spans beyond file end')
        if  (self.field_ids_off + (self.field_ids_size *8)> self.file_size):
            self.warning_list.append('Field IDs section spans beyond file end')
        if  (self.method_ids_off + (self.method_ids_size *8)> self.file_size):
            self.warning_list.append('Method IDs section spans beyond file end')
        if  (self.class_defs_off + (self.class_defs_size *32)> self.file_size):
            self.warning_list.append('Class defs section spans beyond file end')
        if verbose:
            print self.str_warnings()
        

    def read_string_ids(self, verbose = False):
        if verbose:
            print "Parsing String IDs..."
            
        # string_ids_size = count of strings in the string identifiers list (4 bytes each)
        for position in range(self.string_ids_off, self.string_ids_off+(self.string_ids_size*4),4):
            string_data_off = struct.unpack('<L', self.buffer[position:position+4])[0]
            #print "String data offset: %d" % string_data_off
            
            if not self.in_data_section(string_data_off):
                self.warning_list.append('String data offset %d is beyond data section' % string_data_off)
                
            # read size of the string
            nb_utf16_units = read_uleb128(self.buffer, string_data_off)[0]
            #print "Nb of UTF16 units: %d" % nb_utf16_units
            
            # read data
            self.strings[string_data_off+1] = self.buffer[string_data_off+1:string_data_off+1+nb_utf16_units]
            #print "offset=%d length=%d s=%s" % (string_data_off+1, nb_utf16_units, s)

        if verbose:
            print self.strings

    def get_string(self, index):
        list_of_offsets = sorted(self.strings)
        offset = list_of_offsets[index]
        return self.strings[offset]

    def read_type_ids(self, verbose = False):
        if verbose:
            print "Parsing Type IDs..."
        for position in range(self.type_ids_off, self.type_ids_off+(self.type_ids_size*4),4):
            type_index = struct.unpack('<L', self.buffer[position:position+4])[0]
            self.types.append(self.get_string(type_index))
        if verbose:
            print self.types

    def read_proto_ids(self, verbose=False):
        if verbose:
            print "Parsing Prototype IDs..."
        for idx in range(self.proto_ids_off, self.proto_ids_off+(self.proto_ids_size*12), 12):
            shorty_idx = struct.unpack('<L', self.buffer[idx:idx+4])[0]
            return_type_idx = struct.unpack('<L', self.buffer[idx+4:idx+8])[0]
            parameters_off = struct.unpack('<L', self.buffer[idx+8:idx+12])[0]
            if not self.in_data_section(parameters_off):
                self.warning_list.append('Parameter offset is not in data section: shorty_idx=%d ret_idx=%d offset=%d\n' % (shorty_idx, return_type_idx, parameters_off))
            self.protos.append((shorty_idx, return_type_idx, parameters_off))

    def _read_hhl(self, offset, count):
        array = []
        for idx in range(offset, offset + (count *8), 8):
            a =  struct.unpack('<H', self.buffer[idx:idx+2])[0]
            b =  struct.unpack('<H', self.buffer[idx+2:idx+4])[0]
            c = struct.unpack('<L', self.buffer[idx+4:idx+8])[0]
            array.append((a,b,c))
        return array

    def read_field_ids(self, verbose=False):
        if verbose:
            print "Parsing Field IDs..."
        self._read_hhl(self.field_ids_off, self.field_ids_size)

    def read_method_ids(self, verbose=False):
        if verbose:
            print "Parsing Method IDs..."
        self._read_hhl(self.method_ids_off, self.method_ids_size)
    
    
    def read_class_defs(self, verbose=False):
        if verbose:
            print "Parsing Class Defs IDs..."

        for idx in range(self.class_defs_off, self.class_defs_off+(self.class_defs_size *32), 32):
            class_idx = struct.unpack('<L', self.buffer[idx:idx+4])[0]
            access_flags = struct.unpack('<L', self.buffer[idx+4:idx+8])[0]
            superclass_idx = struct.unpack('<L', self.buffer[idx+8:idx+12])[0]
            interfaces_off =  struct.unpack('<L', self.buffer[idx+12:idx+16])[0]
            source_file_idx =  struct.unpack('<L', self.buffer[idx+16:idx+20])[0]
            annotations_off = struct.unpack('<L', self.buffer[idx+20:idx+24])[0]
            class_data_off = struct.unpack('<L', self.buffer[idx+24:idx+28])[0]
            static_values_off = struct.unpack('<L', self.buffer[idx+28:idx+32])[0]
            if not self.in_data_section(interfaces_off):
                self.warning_list.append('Interfaces offset is not in data section: idx=%d class_idx=%d interfaces_off=%d' % (idx, class_idx, interfaces_off))
            if not self.in_data_section(annotations_off):
                self.warning_list.append('Annotation offset is not in data section: idx=%d class_idx=%d annotations_off=%d' % (idx, class_idx, annotations_off))
            if not self.in_data_section(class_data_off):
                self.warning_list.append('Class data offset is not in data section: idx=%d class_idx=%d offset=%d' % (idx, class_idx, class_data_off))
            if not self.in_data_section(static_values_off):
                self.warning_list.append('Static values offset is not in data section: idx=%d class_idx=%d offset=%d' % (idx, class_idx, static_values_off))
            self.class_defs.append((class_idx, access_flags, superclass_idx, interfaces_off, source_file_idx, annotations_off, class_data_off, static_values_off))
            if class_data_off > 0:
                self.read_class_data(class_data_off, verbose)

    def read_class_data(self, offset, verbose=False):
        if verbose:
            print 'Reading class data at offset=%d' % (offset)
            
        (static_fields_size, offset) = read_uleb128(self.buffer, offset)
        if verbose:
            print 'Static fields size=%d offset=%d' % (static_fields_size, offset)
        (instance_fields_size, offset) = read_uleb128(self.buffer, offset)
        if verbose:
            print 'Instance fields size=%d offset=%d' % (instance_fields_size, offset)
        (direct_methods_size, offset) = read_uleb128(self.buffer, offset)
        (virtual_methods_size, offset) = read_uleb128(self.buffer, offset)

        # static fields
        fields = []
        instances = []
        directs = []
        virtuals = []
        for i in range(0, static_fields_size):
            (a, b, offset) = self.read_encoded_field(offset, verbose)
            fields.append((a,b))
            
        # instance fields
        for i in range(0, instance_fields_size):
            (a, b, offset) = self.read_encoded_field(offset, verbose)
            instances.append((a,b))
            
        # direct methods
        for i in range(0, direct_methods_size):
            if verbose:
                print "Reading direct method #%d / %d at offset %d" % (i, direct_methods_size, offset)
            (a, b,c, offset, code) = self.read_encoded_method(offset, verbose)
            directs.append((a,b,c, code))
            
        # virtual methods
        for i in range(0, virtual_methods_size):
            (a, b,c, offset,code) = self.read_encoded_method(offset, verbose)
            directs.append((a,b,c, code))

        # save information in class data - note we don't save the offset
        self.class_data.append((static_fields_size, instance_fields_size, direct_methods_size, virtual_methods_size, fields, instances, directs, virtuals))
        if verbose:
            print self.class_data

    def read_encoded_field(self, offset, verbose=False):
        ''' Returns
        field_idx_diff
        access_flags
        offset after reading last uleb128
        '''
        (field_idx_diff, offset) = read_uleb128(self.buffer, offset)
        (access_flags, offset) = read_uleb128(self.buffer, offset)
        if verbose:
            print "EncodedField: idx_diff=%d access flags = %s end_offset=%d" % (field_idx_diff, flag_to_string(access_flags), offset)
        return (field_idx_diff, access_flags, offset)

    def read_encoded_method(self, offset, verbose=False):
        (method_idx_diff, offset) = read_uleb128(self.buffer, offset)
        (access_flags, offset) = read_uleb128(self.buffer, offset)
        (code_off, offset) = read_uleb128(self.buffer, offset)
        if verbose:
            print "EncodedMethod: idx_diff=%d access flags = %s Code_off=%d end_offset=%d" % (method_idx_diff, flag_to_string(access_flags), code_off, offset)
        code_item = (0)
        if code_off > 0:
            code_item = self.read_code_item(code_off, verbose)
        if verbose:
            print "Returning encoded method: ",  (method_idx_diff, access_flags, code_off, offset, code_item)
        return (method_idx_diff, access_flags, code_off, offset, code_item)



    def read_code_item(self, offset, verbose=False):
        registers_size = struct.unpack('<H', self.buffer[offset:offset+2])[0]
        ins_size = struct.unpack('<H', self.buffer[offset+2:offset+4])[0]
        outs_size = struct.unpack('<H', self.buffer[offset+4:offset+6])[0]
        tries_size = struct.unpack('<H', self.buffer[offset+6:offset+8])[0]
        debug_info_off = struct.unpack('<L', self.buffer[offset+8:offset+12])[0]
        insns_size =  struct.unpack('<L', self.buffer[offset+12:offset+16])[0]
        if verbose:
            print "Registers=%d Ins=%d Outs=%d Tries=%d Debug=%d Instructions=%d" % (registers_size, ins_size, outs_size, tries_size, debug_info_off, insns_size)

        bytecode = []
        index = offset + 16
        for i in range(0, insns_size):
            value = struct.unpack('<H', self.buffer[index:index+2])[0]
            bytecode.append(value)
            index = index + 2
            if verbose:
                print "Byte code: index=%d value=%d" % (index, value)

        # there's more after
        return (registers_size, ins_size, outs_size, tries_size, debug_info_off, insns_size, bytecode)
                        
        
        
    def read_ids(self, verbose=False):
        self.read_string_ids(verbose)
        self.read_type_ids(verbose)
        self.read_proto_ids(verbose)
        self.fields = self._read_hhl(self.field_ids_off, self.field_ids_size)
        self.methods = self._read_hhl(self.method_ids_off, self.method_ids_size)
        self.read_class_defs(verbose)

    def _patch_offset(self, patch_buffer, insert_offset, insert_len, concerned_offset, begin_offset, end_offset, original_value, name='', verbose=False):
        '''Decides if a given offset in the patch buffer needs to be patched with a new value or not'''
        if (insert_offset < concerned_offset):
            if verbose:
                print '\tPatching %s: %d --> %d' % (name, original_value, original_value+insert_len)
            patch_buffer[begin_offset:end_offset] = struct.pack('<L', original_value+insert_len)
        return patch_buffer

    # ------------------ Modify, hacks

    def modify_class_accessflag(self, idx, flag, verbose=False):
        '''Modifies the access flag of a given class def
        idx is the index in the table of class defs
        flag is the new flag to set'''
        offset = self.class_defs_off + (idx *32)
        class_idx = struct.unpack('<L', self.buffer[offset:offset+4])[0]
        access_flags = struct.unpack('<L', self.buffer[offset+4:offset+8])[0]
        superclass_idx = struct.unpack('<L', self.buffer[offset+8:offset+12])[0]
        interfaces_off =  struct.unpack('<L', self.buffer[offset+12:offset+16])[0]
        source_file_idx =  struct.unpack('<L', self.buffer[offset+16:offset+20])[0]
        annotations_off = struct.unpack('<L', self.buffer[offset+20:offset+24])[0]
        class_data_off = struct.unpack('<L', self.buffer[offset+24:offset+28])[0]
        static_values_off = struct.unpack('<L', self.buffer[offset+28:offset+32])[0]

        # modify access flag
        if verbose:
            print "Patch access flag..."
        patched = list(bytearray(self.buffer))
        patched[offset+4:offset+8] = struct.pack('<L', flag)

        return patch_adler32_and_sha1(patched)



    def patch_offset(self, byte, offset, verbose=False):
        if verbose:
            print "Patching byte at offset=%d to value=%02x" % (offset, byte)

        patched = list(bytearray(self.buffer))

        patched[offset] = byte

        # depending on which offset is being modified this might be insufficient
        
        return patch_adler32_and_sha1(patched)

    def insert_data(self, data, offset, verbose=False):
        if verbose:
            print "Inserting data at offset=%d (0x%04x) len=%d" % (offset, offset, len(data))
            
        newbuffer = self.buffer[:offset] + data + self.buffer[offset:]
        patched = list(bytearray(newbuffer))

        # patch file size
        patched[0x20:0x24] = struct.pack('<L', self.file_size + len(data))

        # patch other parts of header
        self._patch_offset(patched, offset, len(data), self.header_size, 0x24, 0x28, self.header_size, 'header size', verbose)
        if self.link_off > 0:
            self._patch_offset(patched, offset, len(data), self.link_off + self.link_size, 0x2c, 0x30, self.link_off, 'link section', verbose)
        if self.map_off > 0:
            self._patch_offset(patched, offset, len(data), self.map_off, 0x34, 0x38, self.map_off, 'map section', verbose)
        self._patch_offset(patched, offset, len(data), self.string_ids_off + (self.string_ids_size*4), 0x3c, 0x40, self.string_ids_off, 'string ids', verbose)
        self._patch_offset(patched, offset, len(data), self.type_ids_off + (self.type_ids_size*4), 0x44, 0x48, self.type_ids_off, 'type ids', verbose)
        self._patch_offset(patched, offset, len(data), self.proto_ids_off + (self.proto_ids_size*12), 0x4c, 0x50, self.proto_ids_off, 'proto ids', verbose)
        self._patch_offset(patched, offset, len(data), self.field_ids_off + (self.field_ids_size*8), 0x54, 0x58, self.field_ids_off, 'field ids', verbose)
        self._patch_offset(patched, offset, len(data), self.method_ids_off + (self.method_ids_size*8), 0x5c, 0x60, self.method_ids_off, 'method ids', verbose)
        self._patch_offset(patched, offset, len(data), self.class_defs_off + (self.class_defs_size*32), 0x64, 0x68, self.class_defs_off, 'class defs', verbose)
        self._patch_offset(patched, offset, len(data), self.data_off + self.data_size, 0x6c, 0x70, self.data_off, 'data', verbose)
            
        # patch offsets in string ids
        for idx in range(self.string_ids_off, self.string_ids_off+(self.string_ids_size*4),4):
            string_data_off = struct.unpack('<L', self.buffer[idx:idx+4])[0]
            if string_data_off > 0 and offset < string_data_off:
                if offset < idx:
                    patched[idx+len(data):idx+4+len(data)] = struct.pack('<L', string_data_off + len(data))
                else:
                    patched[idx:idx+4] = struct.pack('<L', string_data_off + len(data))
                if verbose:
                    print "\tPatching string_ids[%4d]: offset=%d --> %d" % ((idx-self.string_ids_off) /4, string_data_off, string_data_off + len(data))

        # type ids have indexes to string ids table --> nothing to patch
        # patch parameters offset in proto ids
        for idx in range(self.proto_ids_off, self.proto_ids_off+(self.proto_ids_size*12), 12):
            parameters_off = struct.unpack('<L', self.buffer[idx+8:idx+12])[0]
            if parameters_off > 0 and offset < parameters_off:
                if offset < (idx + 8):
                    patched[idx+8+len(data):idx+12+len(data)] = struct.pack('<L', parameters_off + len(data))
                else:
                    patched[idx+8:idx+12] = struct.pack('<L', parameters_off + len(data))
                if verbose:
                    print '\tPatching proto_ids[%4d]: parameters_off=%d --> %d' % ((idx - self.proto_ids_off)/12, parameters_off, parameters_off + len(data))
        
        # nothing to patch in field ids
        # nothing to patch in method ids
        # patch class defs
        for idx in range(self.class_defs_off, self.class_defs_off+(self.class_defs_size *32), 32):
            interfaces_off =  struct.unpack('<L', self.buffer[idx+12:idx+16])[0]
            annotations_off = struct.unpack('<L', self.buffer[idx+20:idx+24])[0]
            class_data_off = struct.unpack('<L', self.buffer[idx+24:idx+28])[0]
            static_values_off = struct.unpack('<L', self.buffer[idx+28:idx+32])[0]
            if interfaces_off > 0 and offset < interfaces_off:
                if offset < (idx + 12):
                    patched[idx+12+len(data):idx+16+len(data)] = struct.pack('<L', interfaces_off + len(data))
                else:
                    patched[idx+12:idx+16] = struct.pack('<L', interfaces_off + len(data))
                if verbose:
                    print '\tPatching classdefs[%d]:' % ((idx - self.class_defs_off)/32)
                    print '\t\tinterfaces_off=%d --> %d' % (interfaces_off, interfaces_off+len(data))
            if annotations_off > 0 and offset < annotations_off:
                if offset < (idx + 12):
                    patched[idx+20+len(data):idx+24+len(data)] = struct.pack('<L', annotations_off + len(data))
                else:
                    patched[idx+20:idx+24] = struct.pack('<L', annotations_off + len(data))
                if verbose:
                    print '\t\tannotations_off=%d --> %d' % (annotations_off, annotations_off+len(data))
            if class_data_off > 0 and offset < class_data_off:
                if offset < (idx + 24):
                    patched[idx+24+len(data):idx+28+len(data)] = struct.pack('<L', class_data_off + len(data))
                else:
                    patched[idx+24:idx+28] = struct.pack('<L', class_data_off + len(data))
                if verbose:
                    print '\t\tclass_data_off=%d --> %d' % (class_data_off, class_data_off+len(data))
            if static_values_off > 0 and offset < static_values_off:
                if offset < (idx+28):
                    patched[idx+28+len(data):idx+32+len(data)] = struct.pack('<L', static_values_off + len(data))
                else:
                    patched[idx+28:idx+32] = struct.pack('<L', static_values_off + len(data))    
                if verbose:
                    print '\t\tstatic_values_off=%d --> %d' % (static_values_off, static_values_off+len(data))

        # rehash, re-checksum
        if offset > 0x08:
            return patch_adler32_and_sha1(patched)
        return patched

    # ------------------------- Map 
    
    def _map_byte(self, offset, character, newline_color, column_size=32):
        s = ''
        # display left column with offset
        if offset % column_size == 0:
            s = s + '%08x ' % (offset)
            s = s + newline_color
        s = s + character
        # insert a space between 16 bits
        if offset > 0 and (offset % column_size) == 15:
            s = s + ' '
        # end of line
        if offset > 0 and (offset % column_size) == column_size - 1:
            s = s + '\033[0m'
            s = s + '\n'
        return s

    def _map_shorten(self, section_start, character, color, section_len, column_size=32):
        s = color
        offset = section_start
        if section_len > 3 * column_size:
            # display one line
            for j in range(0, column_size):
                s = s + self._map_byte(offset+j, character, color)
            offset = offset+column_size
            # display part of another line
            while (offset % column_size) != 0:
                s = s + self._map_byte(offset, character, color)
                offset = offset + 1
            # display ...
            s = s + '\033[0m         .................................\033[0m\n'
            offset = section_start + section_len - ((section_start + section_len) % column_size)
            # display part of last line
            for j in range(offset, section_start+section_len):
                s = s + self._map_byte(offset+j, character, color)
        else:
            # display all
            for j in range(0, section_len):
                s = s + self._map_byte(offset+j, character, color)
        return s

    def _map_section(self, current_pos, display, section_start, character, color, section_len, verbose=False):
        if current_pos == section_start:
            if verbose:
                print "Inside %c" % (character)
            s = self._map_shorten(section_start, character, color, section_len)
            return (section_start + section_len, display +s)
        return (current_pos, display)
            

    def show_map(self, verbose=False):
        '''Prints out a nice colored section map of the DEX.
        If the DEX is long, will display ... and span over the long sections
        '''
        print("""\
______ _______   __  _____           _   _               _   _ _               
|  _  |  ___\ \ / / /  ___|         | | (_)             | | | (_)              
| | | | |__  \ V /  \ `--.  ___  ___| |_ _  ___  _ __   | | | |_  _____      __
| | | |  __| /   \   `--. \/ _ \/ __| __| |/ _ \| '_ \  | | | | |/ _ \ \ /\ / /
| |/ /| |___/ /^\ \ /\__/ |  __| (__| |_| | (_) | | | | \ \_/ | |  __/\ V  V / 
|___/ \____/\/   \/ \____/ \___|\___|\__|_|\___/|_| |_|  \___/|_|\___| \_/\_/  
        """)
        s = 'Hex      0123456789ABCDEF 0123456789ABCDEF\n'
        s = s + '--------------------------------------------------------------\n'

        # show entire header
        if verbose:
            print "Reading header..."
        for i in range(0, self.header_size):
            s = s + self._map_byte(i, 'H', "\033[1;32;1m")
        i = self.header_size
            
        while i < self.file_size:
            # which section is next?
            save_i = i
            (i, s) = self._map_section(i, s, self.string_ids_off, 'S', '\033[1;32;1m', self.string_ids_size * 4, verbose)
            (i, s) = self._map_section(i, s, self.type_ids_off, 'T', '\033[1;33;1m', self.type_ids_size * 4, verbose)
            (i, s) = self._map_section(i, s, self.proto_ids_off, 'P', '\033[1;34;1m', self.proto_ids_size * 12, verbose)
            (i, s) = self._map_section(i, s, self.field_ids_off, 'F', '\033[1;35;1m', self.field_ids_size * 8, verbose)
            (i, s) = self._map_section(i, s, self.method_ids_off, 'F', '\033[1;36;1m', self.method_ids_size * 8, verbose)
            (i, s) = self._map_section(i, s, self.class_defs_off, 'C', '\033[0;30;41m', self.class_defs_size * 32, verbose)
            (i, s) = self._map_section(i, s, self.data_off, 'D', '\033[0;30;42m', self.data_size, verbose)
            (i, s) = self._map_section(i, s, self.link_off, 'L', '\033[0;30;43m', self.link_size, verbose)
            if i == save_i:
                if verbose:
                    print 'this byte is in no section: offset=%d' % (i)
                s = s + '\033[0;30;47m'  + self._map_byte(i, 'U', '\033[0;30;47m')
                i = i + 1
                s = s + '\033[0m'

        if verbose:
            print "end of show map"
        s = s + '\033[1;37;41m<--END\033[0m'
        print s

    # ------------------------------- str

    def str_header(self):
        # Use ANSI code for color
        s = "\033[1;32;1mHeader ----------------------\n\033[0m" # Bright green
        s = s + "%20s: %3s\n" % ('Magic', mixedbuf_to_string(self.magic))
        s = s + "%20s: %3s\n" % ('Version', mixedbuf_to_string(self.version))
        s = s+"%20s: %d\n" % ("Adler32 checksum", self.adler32_checksum)
        s = s+"%20s: %s\n" % ("SHA1 signature", hexbuf_to_string(self.sha1))
        s = s+"%20s: %d\n" % ("File size", self.file_size)
        s = s+"%20s: %d (0x%02x)\n" % ("Header size", self.header_size, self.header_size)
        s = s+"%20s: %d\n" % ("Endian tag" , self.endian_tag)
        s = s+"%20s: %d\n" % ("Link size", self.link_size)
        s = s+"%20s: %d\n" % ("Link offset", self.link_off)
        s = s+"%20s: %d\n" % ("Map offset", self.map_off)
        s = s+"%20s: %d\n" % ("String IDs size", self.string_ids_size)
        s = s+"%20s: %d\n" % ("String IDs offset", self.string_ids_off)
        s = s+"%20s: %d\n" % ("Type IDs size", self.type_ids_size)
        s = s+"%20s: %d\n" % ("Type IDs offset", self.type_ids_off)
        s = s+"%20s: %d\n" % ("Proto IDs size", self.proto_ids_size)
        s = s+"%20s: %d\n" % ("Proto IDs offset", self.proto_ids_off)
        s = s+"%20s: %d\n" % ("Field IDs size", self.field_ids_size)
        s = s+"%20s: %d\n" % ("Field IDs offset", self.field_ids_off)
        s = s+"%20s: %d\n" % ("Method IDs size", self.method_ids_size)
        s = s+"%20s: %d\n" % ("Method IDs offset", self.method_ids_off)
        s = s+"%20s: %d\n" % ("Class defs size", self.class_defs_size)
        s = s+"%20s: %d\n" % ("Class defs offset", self.class_defs_off)
        s = s+"%20s: %d\n" % ("Data size", self.data_size)
        s = s+"%20s: %d\n" % ("Data offset", self.data_off)
        return s

    def str_warnings(self):
        s = ''
        # display header warnings
        if not self.warning_list:
            s = s + "\033[1;32;1mChecks OK\n\033[0m" # Bright green
        for warning in self.warning_list:
            s = s + "\033[1;31;1mWarning: %s\033[0m\n" % (warning)
        return s

    def str_strings(self):
        '''displays the String IDs section'''
        s = "\033[1;32;1mStrings ----------------------\n\033[0m" # Bright green
        for offset in sorted(self.strings):
            s = s + "offset=%5d - %5d string=%s\n" % (offset, offset+len(self.strings[offset]), self.strings[offset])
        return s

    def str_types(self):
        s = "\033[1;32;1mTypes ----------------------\n\033[0m" # Bright green
        for t in self.types:
            s = s + "type=%s\n" % (t)
        return s

    def str_protos(self):
        s = "\033[1;32;1mPrototypes ----------------------\n\033[0m" # Bright green
        for proto in self.protos:
            prototype = self.get_string(proto[0])
            return_type = self.types[proto[1]]
            s = s + "prototype=%s return-type=%s param-offset=%d\n" % (prototype, return_type, proto[2])
        return s

    def str_fields(self):
        s = "\033[1;32;1mFields ----------------------\n\033[0m" # Bright green
        for field in self.fields:
            class_name = self.types[field[0]]
            type_name = self.types[field[1]]
            name = self.get_string(field[2])
            s = s +"class=%s type=%s name=%s\n" % (class_name, type_name, name)
        return s

    def str_methods(self):
        s = "\033[1;32;1mMethods ----------------------\n\033[0m" # Bright green
        for method in self.methods:
            try:
                class_name = self.types[method[0]]
                type_name = self.types[method[1]]
                name = self.get_string(method[2])
                s = s +"class=%s type=%s name=%s\n" % (class_name, type_name, name)
            except IndexError, e:
                self.warning_list.append('Index error: %s' % str(method))
        return s

    def str_class_defs(self):
        s = "\033[1;32;1mClass defs ----------------------\n\033[0m" # Bright green
        index = 0
        for cdef in self.class_defs:
            class_name = self.types[cdef[0]]
            flags = access_flags[cdef[1]]
            superclass = 'None'
            if cdef[2] != 0xffffffff:
                superclass = self.types[cdef[2]]
            interfaces_off = cdef[3]
            source = 'None'
            if cdef[4] != 0xffffffff:
                source = self.get_string(cdef[4])
            annotations_off = cdef[5]
            class_data_off = cdef[6]
            static_values_off = cdef[7]
            s = s + "class=%s flags=%s superclass=%s sourcefile=%s\n\tinterfaces-off=%d annotations-off=%d class-data-off=%d static-values-off=%d\n" % (class_name, flags, superclass, source, interfaces_off, annotations_off, class_data_off, static_values_off)
            if class_data_off > 0:
                sfs = self.class_data[index][0]
                ifs = self.class_data[index][1]
                dms = self.class_data[index][2]
                vms = self.class_data[index][3]
                s = s + "\tclass data: static-fields-size=%d instance-fields-size=%d direct-methods-size=%d virtual-methods-size=%d\n" % (sfs, ifs, dms, vms)
                j = 4

                # print encoded static field structure
                if sfs > 0:
                    s = s + encoded_field_to_string('static field', self.class_data[index][4])

                # print encoded instance field structure
                if ifs > 0:
                    s = s + encoded_field_to_string('instance field', self.class_data[index][5])

                # print encoded direct method structure
                if dms > 0:
                    s = s + encoded_method_to_string('direct method', self.class_data[index][6])

                # print encoded virtual method structure
                if vms > 0:
                    s = s + encoded_method_to_string('virtual method', self.class_data[index][7])

            index = index + 1

        return s
    
    def __str__(self):
        s = self.str_header()
        s = s + self.str_warnings()
        s = s + self.str_strings()
        s = s + self.str_types()
        s = s + self.str_protos()
        s = s + self.str_fields()
        s = s + self.str_methods()
        s = s + self.str_class_defs()
        return s

# ----------------------------------------------------------------

def hexbuf_to_string(buf):
    '''\xde\xad\xbe\xef -> de ad be ef'''
    out = ''
    for i in range(0, len(buf)):
        out = out + "%02x " % ord(buf[i])
    return out
                   

def mixedbuf_to_string(buf):
    '''\x30\x31\xde\xad\xbe\xef -> 01 de ad be ef '''
    pretty = ''
    printables = set(string.printable)
    for i in range(0,len(buf)):
        if buf[i] in printables:
            pretty = pretty + buf[i]
        else:
            if len(pretty) < 1 or pretty[len(pretty) -1] != ' ':
                pretty = pretty + ' '
            pretty = pretty + "%02x" % ord(buf[i])
    return pretty

def read_uleb128(buffer, offset):
    b = 0xff
    position = 0
    result = 0
    shift = 0
    #print 'ULEB 128: offset=%d' % (offset)
    #print ''.join([ '%02x ' % (ord(i)) for i in buffer[offset:offset+5]])
    while (b & 0x80) != 0:
        b = ord(buffer[offset + position])
        result = result | (( b & 0x7f ) << shift)
        shift = shift + 7
        position = position + 1
        #print "b=%02x result=%d shift=%d position=%d" %(b, result, shift, position)
    #print "result=%d end_offset=%d" % (result, offset+position)
    return result, offset + position

def flag_to_string(flag):
    '''Converts a flag integer to a string'''
    s = ''
    for b in access_flags:
        if flag & b:
            s = s + access_flags[b] + ' '
    return s

def encoded_field_to_string(tag, encoded_field):
    s = ''
    for item in encoded_field:
        s = s + "\t%s: idx=%d access-flag=%s\n" % (tag, item[0], flag_to_string(item[1]))
    return s

def encoded_method_to_string(tag, encoded_method):
    '''returns a string containing the contents of an encoded method
    tag is just some string to print before
    '''
    s = ''
    for item in encoded_method:
        idx = item[0]
        flag = item[1]
        code_off = item[2]
        s = s + "\t%s: idx=%d access-flag=%s code-off=%d\n" % (tag, idx, flag_to_string(flag), code_off)
        print "Encoded_method: code_off=%d" % (code_off)
        if code_off > 0:
            code_item = item[3]
            nb_of_instructions = code_item[5]
            s = s + "\t\tregisters=%d ins=%d outs=%d tries=%d debug=%d nbInstr=%d\n" % (code_item[0], code_item[1], code_item[2], code_item[3], code_item[4], nb_of_instructions)
            s = s + '\t\tbyte code: ' + ''.join([ '%04x ' % (x) for x in code_item[6]]) + '\n'
    return s
       
    
def patch_adler32_and_sha1(dexbuffer, verbose=True):
    '''This will re-compute a correct Adler32 checksum and SHA1 hash for the input dexbuffer 
    and write it to filename'''
    patched = list(bytearray(dexbuffer))
    
    # re-hash on what's after the sha1 field
    hashed_part = ''.join([chr(x) for x in patched[0x20:]])
    m = hashlib.sha1()
    m.update(hashed_part)
    expected_sha1 = m.digest()
    if verbose:
        print 'Patching DEX with SHA1 hash: %s' % (hexbuf_to_string(expected_sha1))

    # re-compute checksum on what's after the checksum field
    adler32_part = expected_sha1 + hashed_part
    expected_adler32 = zlib.adler32(adler32_part) & 0xffffffff
    if verbose:
        print 'Patching DEX with Adler32 checksum: %d' % (expected_adler32)

    # build new dex
    magic_part = ''.join([chr(x) for x in patched[0:8]])
    new_dex = magic_part + struct.pack('<L', expected_adler32) + adler32_part

    return new_dex

def print_warning(s):
    print "\033[1;31;1mWarning: %s\033[0m" % (s)

# ----------------------------------------------------------------

def get_arguments():
    parser = argparse.ArgumentParser(description='Dalvik Executable viewer', prog='dexview', epilog='Greetz from Axelle Apvrille')
    parser.add_argument('-i', '--input', help='input DEX file name', action='store')
    parser.add_argument('-r', '--rehash', help='rehash the DEX', action='store_true')
    parser.add_argument('-s', '--insert', help='insert a string in the Data section', action='store')
    parser.add_argument('-f', '--offset', help='offset to insert a string for instance', action='store', default=0x70)
    parser.add_argument('-m', '--map', help='show DEX section map', action='store_true')
    parser.add_argument('-v', '--verbose', help='more info', action='store_true')
    parser.add_argument('-w','--disable-warnings', help='disable DEX consistency check display', action='store_true', default=False)
    parser.add_argument('--class-idx', help='index in the class ids', action='store')
    parser.add_argument('--access-flag', help='modify access flag for class - expecting hex value', action='store')
    parser.add_argument('--patch', help='value to patch at a given offset - expecting hex value', action='store')
    args = parser.parse_args()
    return args

def main(args):
    dexfile = open(args.input, 'rb').read()
    dex = Dex(dexfile, verbose=args.verbose)
    if not args.disable_warnings:
        dex.check(verbose=args.verbose)

    if not dex.check_sha1() or args.rehash:
        answer = raw_input('Would you like to rehash? (y/n) ')
        if answer == 'y':
            print "Patching..."
            new_dex = patch_adler32_and_sha1(dex.buffer)
            print 'Writing DEX to %s...\n' % (args.input + '.patched')
            f = open(args.input+'.patched','wb')
            f.write(new_dex)
            f.close()
            
    if args.map:
        dex.show_map(verbose=args.verbose)
    elif args.insert:
        try:
            offset = int(args.offset)
            new_dex = dex.insert_data(args.insert, offset=offset, verbose=args.verbose)
            print 'Writing DEX to %s...\n' % (args.input + '.inserted')
            f = open(args.input+'.inserted','wb')
            f.write(new_dex)
            f.close()
        except TypeError:
            print "Bad offset"
    elif args.class_idx:
        flag = args.access_flag.lower()
        if '0x' in flag:
            flag = flag.replace('0x','')
        flag_value = int(flag, 16)
        new_dex = dex.modify_class_accessflag(int(args.class_idx), flag_value, args.verbose)
        print 'Writing DEX to %s...\n' % (args.input + '.flag')
        f = open(args.input+'.flag','wb')
        f.write(new_dex)
        f.close()
    elif args.patch:
        offset = int(args.offset) # offset to patch
        value_s = args.patch.lower() # value to patch with - in hex
        value_s = value_s.replace('0x','')
        value = int(value_s, 16)
        new_dex = dex.patch_offset(value, offset, args.verbose)
        print 'Writing DEX to %s...\n' % (args.input + '.patched')
        f = open(args.input+'.patched','wb')
        f.write(new_dex)
        f.close()
        
    else:
        dex.read_ids(args.verbose)
        print dex
        
if __name__ == "__main__":
    args = get_arguments()
    main(args)
        
            
        
        

    
        
