#! /usr/bin/env python

"""
__author__ = "Axelle Apvrille"
__status__ = "Alpha"
__copyright__ = "Copyright 2018, Fortinet, Fortiguard Labs"
__license__ = "MIT License"


The program takes only one argument: the filename of the APK to inspect

"""


import struct
import sys
import re

# ------------------------------- Parsing ZIP -------------

def parse_apk(data):
    '''Parses an Android Package. This is mainly a ZIP file, but there is an APK Sig Block in addition
    data = content of file
    '''
    for eocd in re.finditer("PK\5\6", data):
        parse_eocd(data, eocd.start())

    for cd in re.finditer("PK\1\2", data):
        parse_cd(data, cd.start())

    for lfh in re.finditer("PK\3\4", data):
        parse_file(data, lfh.start())

    for sb in re.finditer("APK Sig Block 42", data):
        parse_signing_block(data, sb.start())


def parse_eocd(data, offset):
    '''Parses End of Central Directory structure in ZIP file
    data = content of the entire APK
    offset = offset to the beginning of EOCD
    '''
    print "\033[1;33;1m---------------- End of Central Directory ------------"
    print "Offset: %d (0x%08x)" % (offset, offset)
    eocd = data[offset:]
    signature = eocd[0:4]
    #print "Tag : ", signature
    disk_number = struct.unpack("<H", eocd[4:6])[0]
    start_disk_number = struct.unpack("<H", eocd[6:8])[0]
    entries_on_disk =  struct.unpack("<H", eocd[8:10])[0]
    entries_in_directory = struct.unpack("<H", eocd[10:12])[0]
    print "Entries in directory        = %d" % (entries_in_directory)
    directory_size = struct.unpack("<L", eocd[12:16])[0]
    print "Directory size              = %d" % (directory_size)
    directory_offset = struct.unpack("<L", eocd[16:20])[0]
    print "Offset to Central Directory = %d (0x%08x)" % (directory_offset, directory_offset)
    comment_length = struct.unpack("<h", eocd[20:22])[0]
    print "Comment length              = %d" % (comment_length)
    comment = eocd[22:22+comment_length]
    print "Comment: %s" % (comment)
    print "\033[0m"
    return directory_offset

def parse_cd(data, offset):
    '''
    parses Central Directory header for ZIP file
    data = content of APK
    offset = offset to the beginning of CD
    '''
    print "\033[1;32;1m---------------- Central Directory ------------"
    print "Offset: %d (0x%08x)" % (offset, offset)
    cdir = data[offset:]

    # parsing the central directory header
    signature = cdir[0:4]
    #print "Tag: ", signature
    version_made_by = struct.unpack("<H", cdir[4:6])[0]
    print "Version made by: ", version_made_by
    version_needed = struct.unpack("<H", cdir[6:8])[0]
    print "Version needed : ", version_needed
    compressed_size = struct.unpack("<L", cdir[20:24])[0]
    print "Compressed size: ", compressed_size
    uncompressed_size = struct.unpack("<L", cdir[24:28])[0]
    print "Uncompressed size: ", uncompressed_size
    filename_length = struct.unpack("<H", cdir[28:30])[0]
    extrafield_length = struct.unpack("<H", cdir[30:32])[0]
    comment_length = struct.unpack("<H", cdir[32:34])[0] #file comment
    offset_local = struct.unpack("<L", cdir[42:46])[0]
    print "Relative offset to local header: ", offset_local

    #After the header:
    if filename_length > 0:
        filename = cdir[46:46+filename_length]
        print "File name (length=%d): %s" % (filename_length ,filename)

    if comment_length > 0:
        comment = cdir[46+filename_length+extrafield_length:46+filename_length+extrafield_length+comment_length]
        print "File comment (length=%d): %s" % (comment_length, comment)
    print "\033[0m"
    
def parse_file(data, offset):
    '''
    parses Local File Header structure for ZIP file
    data = content of entire APK
    offset = offset to the beginning of Local File Header
    '''
    print "------------- Local File Header -------------------"
    print "Offset: %d (0x%08x)" % (offset, offset)
    lfh = data[offset:]
    signature = lfh[0:4]
    version_needed = struct.unpack("<H", lfh[4:6])[0]
    print "Version needed   : ", version_needed
    compressed_size = struct.unpack("<L", lfh[18:22])[0]
    print "Compressed size  : ", compressed_size
    uncompressed_size = struct.unpack("<L", lfh[22:26])[0]
    print "Uncompressed size: ", uncompressed_size
    filename_length = struct.unpack("<H", lfh[26:28])[0]
    extrafield_length = struct.unpack("<H", lfh[28:30])[0]
    filename = lfh[30:30+filename_length]
    print "Filename: ", filename
    
    # file data should be placed immediately after local header

# ------------------------------- APK Signing Block -------------
    
def parse_signing_block(data, magic_offset):
    '''
    Parses the APK Signing block 
    https://source.android.com/security/apksigning/v2#apk-signing-block-format

    data = content of the entire APK
    magic_offset = offset of where we spotted the magic word "APK Sig Block 42"
    '''
    print "\033[1;34;1m------------- APK Signing Block -------------------"

    # we compute the beginning of the APK Signing block
    # https://source.android.com/security/apksigning/v2
    magic = data[magic_offset:magic_offset+16]
    block_size2 = struct.unpack("<Q", data[magic_offset-8:magic_offset])[0]
    begin_offset = magic_offset +16 - 8 - block_size2
    print "Offset: %d (0x%08x)" % (begin_offset, begin_offset)

    block_size = struct.unpack("<Q", data[begin_offset:begin_offset+8])[0]
    print "Block size  : ", block_size

    if block_size != block_size2:
        print "WARNING: block sizes do not match"

    print "Block size 2: ", block_size2
    print "Magic: ", magic

    # parse pairs
    current_offset = begin_offset + 8
    while current_offset < magic_offset - 8:
        print "\t----- Pair -----"
        pair_length = struct.unpack("<Q", data[current_offset:current_offset+8])[0]
        print "\tValue Length: %d" % (pair_length)
        pair_id = struct.unpack("<L", data[current_offset+8:current_offset+12])[0]
        print "\tID: 0x%08X" % (pair_id)
        if pair_id == 0x7109871a:
            print "\tAPK Signature Scheme v2"
            parse_sigv2(data, current_offset+12, pair_length-4)
        
        current_offset = current_offset + 8 + pair_length

    if current_offset != magic_offset - 8:
        print "WARNING: pair sizes do not add up: current_offset=%d, magic_offset=%d" % (current_offset, magic_offset)

    print "\033[0m"
    

def parse_public_key(data, offset):
    '''
    parses a length prefixed public key (inside APK Signature Scheme v2 Block)
    offset is the offset to the beginning of the length prefixed public key
    returns: length we parsed
    '''
    length = struct.unpack("<L", data[offset: offset+4])[0]
    print "\t\t\tSubjectPublicKeyInfo length: ", length
    # public key after
    
    return 4+length

def str_algo_id(algo_id):
    if algo_id == 0x00000101:
        return "RSASSA-PSS with SHA2-256"
    if algo_id == 0x00000102:
        return "RSASSA-PSS with SHA2-512"
    if algo_id == 0x00000103:
        return "RSASSA-PKCS1-v1_5 with SHA2-256"
    if algo_id == 0x00000104:
        return "RSASSA-PKCS1-v1_5 with SHA2-512"
    if algo_id == 0x00000201:
        return "ECDSA with SHA2-256"
    if algo_id == 0x00000202:
        return "ECDSA with SHA2-512"
    if algo_id == 0x00000301:
        return  "DSA with SHA2-256"
    return "Unknown algo id: 0x%04x" % (algo_id)


def parse_signatures(data, offset):
    '''parses length prefixed sequence of signatures (inside APK Signature Scheme v2 Block)
    '''
    # length of sequence of signatures
    total_length = struct.unpack("<L", data[offset: offset+4])[0]
    print "\t\t\tTotal length of signatures: ", total_length
    
    i = 0
    nb = 1
    while i < (total_length + 4):
        # length of signature
        length = struct.unpack("<L", data[offset+i+4: offset+8+i])[0]
        print "\t\t\tSignature struct #%d length=%d" % (nb, length)
        
        # signature algorithm id
        sigalgo_id = struct.unpack("<L", data[offset+i+8: offset+12+i])[0]
        print "\t\t\t\tSignature algo id: %s " % (str_algo_id(sigalgo_id))

        # length of signature
        siglen = struct.unpack("<L", data[offset+i+12: offset+16+i])[0]
        print "\t\t\t\tSignature length : ", siglen

        # then, there is the signature
        sig = data[offset+16+i:offset+16+siglen]
        print "\t\t\t\tSignature: ", sig.encode('hex')
        
        i = i + 16 + siglen
        nb = nb + 1

    if i != (total_length+4):
        print "WARNING: problem parsing the sequence of signatures: total_len=%d i=%d" % (total_length, i)

    return total_length + 4

def parse_digest(data, offset):
    '''parses a length prefixed digest (inside APK Signature Scheme v2 Block)
    '''
    length = struct.unpack("<L", data[offset: offset+4])[0]
    print "\t\t\t\t\tLength of digest struct: ", length

    algoid = struct.unpack("<L", data[offset+4: offset+8])[0]
    print "\t\t\t\t\tDigest algo id         : %s" % (str_algo_id(algoid))

    digest_len = struct.unpack("<L", data[offset+8: offset+12])[0]
    print "\t\t\t\t\tDigest length          : ", digest_len

    digest = data[offset+12:offset+12+digest_len]
    print "\t\t\t\t\tDigest: ", digest.encode('hex')
    
    return 12+digest_len

def parse_certificates(data, offset, length):
    '''parses a sequence of certificates (inside APK Signature Scheme v2 Block)
    '''
    i = 0
    nb = 1
    while i < length:
        certificate_length = struct.unpack("<L", data[offset+i: offset+i+4])[0]
        print "\t\t\tCertificate #%d length=%d" % (nb, certificate_length)
        certificate = data[offset+4+i:offset+4+i+certificate_length]
        print "\t\t\tASN.1 DER certificate: ", certificate.encode('hex')
        nb = nb + 1
        i = i + 4 + certificate_length
        
    if i != length:
        print "WARNING: parse_certificates() error: i=%d length=%d" % (i, length)


def parse_attributes(data, offset, length):
    '''parses a sequence of attributes (inside APK Signature Scheme v2 Block)
    '''
    i = 0
    nb = 1
    while i < length:
        attribute_length, attribute_id = struct.unpack("<LL", data[offset+i: offset+i+8])
        print "\t\t\tAttribute #%d length=%d id=%d" % (nb, attribute_length, attribute_id)
        attribute = data[offset+8+i:offset+8+i+attribute_length-4]
        print "\t\t\tValue: ", attribute.encode('hex')
        nb = nb + 1
        i = i + 4 + attribute_length
        
    if i != length:
        print "WARNING: parse_attributes() error: i=%d length=%d" % (i, length)


def parse_signed_data(data, offset):
    '''parses a length prefixed signed data (inside APK Signature Scheme v2 Block)
    '''
    length = struct.unpack("<L", data[offset: offset+4])[0]
    print "\t\t\tSigned data length=", length

    # sequence of digests
    total_digests_length = struct.unpack("<L", data[offset+4: offset+8])[0]
    print "\t\t\t\tTotal digests length: ", total_digests_length
    i = 0
    nb = 1
    while i < total_digests_length:
        print "\t\t\t\tDigest struct #%d" % (nb)
        increment = parse_digest(data, offset + i + 8)
        i = i + increment
    if  i != total_digests_length:
        print "WARNING: Bad total digest length"

    # sequence of certificates
    total_certificates_length = struct.unpack("<L", data[offset+8+total_digests_length:offset+12+total_digests_length])[0]
    print "\t\t\t\tTotal certificates length: ", total_certificates_length
    parse_certificates(data, offset+12+total_digests_length, total_certificates_length)

    # sequence of attributes
    total_attributes_length = struct.unpack("<L", data[offset+12+total_digests_length+total_certificates_length:offset+16+total_digests_length+total_certificates_length])[0]
    print "\t\t\t\tTotal attributes length: ", total_attributes_length
    parse_attributes(data, offset+16+total_digests_length+total_certificates_length, total_attributes_length)

    i = 16+total_digests_length+total_certificates_length+total_attributes_length
    if i != length:
        print "WARNING: parse_signed_data() error: i=%d length=%d" % (i, length)

    return length + 4
    

def parse_sigv2(data, offset, length):
    '''
    offset where APK Signature Scheme v2 is stored
    length of APK Signature Scheme v2 block
    '''
    total_signers_length = struct.unpack("<L", data[offset:offset+4])[0]
    print "\t\tTotal signers length: ", total_signers_length

    i = 0
    nb = 1
    while i < total_signers_length:
        signer_length = struct.unpack("<L", data[offset+i+4:offset+i+8])[0]
        print "\t\tSigner #%d length=%d --- " % (nb, signer_length)
                
        # parsing each signer
        p1 = parse_signed_data(data, offset+i+8)
        p2 = parse_signatures(data, offset+i+8+p1)
        p3 = parse_public_key(data, offset+i+8+p1+p2)
        i = p1 + p2 + p3 + 4
        nb = nb + 1

    if total_signers_length != i:
        print "WARNING: parsing error: total_signers_length=%d length=%d" % (total_signers_length, i)
        
    return total_signers_length + 4

# ------------------------ MAIN ------------------------

if __name__ == "__main__":
    filename = sys.argv[1]
    apk = open(filename, "rb").read()
    parse_apk(apk)
