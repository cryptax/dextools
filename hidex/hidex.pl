#!/usr/bin/perl
# Copyright (c) 2013, 2014, A. Apvrille
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#
# Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
# Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use strict;
use warnings;
use Getopt::Long;
use Digest::SHA;
use Digest::Adler32;

my $help;
my $detect = 0;
my $classname;
my $methodname;
my $dex = {
    filename => '',
    magic => '',
    checksum => '',
    sha1 => ''
};
my $patch_offset;
my $patch_access_flags;
my $patch_code_offset;
my $patch_method_idx_diff;
my $patch_next_method_idx_diff;
my $patch_string_offset;
my $patch_string_data;
my $show_strings;
my $rename_strings;
my $add_link_data;
my $add_link_len;

my @referenced_method_idx;
my @referenced_code_offset;

sub usage {
    print "=== Hiding/Unhiding with DEX files ===\n";
    print "Copyright (c) 2013, 2014, A. Apvrille\n";
    print "http://opensource.org/licenses/BSD-2-Clause\n";
    print "\n";
    print "Usage:\n";
    print "./hidex.pl --input <filename>\n\t[--show-strings]\n\t[--rename-strings]\n\t[--detect]\n\t[--patch-string-offset HEX --patch-string-data HEX]\n\t[--patch-offset HEX --patch-idx HEX --patch-code HEX --patch-flag HEX --patch-next-idx HEX]\n\t[--class classname [--method methodname]]\n";
    print "\t--input filename  file to analyze.\n";
    print "\t--show-strings show all strings.\n";
    print "\t--rename-strings rename non printable strings in the DEX. Beware, this breaks the DEX because strings arent properly ordered after this.\n";
    print "\t--detect          detects possible attempts to hide a method.\n";
    print "\tExample: ./hidex.pl --input classes.dex --detect\n\n";
    print "\t--class classname Restrict display of layout to only this class.\n";
    print "\tExample: ./hidex.pl --input=classes.dex.invoke --class \"Lcom/fortiguard/hideandseek/MrHyde;\"\n";
    print "\tExample: ./hidex.pl --input=classes.dex --class \"Lcom/fortiguard/hideandseek/MrHyde;\" --detect\n";
    print "\t         will show info & warnings only for class MrHyde\n\n";
    print "\t--method methodname Restrict display of layout to only this method. A class must be specified too.\n";
    print "\tExample: ./hidex.pl --input=classes.dex.invoke --class \"Lcom/fortiguard/hideandseek/MrHyde;\" --method \"thisishidden\"\n\n";
    print "\n";
    print "\t--patch-offset HEX Hides/unhides method located at offset HEX (HEX is an hexadecimal offset e.g 0x1234)\n";
    print "\t--patch-idx HEX Sets the method_idx to hexadecimal value HEX\n";
    print "\t--patch-code HEX Sets the code offset to HEX where HEX is an hexadecimal offset\n";
    print "\t--patch-flag HEX Sets the access flag to hexadecimal value\n";
    print "\t--patch-next-idx HEX Sets the method_idx of the next method\n";
    print "\tExample: ./hidex.pl --input classes.dex --patch-offset 0x2c99 --patch-idx 0 --patch-flag 1 --patch-code 0x13d8 --patch-next-idx 2\n\n";
    print "\n";
    print "\t--patch-string-offset HEX\n";
    print "\t--patch-string-data HEX\n";
    print "\t--add-link HEXSTRING: adds this string in the link section. The string is hexa bytes.\n";
    print "\tExample: ./hidex.pl --input classes.dex --add-link '01020304'\n";
    exit(0);
}

# little endian to big endian
sub ltob {
    my $hex = shift;

    my $bits = pack("V*", unpack("N*", pack("H*", $hex)));
    return unpack("H*", $bits);
}

sub btol {
    my $hex = shift;
    my $bits = pack("N*", unpack("V*", pack("H*", $hex)));
    return unpack("H*", $bits);
}

sub read_uleb128 {
    my $fh = shift;
    my $result = 0;
    my $shift = 0;
    my $byte;
    my $data;
    do {
	read( $fh, $data, 1) or die "cant read byte : $!";
	$byte = unpack( "c", $data );
	#my $hex = unpack( "H*", $data );
	$result |= ($byte & 0x7f) << $shift;
	#my $tmpr_hex = unpack( "H*", pack("c", $result ));
	$shift += 7;
    } while (($byte & 0x80) != 0);

    return $result;
}

sub write_uleb128 {
    my $fh = shift;
    my $result = shift;
    my $value = $result;
    my $byte;

    do {
	$byte = 0x7f & $value;
	#print "7 lower order bits: ".unpack( "H2", pack( "I", $byte ))."\n";
	$value >>= 7;
	if ($value != 0) {
	    $byte |= 0x80;
	}
	#print " => ".unpack( "H2", pack( "C", $byte ))."\n";
	print( $fh pack("C", $byte)) or die "cant write byte: $!";

    } while ($value != 0);
}

sub show_uleb128 {
    my $value = shift;
    my $string ='';
    my $byte;
    do {
	$byte = 0x7f & $value;
	#print "7 lower order bits: ".unpack( "H2", pack( "I", $byte ))."\n";
	$value >>= 7;
	if ($value != 0) {
	    $byte |= 0x80;
	}
	$string .= unpack( "H2", pack( "C", $byte ))." ";
    } while ($value != 0);
    return $string;
}

# ubyte[8] DEX_FILE_MAGIC = { 0x64 0x65 0x78 0x0a 0x30 0x33 0x35 0x00 }
sub get_magic {
    my $fh = shift;
    my $data;

    read( $fh, $data, 8) or die "cant read magic from file: $!";
    my $hex = unpack( 'H*', $data );
    return $hex;
}

# uint 32-bit unsigned int, little-endian
sub get_checksum {
    my $fh = shift;
    my $data;

    read( $fh, $data, 4) or die "cant read checksum from file: $!";
    my $hex = unpack( 'H*', $data );

    return $hex;
}

sub write_checksum {
    my $filename = shift;
    my $hexstring = shift;

    my @checksum = pack( 'H*' , btol( $hexstring ) );

    open( FILE, "+<$filename" ) or die "cant open file '$filename': $!";
    binmode FILE, ":bytes";
    seek( FILE, 8, 0 );

    foreach my $byte (@checksum) {
	print( FILE $byte ) or die "cant write checksum in file: $!";
    }

    close( FILE );
    
}

sub get_sha1 {
    my $fh = shift;
    my $data;

    read( $fh, $data, 20) or die "cant read checksum from file: $!";
    my $hex = unpack( 'H*', $data );
    return $hex;
}

sub write_sha1 {
    my $filename = shift;
    my $hexstring = shift;
    my @hash = pack( 'H*', $hexstring );
    my $byte;

    open( FILE, "+<$filename" ) or die "cant open file '$filename': $!";
    binmode FILE, ":bytes";
    seek( FILE, 8+4, 0);

    foreach $byte (@hash) {
	print( FILE $byte ) or die "cant write sha1 in file: $!";
    }

    close( FILE );
}

sub compute_dex_sha1 {
    my $filename = shift;
    open( FILE, $filename ) or die "sha1: cant open $filename: $!";
    binmode FILE;

    # skip magic, checksum, sha1
    $dex->{magic} = get_magic(\*FILE);
    $dex->{checksum} = get_checksum(\*FILE);
    $dex->{sha1} = get_sha1(\*FILE);

    # compute sha1 
    my $shaobj = new Digest::SHA("1");
    my $sha1 = $shaobj->addfile(*FILE)->hexdigest;
    close( FILE );

    return $sha1;
}

sub compute_dex_checksum {
    my $filename = shift;
    open( FILE, $filename ) or die "sha1: cant open $filename: $!";
    binmode FILE;
    
    # skip magic and checksum
    get_magic(\*FILE);
    $dex->{checksum} = get_checksum(\*FILE);

    my $a32 = Digest::Adler32->new;
    $a32->addfile(*FILE);
    close(FILE);    
    my $checksum = $a32->hexdigest;

    return $checksum;
}

sub read_dexheader {
    my $fh = shift;
    my $filename = shift;
    my $data;

    $dex->{magic} = get_magic( \*FILE, $filename );
    $dex->{checksum} = ltob( get_checksum( \*FILE, $filename ) );
    $dex->{sha1} = get_sha1( \*FILE, $filename );
    read( $fh, $data, 4) or die "cant read file size from file: $!";
    $dex->{filesize} = unpack('L', $data);
    read( $fh, $data, 4) or die "cant read header size from file: $!";
    $dex->{headersize} = unpack('L', $data);
    if ($dex->{headersize} != 0x70) {
	printf("WARNING: strange header size: %d\n", $dex->{headersize});
    }
    seek( $fh, 4, 1); # skip endianess
    read( $fh, $data, 4) or die "cant read link_size from file: $!";
    $dex->{link_size} = unpack('L', $data);
    read( $fh, $data, 4) or die "cant read link_off from file: $!";
    $dex->{link_offset} = unpack('L', $data);
    read( $fh, $data, 4) or die "cant read map_off from file: $!";
    $dex->{map_offset} = unpack('L', $data);

    read( $fh, $data, 4) or die "cant read string ids size from file: $!";
    $dex->{string_ids_size} = unpack('L', $data);
    read( $fh, $data, 4) or die "cant read string ids offset from file: $!";
    $dex->{string_ids_offset} = unpack('L', $data);
    read( $fh, $data, 4) or die "cant read type ids size from file: $!";
    $dex->{type_ids_size} = unpack('L', $data);
    read( $fh, $data, 4) or die "cant read type ids offset from file: $!";
    $dex->{type_ids_offset} = unpack('L', $data);
    seek( $fh, 4*4, 1); # skip
    read( $fh, $data, 4) or die "cant read method ids size from file: $!";
    $dex->{method_ids_size} = unpack('L', $data);
    read( $fh, $data, 4) or die "cant read method ids offset from file: $!";
    $dex->{method_ids_offset} = unpack('L', $data);
    read( $fh, $data, 4) or die "cant read class_defs size from file: $!";
    $dex->{class_defs_size} = unpack('L', $data);
    read( $fh, $data, 4) or die "cant read class defs offset from file: $!";
    $dex->{class_defs_offset} = unpack('L', $data);

    print "DEX Header of file:\n";
    print "Magic     : $dex->{magic}\n";
    print "Checksum  : $dex->{checksum}\n";
    print "SHA1      : $dex->{sha1}\n";
    printf("link: offset=0x%X (%d), size=%d\n", $dex->{link_offset}, $dex->{link_offset}, $dex->{link_size});
    printf("map offset=0x%X (%d)\n", $dex->{map_offset}, $dex->{map_offset});
    printf("string_ids: offset=0x%X (%d), size=%d\n", $dex->{string_ids_offset}, $dex->{string_ids_offset}, $dex->{string_ids_size}, $dex->{string_ids_size});
    printf("type_ids  : offset=0x%X (%d), size=%d\n", $dex->{type_ids_offset}, $dex->{type_ids_offset}, $dex->{type_ids_size}, $dex->{type_ids_size});
    printf("method_ids: offset=0x%X (%d), size=%d\n", $dex->{method_ids_offset}, $dex->{method_ids_offset}, $dex->{method_ids_size}, $dex->{method_ids_size});
    printf("class_defs: offset=0x%X (%d), size=%d\n", $dex->{class_defs_offset}, $dex->{class_defs_offset}, $dex->{class_defs_size}, $dex->{class_defs_size});
}

sub get_string {
    my $fh = shift;
    my $idx = shift;
    my $data;

    seek($fh, $dex->{string_ids_offset}, 0);
    seek($fh, 4*$idx, 1);
    read($fh, $data, 4) or die "cant read string data offset: $! - string ids offset: $dex->{string_ids_offset} idx=$idx";
    my $string_data_off = unpack('L', $data);
    #print "string data off: $string_data_off\n";
    
    seek($fh, $string_data_off, 0);
    my $string_size = read_uleb128(\*FILE);
    #print "String size: $string_size\n";
    read($fh, $data, $string_size) or return "ERROR: CAN'T READ DATA";

    return $data;

}

sub get_type_name {
    my $fh = shift;
    my $idx = shift;
    my $data;

    seek($fh, $dex->{type_ids_offset}, 0);
    seek($fh, 4*$idx, 1);
    read($fh, $data, 4) or die "cant read descriptor: $!";
    my $descriptor_idx = unpack('L', $data);
    #printf("Descriptor: 0x%x (%d)\n", $descriptor_idx, $descriptor_idx);

    return get_string($fh, $descriptor_idx);
}

sub get_method_name {
    my $fh = shift;
    my $idx = shift;
    my $data;
    
    seek($fh, $dex->{method_ids_offset}, 0);
    seek($fh, 8*$idx, 1);
    seek($fh, 4, 1); #skip class idx and proto idx
    read($fh, $data, 4) or return 'ERROR GETTING METHOD NAME';
    my $name_idx = unpack('L', $data);

    return get_string($fh, $name_idx);
}

# returns 1 if idx is present in the list of referenced method idxs
sub is_referenced {
    my $search_idx = shift;
    
    foreach my $idx (@referenced_method_idx) {
	if ($idx eq $search_idx) {
	    return 1;
	}
    }

    return 0;
}

# returns 1 if code offset is present in the list of code offsets
# to do: check overlapping?
sub is_offset_referenced {
    my $search_offset = shift;
    
    foreach my $offset (@referenced_code_offset) {
	if ($offset eq $search_offset) {
	    return 1;
	}
    }

    return 0;
}

sub check_code_offset {
    my $class_name = shift;
    my $method_name = shift;
    my $position = shift;
    my $offset = shift;

    # basic offset checking. 
    if ($offset <= 0) {
	printf("Class: $class_name Method: $method_name Position: 0x%X\n", $position);
	print "null code offset detected (interface/abstract or .. hidden method?)\n";
	# this is either an attempt to hide a method or an abstract method 
    }

    # to do: check that offset is in data section
    if (is_offset_referenced($offset) eq 1 && $offset != 0) {
	# null code offset meaningless
	printf("Class: $class_name Method: $method_name Position: 0x%X\n", $position);
	printf("WARNING: Code offset 0x%X ALREADY REFERENCED\n", $offset);
    } else {
	unshift( @referenced_code_offset, $offset );
    }

}

sub check_method_idx {
    my $class_name = shift;
    my $method_name = shift;
    my $position = shift;
    my $method_idx = shift;
    my $method_idx_diff = shift;

    if ($method_idx_diff <= 0) {
	printf("Class: $class_name Method: $method_name Position: 0x%X\n", $position);
	print "WARNING: method_idx_diff <= 0 detected\n";
    }

    # checking for duplicate entries
    if (is_referenced($method_idx) eq 1) {
	printf("Class: $class_name Method: $method_name Position: 0x%X\n", $position);
	print "WARNING: METHOD_IDX $method_idx ALREADY REFERENCED\n";
	return ;
    }

    # add method to list of referenced method idxs
    unshift( @referenced_method_idx, $method_idx );
}

# call this when @referenced_method_idx is complete
sub check_missing_method_idx {
    my $fh = shift;
    my $search_class = shift;
    my $search_method = shift;
    my $data;

    seek($fh, $dex->{method_ids_offset}, 0);

    for (my $count = 0; $count < $dex->{method_ids_size} ; $count++) {
	read( $fh, $data, 2) or die "cant read class_idx: $!";
	my $class_idx = unpack('S', $data);
	seek($fh, 2, 1); # skip proto idx
	read( $fh, $data, 4) or die "cant read name_idx: $!";
	my $name_idx = unpack('L', $data);
	my $saved_position = tell($fh);

	if (is_referenced($count) ne 1) {
	    seek($fh, $dex->{type_ids_offset}, 0);
	    seek($fh, $class_idx*4, 1); # jump to entry for class_idx
	    read($fh, $data, 4) or die "cant read description_idx: $!";
	    my $descriptor_idx = unpack('L', $data);
	    my $class_name = get_string($fh, $descriptor_idx);
	    my $method_name = get_string($fh, $name_idx);

	    if (!defined $search_class ||
		$search_class eq '' ||
		($search_class eq $class_name && !defined $search_method) ||
		($search_class eq $class_name && $search_method eq '') ||
		($search_class eq $class_name && $search_method eq $method_name)) {  
	    
		print "Method idx: $count Class: $class_name Name: $method_name is never referenced\n";
		# this is either because it is just used (not implemented) or ... hidden
	    }

	    seek($fh, $saved_position, 0);
	}
    }
}

sub read_class_def {
    my $fh = shift;
    my $offset = shift;
    my $size = shift;
    my $search_class = shift;
    my $search_method = shift;
    my $detect_flag = shift;
    my $data;

    for (my $count =0; $count < $size; $count++) {
	seek( $fh, $offset + (8*4*$count), 0);
	read( $fh, $data, 4) or die "cant read class_idx: $!";
	my $class_idx = unpack('L', $data);
	seek( $fh, 5*4, 1); # skip 20 bytes
	read( $fh, $data, 4) or die "cant read class_data_off: $!";
	my $class_data_off = unpack('L', $data);
	my $class_name = get_type_name($fh, $class_idx);

	if (!defined $search_class ||
	    $search_class eq '' ||
	    $search_class eq $class_name) {
	    print "Class_def[".$count."]:\n";
	    printf(" class idx         = %s (0x%X)\n", $class_name, $class_idx);
	    print " class data offset = $class_data_off\n";
	}

	if ($class_data_off <= 0) {
	    print "No class data for this class\n";
	    next;
	}

	# now read class_data_item
	seek( $fh, $class_data_off, 0);
	my $static_fields_size = read_uleb128($fh);
	my $instance_fields_size = read_uleb128($fh);
	my $direct_methods_size = read_uleb128($fh);
	my $virtual_methods_size = read_uleb128($fh);
	if (!defined $search_class ||
	    $search_class eq '' ||
	    $search_class eq $class_name) {
	    print " # static fields  = $static_fields_size\n";
	    print " # instance fields= $instance_fields_size\n";
	    print " # direct methods = $direct_methods_size\n";
	    print " # virtual methods= $virtual_methods_size\n";
	}

	# skip all fields
	for (my $skip = 0; $skip < $static_fields_size + $instance_fields_size; $skip++) {
	    read_uleb128($fh);
	    read_uleb128($fh);
	}

	my $method_idx = 0;
	# now read methods
	if (!defined $search_class ||
	    $search_class eq '' ||
	    $search_class eq $class_name) {
	    print " direct methods:\n";
	}
	for (my $method = 0; $method < $direct_methods_size; $method++) {
	    my $position = tell($fh);
	    my $method_idx_diff = read_uleb128($fh);
	    $method_idx += $method_idx_diff;
	    my $access_flags = read_uleb128($fh);
	    my $code_off = read_uleb128($fh);
	    my $saved_position = tell($fh);
	    my $method_name = get_method_name($fh, $method_idx);


	    if (!defined $search_class ||
		$search_class eq '' ||
		($search_class eq $class_name && !defined $search_method) ||
		($search_class eq $class_name && $search_method eq '') ||
		($search_class eq $class_name && $search_method eq $method_name)) {
		printf( "   method #%d- name=%s (0x%x) (position=0x%X)\n", $method, $method_name, $method_idx, $position);
		printf( "     access     = 0x%X (%d)\n", $access_flags, $access_flags);
		printf( "     code_offset= 0x%X (%d)\n", $code_off, $code_off);
		printf( "     idx_diff   = %d\n", $method_idx_diff);

		if ($detect_flag) {
		    check_code_offset($class_name, $method_name, $position, $code_off);
		    if ($code_off > 0) {
			check_method_idx($class_name, $method_name, $position, $method_idx, $method_idx_diff);
		    }
		}
	    }
	    seek($fh, $saved_position, 0);
	}
	if (!defined $search_class ||
	    $search_class eq '' ||
	    $search_class eq $class_name) {
	    print " virtual methods:\n";
	}
	$method_idx = 0;
	for (my $virtual = 0; $virtual < $virtual_methods_size; $virtual++) {
	    my $position = tell($fh);
	    my $method_idx_diff = read_uleb128($fh);
	    $method_idx += $method_idx_diff;
	    my $access_flags = read_uleb128($fh);
	    my $code_off = read_uleb128($fh);
	    my $saved_position = tell($fh);
	    my $method_name = get_method_name($fh, $method_idx);

	    if (!defined $search_class ||
		$search_class eq '' ||
		($search_class eq $class_name && !defined $search_method) ||
		($search_class eq $class_name && $search_method eq '') ||
		($search_class eq $class_name && $search_method eq $method_name)) {	
		printf( "   name=%s (0x%x) (position=0x%X)\n", get_method_name($fh, $method_idx), $method_idx, $position);
		printf( "     access     = 0x%X (%d)\n", $access_flags, $access_flags);
		printf( "     code_offset= 0x%X (%d) [%s]\n", $code_off, $code_off, show_uleb128($code_off));
		printf( "     idx_diff   = %d\n", $method_idx_diff);
		if ($detect_flag) {
		    check_code_offset($class_name, $method_name, $position, $code_off);
		    if ($code_off > 0) {
			check_method_idx($class_name, $method_name, $position, $method_idx, $method_idx_diff);
		    }
		}
	    }
	    seek($fh, $saved_position, 0);
	}

    }
}

sub patch_method {
    my $fh = shift;
    my $patch_offset = shift;
    my $patch_method_idx_diff = shift;
    my $patch_access_flags = shift;
    my $patch_code_offset = shift;
    my $patch_next_method_idx_diff = shift;

    $patch_offset = hex($patch_offset);
    $patch_code_offset = hex($patch_code_offset);
    $patch_access_flags = hex($patch_access_flags);
    $patch_method_idx_diff = hex($patch_method_idx_diff);
    $patch_next_method_idx_diff = hex($patch_next_method_idx_diff);

    seek($fh, $patch_offset, 0); # e.g 0x2da9
    write_uleb128($fh, $patch_method_idx_diff); # idx e.g 0
    write_uleb128($fh, $patch_access_flags); # access, e.g 1
    write_uleb128($fh, $patch_code_offset); # code offset (2 bytes) e.g 0x1448

    if (defined $patch_next_method_idx_diff) {
	write_uleb128($fh, $patch_next_method_idx_diff);  # next method_idx e.g 2
    }
}

sub patch_string {
    my $fh = shift;
    my $patch_string_offset = shift;
    my $patch_string_data = shift;

    $patch_string_offset = hex($patch_string_offset);
    $patch_string_data = hex($patch_string_data);

    seek($fh, $patch_string_offset, 0);
    
    print( $fh pack( "S*", $patch_string_data ) );
}

sub read_all_strings {
    my $fh = shift;
    my $rename = shift;

    if ($rename) {
	print "Renaming strings: size=$dex->{string_ids_size}\n";
    } else {
	print "Reading strings: size=$dex->{string_ids_size}\n";
    }

    my $letter = 0x30;
    my @replacement; # list of new replacement strings we use
    
    for my $count (0 .. $dex->{string_ids_size}-1) {
	my $data;
	seek($fh, $dex->{string_ids_offset}, 0);
	seek($fh, 4*$count, 1);
	read($fh, $data, 4) or die "cant read string data offset: $!";
	my $string_data_off = unpack('L', $data);
	seek($fh, $string_data_off, 0);
	my $utf16_units = read_uleb128(\*FILE);
	my $pos = tell($fh);
	read($fh, $data, $utf16_units) or warn "ERROR: can't read string[$count] at offset $string_data_off";
	
	# when strings are UTF8, 1 byte = 1 character, and then a 0x00 immediately follows
	# but that's not true if you have UTF16 characters!
	# DEX format says: "size of this string, in UTF-16 code units"
	my $more_char;
	my $string_nb_of_bytes = 0;
	read($fh, $more_char, 1);
	my $more_char_byte = unpack( "c", $more_char );
	while ($more_char_byte != 0x00) {
	    $data .= $more_char;
	    $string_nb_of_bytes ++;
	    read($fh, $more_char, 1);
	    $more_char_byte = unpack( "c", $more_char );
	}

	if ($rename && $data =~ /[^\x20-\x7e]/ && $utf16_units > 0) {
	    # beware, this string renaming breaks the string ordering 
	    # the DEX will no longer be valid

	    # we will just replace the non-printable characters with dummy ones
	    my $new_data = $data;
	    $new_data =~ s/[^\x20-\x7e]/U/g; #each UTF16 is replaced by two ascii

	    for my $element (@replacement) {
		if ($element eq $new_data) {
		    # This string constant already exist, we must choose another one
		    # We'll be using another replacement letter ($letter)
		    # TO FIX: if we go beyond 0x7e, we'll be using non printable characters again...
		    $letter++; 

		    if ($letter == 0x3a) {
			$letter = 0x41; # skipping punctuation characters
		    }
		    $new_data =~ s/U/chr($letter)/eg; # that's a bit buggy if there are other Us in the string
		    # print "string[$count]: duplicate found -> we changed: $new_data\n";
		}
	    }
	    unshift(@replacement, $new_data);    

	    printf( "Replacing string[%d] @ offset=0x%x, utf16-units=%d, str_bytes=%d old value=%s -> new value=%s\n",
		    $count, $string_data_off, $utf16_units, 
		    $string_nb_of_bytes+$utf16_units, 
		    $data, 
		    $new_data);

	    my $desired_len = $utf16_units + $string_nb_of_bytes;
	    if (length($new_data) != $desired_len) {
		# unexpected situation or bug :(
		print "Oops: something is wrong\n";
		exit(0);
	    }

	    # we are not modifying the utf16_unit size
	    seek($fh, $pos, 0);
	    
	    # write the renamed string
	    for (my $i=0; $i<$desired_len; $i++) {
		print( $fh substr($new_data, $i, 1)) or die "cant write renamed string: $!";
	    }

	    # normally, we should not need to write this one, it should already be at the right place
	    print( $fh pack("C", 0x00)) or die "cant write byte: $!";
	}

	printf("string[%d] -> offset: 0x%X (%d), utf16_units: %d, bytes: %d, value: %s\n",
	       $count, $string_data_off, $string_data_off,
	       $utf16_units,
	       $utf16_units + $string_nb_of_bytes,
	       $data);
    }
}

sub add_link {
    my $fh = shift;
    my $link_data = shift;

    my @hex    = ($link_data =~ /(..)/g);
    my @dec    = map { hex($_) } @hex;
    my @link_bytes  = map { pack('C', $_) } @dec;
    my $link_size = $#link_bytes +1;

    $dex->{link_offset} = $dex->{filesize};
    $dex->{link_size} = $link_size;
    $dex->{filesize} += $link_size;

    # patch filesize
    seek($fh, 8+4+20, 0);
    printf "New filesize: 0x%X (%d)\n", $dex->{filesize}, $dex->{filesize};
    print( $fh pack( "I*", $dex->{filesize} ));

    # patch link size
    seek($fh, 8, 1);
    printf "Link size: %d at offset 0x%X (%d)\n", $dex->{link_size}, $dex->{link_offset}, $dex->{link_offset};
    print( $fh pack( "I*", $dex->{link_size} ));
    print( $fh pack( "I*", $dex->{link_offset} ));

    # put link
    print "Writing link data: $link_data\n";
    seek($fh, $dex->{link_offset}, 0);
    print($fh @link_bytes);
}


# -------------- Main ------------------
usage if (! GetOptions('help|?' => \$help,
		       'detect|d' => \$detect,
		       'patch-offset|p=s' => \$patch_offset,
		       'patch-flag|f=s' => \$patch_access_flags,
		       'patch-code=s' => \$patch_code_offset,
		       'patch-next-idx=s' => \$patch_next_method_idx_diff,
		       'patch-idx=s' => \$patch_method_idx_diff,
		       'patch-string-offset=s' => \$patch_string_offset,
		       'patch-string-data=s' => \$patch_string_data,
		       'add-link-data|a=s' => \$add_link_data,
		       'show-strings' => \$show_strings,
		       'rename-strings' => \$rename_strings,
		       'method|m=s' => \$methodname,
		       'class|c=s' => \$classname,
		       'input|i=s' => \$dex->{filename} )
	  or defined $help
	  or $dex->{filename} eq '' );

my $computed_checksum = compute_dex_checksum( $dex->{filename} );
open( FILE, "$dex->{filename}" ) or die "cant open file '$dex->{filename}': $!";
binmode FILE;
read_dexheader(\*FILE, $dex->{filename});
print "\n";
read_class_def(\*FILE, $dex->{class_defs_offset}, $dex->{class_defs_size}, $classname, $methodname, $detect);
print "\n";
if (defined $detect && ($detect eq 1)) {
    check_missing_method_idx(\*FILE, $classname, $methodname);
}
if (defined $show_strings) {
    read_all_strings(\*FILE, 0);
}
close( FILE );

if ((defined $patch_string_offset && defined $patch_string_data) ||
    (defined $add_link_data) ||
    (defined $rename_strings) ||
    (defined $patch_offset && defined $patch_access_flags && 
     defined $patch_code_offset && defined $patch_method_idx_diff)) {
    print "Patching DEX...\n";
    open( FILE, "+<$dex->{filename}" ) or die "cant open file '$dex->{filename}': $!";
    binmode FILE, ":bytes";

    if (defined $add_link_data) {
	add_link(\*FILE, $add_link_data);
    }

    if (defined $rename_strings) {
	read_all_strings(\*FILE, 1);
    }

    if (defined $patch_string_offset && defined $patch_string_data) {
	patch_string(\*FILE, $patch_string_offset, $patch_string_data);
    }

    if (defined $patch_offset && defined $patch_access_flags && 
	defined $patch_code_offset && defined $patch_method_idx_diff) {
	patch_method(\*FILE, $patch_offset, $patch_method_idx_diff,
		     $patch_access_flags, $patch_code_offset,
		     $patch_next_method_idx_diff);
    }

    # re-compute sha1
    my $new_sha1 = compute_dex_sha1( $dex->{filename} );
    write_sha1( $dex->{filename}, $new_sha1 );

    my $new_checksum = compute_dex_checksum( $dex->{filename} );
    write_checksum( $dex->{filename}, $new_checksum );

    print "Writing:\n";
    print "Checksum: $new_checksum\n";
    print "SHA1    : $new_sha1\n";

    close( FILE );
}





exit(1);
