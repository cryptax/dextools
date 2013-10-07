#!/usr/bin/perl
#
# Copyright (c) 2012, A. Apvrille (cryptax)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
# Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
# Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use strict;
use warnings;
use Getopt::Long;
use Digest::SHA;
use Digest::Adler32;

my $help;
my $rehash;
my $checkhash;
my $dex = {
    filename => '',
    magic => '',
    checksum => '',
    sha1 => ''
};

sub usage {
    print "./dexrehash.pl --input <dex filename> [--rehash]\n";
    print "\t--input\t: Dalvik Executable filename\n";
    print "\t--rehash\t: re-compute sha1 and checksum of DEX \n";
    print "\t AND updates the current file with those values.\n";
    print "\t Beware, that overwrites the current file!\n";
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

# -------------- Main ------------------
usage if (! GetOptions('help|?' => \$help,
		       'input|i=s' => \$dex->{filename},
		       'rehash|r' => \$rehash
	  )
	  or defined $help
	  or $dex->{filename} eq '' );

my $computed_checksum = compute_dex_checksum( $dex->{filename} );
open( FILE, "$dex->{filename}" ) or die "cant open file '$dex->{filename}': $!";
binmode FILE;
$dex->{magic} = get_magic( \*FILE, $dex->{filename} );
$dex->{checksum} = ltob( get_checksum( \*FILE, $dex->{filename} ) );
$dex->{sha1} = get_sha1( \*FILE, $dex->{filename} );
close( FILE );

print "Read from file:\n";
print "Magic   : $dex->{magic}\n";
print "Checksum: $dex->{checksum}\n";
print "SHA1    : $dex->{sha1}\n";

if (defined $rehash) {
    my $new_sha1 = compute_dex_sha1( $dex->{filename} );
    write_sha1( $dex->{filename}, $new_sha1 );
    
    my $new_checksum = compute_dex_checksum( $dex->{filename} );
    write_checksum( $dex->{filename}, $new_checksum );

    print "Writing:\n";
    print "Checksum: $new_checksum\n";
    print "SHA1    : $new_sha1\n";
}

exit(1);
