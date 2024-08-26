#!/usr/bin/env perl

use strict;
use warnings;
use utf8;

{
    local $/ = undef;
    my $a = <>;

    $a =~ s/^[\s\S]+?\r\n\r\n//;

    $a =~ s/[ \t]+\r\n/\r\n/g;
    $a =~ s/[ \t]+/ /g;

    print $a;
}
