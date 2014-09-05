#!perl -w
use strict;
printf("auto id;\n");
printf("id= AddEnum(-1,\"enum\",0);\n");
my ($anum,$bnum)=(0,0);
my @list;
while (<>) {
    s/#\s*define\s+//;
    if (/^(\w+)\s+(\w+)/) {
        my ($a, $b)= ($1, $2);
        push @list, [$a, $b];
        $anum++ if ($a =~ /^\d/);
        $bnum++ if ($b =~ /^\d/);
    }
}
if ($anum > $bnum) {
    printf("AddConstEx(id, \"%s\", %s, -1);\n", $_->[1], $_->[0]) for @list;
}
else {
    printf("AddConstEx(id, \"%s\", %s, -1);\n", $_->[0], $_->[1]) for @list;
}
