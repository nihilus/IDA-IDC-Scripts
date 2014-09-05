import idc
import idascript

print "Hello world from IDAPython\n"
for i in xrange(1, len(idc.ARGV)):
    print "ARGV[%d]=%s" % (i, idc.ARGV[i])

idc.Exit(0)