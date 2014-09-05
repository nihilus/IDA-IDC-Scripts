import sys

class ToFileStdOut(object):
    def __init__(self):
        self.outfile = open('idaout.txt', 'w')

    def write(self, text):
        self.outfile.write(text)

    def flush(self):
        self.outfile.flush()

    def isatty(self):
        return False

    def __del__(self):
        self.outfile.close()

sys.stdout = sys.stderr = ToFileStdOut()
