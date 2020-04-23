import hashlib
import sys


class HashGenerator:
    description = "Takes a file and generates the chosen encryption hash for it"

    def __init__(self, hashname, filename):
        self.hashname = hashname
        self.filename = filename

    def md5_hash(self):
        self.hashname = hashlib.md5()
        with open(self.filename, "rb") as f:
            for part in iter(lambda: f.read(4096), b""):
                self.hashname.update(part)
        return self.hashname.hexdigest()

    def sha1_hash(self):
        self.hashname = hashlib.sha1()
        with open(self.filename, "rb") as f:
            for part in iter(lambda: f.read(4096), b""):
                self.hashname.update(part)
        return self.hashname.hexdigest()

    def sha256_hash(self):
        self.hashname = hashlib.sha256()
        with open(self.filename, "rb") as f:
            for part in iter(lambda: f.read(4096), b""):
                self.hashname.update(part)
        return self.hashname.hexdigest()

    def sha512_hash(self):
        self.hashname = hashlib.sha512()
        with open(self.filename, "rb") as f:
            for part in iter(lambda: f.read(4096), b""):
                self.hashname.update(part)
        return self.hashname.hexdigest()

    def choose_hash(self):
        if self.hashname == "md5":
            return self.md5_hash()
        elif self.hashname == "sha1":
            return self.sha1_hash()
        elif self.hashname == "sha256":
            return self.sha256_hash()
        elif self.hashname == "sha512":
            return self.sha512_hash()
        else:
            return "Unrecognized hashtype, please enter the correct hashtype"

# argv's are there to make it work from the terminal
hash1 = HashGenerator((sys.argv[1].lower()), sys.argv[2])

print(hash1.choose_hash())
