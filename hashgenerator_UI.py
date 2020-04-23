import hashlib
import tkinter as tk
from tkinter.filedialog import askopenfilename

filepath = ""
hash_choice = ""


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


# open file button
def open_file():
    global filepath
    filepath = askopenfilename(filetypes=[("All files", "*.*")])
    if not filepath:
        return
    window.title(f"Hash generator - {filepath}")
    ent_opfile.delete(0, tk.END)
    ent_opfile.insert(0, f"{filepath}")


def button_genhash():
    global hash_choice
    hash_choice = ent_hashchoice.get()
    ent_genhash.delete(0, tk.END)
    ent_genhash.insert(0, f"{HashGenerator((hash_choice.lower()), filepath).choose_hash()}")


def compare_hash():
    if (ent_genhash.get()) == (ent_hashimp.get()):
        lbl_comp["text"] = "Matched \u2713"
    else:
        lbl_comp["text"] = "No match \u274C"


window = tk.Tk()
window.title("Hash generator and comparison tool")
window.rowconfigure([0, 1, 2, 3, 4, 5, 6], minsize=10, weight=1)
window.columnconfigure([0], minsize=15, weight=1)

ent_hashchoice = tk.Entry(master=window, width=15, text="md5")
ent_opfile = tk.Entry(master=window, width=130)
# lbl_opfile = tk.Label(master=window, text="chosen file")
ent_genhash = tk.Entry(master=window, width=130)
ent_hashimp = tk.Entry(master=window, width=130)
lbl_hashimp = tk.Label(master=window, text="\u2193 paste the supplied hash from the website \u2193")
lbl_comp = tk.Label(master=window, text="")  # checkmark /u2713 crossout /u274C
btn_open = tk.Button(master=window, text="Open", command=open_file)
# generate hash button
btn_hash = tk.Button(master=window, text="Generate hash", command=button_genhash)
# compare button that compares the generated string with the pasted string
btn_compare = tk.Button(master=window, text="Compare the hashes", command=compare_hash)

ent_hashchoice.grid(row=2, column=0, sticky="e")
ent_opfile.grid(row=1, column=0, sticky="ns")
# lbl_opfile.grid(row=0, column=0, sticky="nsew")
ent_genhash.grid(row=3, column=0)
ent_hashimp.grid(row=5, column=0)
lbl_hashimp.grid(row=4, column=0, sticky="nsew")
lbl_comp.grid(row=7, column=0)
btn_open.grid(row=0, column=0, sticky="ns")
btn_hash.grid(row=2, column=0, sticky="ns")
btn_compare.grid(row=6, column=0, sticky="ns")


window.mainloop()
