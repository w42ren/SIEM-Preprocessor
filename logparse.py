import re, collections
fails = collections.Counter()
pat = re.compile(r'Failed password.*from ([0-9.]+)')
with open("auth.log") as f:
    for line in f:
        m = pat.search(line)
        if m:
            fails[m.group(1)] += 1
print (type(fails.items()))
print (fails.items())
print([ip for ip, n in fails.items() if n >= 10])


