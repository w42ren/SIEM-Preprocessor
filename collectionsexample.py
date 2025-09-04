from collections import Counter
c = Counter(["a","b","a","c","a"])
print(c["a"])           # 3
print(c.most_common(1)) # [('a', 3)]

