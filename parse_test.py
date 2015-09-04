from urllib import parse

fh1 = open('nonv.txt', mode='r')
fh2 = open('vulnerable.txt', mode='r+')

for atype in ('xss,csrf', 'lfi,dt', 'sqli', 'intof'):
    print(atype, end='   ')
    mem = 0
    for line2 in fh2:
        if atype == line2.split()[0]:
            for line1 in fh1:
                resurl1 = parse.urlparse(line1.split()[3]).path
                resurl2 = parse.urlparse(line2.split()[2]).path
                if resurl1 == resurl2:
                    mem += int(line1.split()[1])
            fh1.seek(0)
    fh2.seek(0)

# avg = tbytes/c
# print(avg)