import re
from urllib import parse

att_type = []
att_meas = []
att_patt = []

fh = open('filters.txt', mode='r')
fh1 = open('cleanlog', mode='r')
fh2 = open('vulnerable.txt', mode='w')
fh3 = open('nonv.txt', mode='w')

for line in fh:
    result = line.split()
    if len(result) == 3:
        att_type.append(result[0])
        att_meas.append(result[1])
        att_patt.append(re.compile(result[2]))

tbytes = 0
c = 0
for line in fh1:
    vflag = False
    for patt in att_patt:
        t = parse.unquote(line.split()[3])
        if patt.search(t):
            i = att_patt.index(patt)
            fh2.write(att_type[i]+' '+att_meas[i]+' '+line.split()[3]+' '+line.split()[1]+'\n')
            vflag = True
        else:
            tbytes += int(line.split()[1])
            c += 1
    if not vflag:
        fh3.write(line)

fh1.close()
fh3.close()
fh2.close()

fh2 = open('vulnerable.txt', mode='r')
fh5 = open('mem.txt', mode='w')
fh1 = open('nonv.txt', mode='r')

resurl1 = ''
resurl2 = ''
i = 0

for atype in ('xss,csrf', 'lfi,dt', 'sqli', 'intof'):
    print(atype)
    mem = 0
    for line2 in fh2:
        # fh1 = open('nonv.txt', mode='r')
        if atype == line2.split()[0]:
            for line1 in fh1:
                resurl2 = parse.urlparse(line2.split()[2]).path
                resurl1 = parse.urlparse(line1.split()[3]).path
                # print(i, resurl1, resurl2)
                # print(mem, 'lalalalalala')
                # mem += 1
                if resurl1 == resurl2:
                    mem += int(line1.split()[1])
            fh1.seek(0)
    fh5.write(str(mem)+'\n')
    fh2.seek(0)
                    # print('lalalalala')

fh5.close()
avg = tbytes/c
print(avg)