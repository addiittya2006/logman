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
        str = line.split()
        fh3.write(str[0]+' '+str[1]+' '+str[2]+' '+parse.unquote(str[3])+'\n')

fh1.close()
fh3.close()
fh2.close()