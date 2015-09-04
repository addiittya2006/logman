import re

att_type = []
att_meas = []
att_patt = []

fh = open('filters.txt', mode='r')

for line in fh:
    result = line.split()
    if len(result) == 3:
        att_type.append(result[0])
        att_meas.append(result[1])
        att_patt.append(re.compile(result[2]))