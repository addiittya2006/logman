__author__ = 'addiittya'

import re


def main():
    # log_line = 'My name is    \"Aditya\"  .'

    fh = open('logs')

    pattern = re.compile('\"(.*?)\"')

    i = 1
    for log_line in fh:

        result = re.findall(pattern, log_line)

        # res = ''.join(str(e) for e in result).split()

        # print(res)
        # print(type(res))
        if len(result) != 0:
            if len(result[0].split()) != 0:
                # for i in (0, 1):
                # req1 = res[0]
                # req2 = res[1]
                try:
                    res = result[0].split()
                    print(i, '  '+res[0]+'   $$$$$$   '+res[1])
                except IndexError:
                    continue
            # print(result[0])

        i = i+1

    # print(log_line, end='')

    # if result:
    #     print(result.match())

if __name__ == '__main__':
    main()