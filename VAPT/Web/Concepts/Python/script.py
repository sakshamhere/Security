import re
line = "</sc[ript>"
# p = s.replace("<script>","")


line = re.sub(r"[</?\[\d+>]","", line)


print(line)