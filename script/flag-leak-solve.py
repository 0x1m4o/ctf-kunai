string = "ocip{FTCk43L_gn1g4lFff0_4tS_6_kc3aea}c7cû"
out = ""
temp = ""
index = 0
for char in string:
    temp += char
    index += 1
    if index%4 == 0:
        fwd = ""
        for temp_char in temp:
            fwd = temp_char + fwd
        out += fwd
        temp = ""
print(out)