import binascii
with open("blob.bin", 'rb') as fd:
	data = fd.read()

idx = data.find(b"\x00\x0d\x19\x20")
print(hex(idx))
assert idx > 0
idx += 4

exp = binascii.unhexlify("c4794141")
data = data[:idx] + exp + data[idx + len(exp):]

with open("exp.bin", 'wb') as fd:
	fd.write(data)