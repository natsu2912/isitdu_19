import time
from subprocess32 import run, STDOUT, PIPE, CalledProcessError

print("5 years in prison! Wanna escape???")
payload = (input()[:0x1000]+"\n").encode('utf-8', 'surrogateescape')
open("log/payload.log","ab").write(payload)
st = time.time()

try:
	result = run(['/prisonbreak'], input=payload, stdout=PIPE, stderr=STDOUT, timeout=2, check=True).stdout
except CalledProcessError as e:
	pass

while time.time()-st<5:
	time.sleep(0.001)
