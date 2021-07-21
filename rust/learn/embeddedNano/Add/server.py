from ledgerblue.commTCP import getDongle as getDongleTCP
from ledgerblue.comm import getDongle

from random import getrandbits as rnd, randint
from binascii import hexlify, unhexlify

from time import sleep

randint1 = 251
randint2 = 253
rand_msg1 = hexlify(randint1.to_bytes(4, 'big')).decode()
rand_msg2 = hexlify(randint2.to_bytes(4, 'big')).decode()

CMDS = [
    "8003"+"0002" + rand_msg1 + rand_msg2,
]

print(CMDS[0])

d = getDongleTCP(port=40000)

print(
    f"Nous essayons de faire l'addition suivante {randint1} + {randint2} = {randint1 + randint2} ")
count = 0
ANSWER = []
for cmd in map(unhexlify, CMDS):
    print(cmd)
    r = None
    try:
        r = d.exchange(cmd)
        sleep(1)
    except Exception as e:
        print("test")
        print(e)
    if r is not None:
        print("Response hex : ", hexlify(r))
        ANSWER.append(int.from_bytes(r, 'big'))
        count += 1

print(f"On obtient le résultat suivant : {ANSWER}")
d.close()
