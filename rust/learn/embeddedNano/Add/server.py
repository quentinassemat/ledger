from ledgerblue.commTCP import getDongle as getDongleTCP
from ledgerblue.comm import getDongle

from random import getrandbits as rnd, randbytes, randint
from binascii import hexlify, unhexlify

from time import sleep
from tools import *

randint1 = int.from_bytes(randbytes(4), 'big') // 2
randint2 = int.from_bytes(randbytes(4), 'big') // 2
rand_msg1 = hexlify(randint1.to_bytes(4, 'big')).decode()
rand_msg2 = hexlify(randint2.to_bytes(4, 'big')).decode()
randfield1 = sct.randbelow(n)
randfield2 = sct.randbelow(n)
rand_msg3 = hexlify(randfield1.to_bytes(N_bytes, 'big')).decode()
rand_msg4 = hexlify(randfield2.to_bytes(N_bytes, 'big')).decode()

CMDS = [
    "8003"+"0002" + rand_msg1 + rand_msg2, # envoie de deux entier de type u32 
    "8004" + "0064" + rand_msg3 + rand_msg4 # envoie deux field element 
]

print(CMDS[0])

d = getDongleTCP(port=40000)

print(
    f"Nous essayons de faire l'addition suivante {randint1} + {randint2} = {randint1 + randint2} ")

print(
    f"Nous essayons de faire l'addition suivante {randfield1} + {randfield2} = {randfield1 + randfield2 % n} ")

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
    sleep(2)

print(f"On obtient le résultat suivant : {ANSWER}")
d.close()
