#CE PYTHON SIMULE NB_SIMUL SIGNEURS parmi nb_participant signeur (les autres étant en rust)

#pour pouvoir utiliser les objets de tools.py comme un #include "lib.h"
from tools import *

NB_SIMUL = nb_participant - 2

SimulSigners = [Signer(nb_nonces) for i in range(NB_SIMUL)]

#les nonces qui sont publiques  
R = [[E]*nb_nonces for i in range(nb_participant)]
Nonces = [R] * NB_SIMUL #Nonces contient NB_SIMUL fois la même chose mais c'est pour simuler qu'il y a bien plusieurs signeurs simulé par ce py

print(f"Voulez vous commencer la signature ? (Envoyer clefs publiques)")
cont = input_yes_no()
if cont == False:
    sys.exit()

#Envoie des clefs publiques au serveur
count_pubkeys = 0
while count_pubkeys < NB_SIMUL:
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((ADRESSE, PORT))
        client.send(point_to_bytes(SimulSigners[count_pubkeys].KEY))
        client.close()
        count_pubkeys += 1
    finally: 
        client.close()

print(f"On a envoyé les clefs publiques, Voulez vous continuer la signature ? (Recevoir clefs publiques)")
cont = input_yes_no()
if cont == False:
    sys.exit()

#Reception des clefs publiques des autres:
PUBKEYS = [[] for i in range(NB_SIMUL)]
count_pubkeys = 0

while count_pubkeys < NB_SIMUL:
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((ADRESSE, PORT))
        donnees = client.recv(MEM)
        PUBKEYS[count_pubkeys] = bytes_to_list(donnees)
        client.close()
        count_pubkeys += 1
    finally:
        client.close()

print(f"On a reçu les clefs publiques, Voulez vous continuer la signature ? (Envoyer les nonces)")
cont = input_yes_no()
if cont == False:
    sys.exit()

#Envoie des nonces au serveur
#First Signing step (Sign and communication round)
for i in range(NB_SIMUL):
    SimulSigners[i].gen_r()

i = 0
while i < NB_SIMUL:
    j = 0
    while j < nb_nonces:
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((ADRESSE, PORT))
            client.send(
            bytes(messagePoint(SimulSigners[i].KEY, ((SimulSigners[i].list_r[j]) * G))))
            client.close()
            j += 1
        finally:
            client.close()
    i += 1

print(f"On a envoyé les clefs nonces, Voulez vous continuez la signature ? (Reception des nonces)");
cont = input_yes_no()
if cont == False:
    sys.exit()

#Reception des nonces 
count_nonces = 0
while count_nonces < NB_SIMUL:
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((ADRESSE, PORT))
        donnees = client.recv(MEM)
        Nonces[count_nonces] = bytes_to_matPoint(donnees)
        client.close()
        count_nonces += 1
    finally:
        client.close()

#Calcul individuel des ai/Xtilde

A = [] # correspond à NB_SIMUL fois les ai pour simuler les signeurs indépendants
for k in range(NB_SIMUL):
    A.append([(int.from_bytes(hl.sha256(b''.join([(PUBKEYS[k][l].x.val).to_bytes(N_bytes, 'big') for l in range(
    nb_participant)] + [(PUBKEYS[k][i].x.val).to_bytes(N_bytes, 'big')])).digest(), 'big') % n) for i in range(nb_participant)])

for k in range(NB_SIMUL):
    for i in range(nb_participant):
        if (PUBKEYS[k][i] == SimulSigners[k].KEY):
            SimulSigners[k].selfa = int.from_bytes(hl.sha256(b''.join([(PUBKEYS[k][l].x.val).to_bytes(N_bytes, 'big') for l in range(
    nb_participant)] + [(PUBKEYS[k][i].x.val).to_bytes(N_bytes, 'big')])).digest(), 'big') % n

Xtildes = [E] * NB_SIMUL
for l in range(NB_SIMUL):
    for i in range(nb_participant):
        Xtildes[l] = Xtildes[l].complete_add_unsafe(A[l][i] * PUBKEYS[l][i])
        Xtildes[l] = Xtildes[l].to_affine()

print("Xtilde")
print(Xtildes[0])

#on calcule les Rj pour j entre 1 et v
Rn = [[E]*nb_nonces for i in range(NB_SIMUL) ] #encore une fois on simule qu'il y a nb_participant signeurs indépendants
for l in range(NB_SIMUL):
    for j in range(nb_nonces):
        for i in range(nb_participant):
            Rn[l][j] = Rn[l][j].complete_add_unsafe(Nonces[l][i][j])
            Rn[l][j] = Rn[l][j].to_affine()

#on calcule le vecteur b (À CHANGER AVEC LA NOUVELLE VERSION DE MUSIG2)
b = [[1] * nb_nonces for i in range(NB_SIMUL)]
for l in range(NB_SIMUL):
    for j in range(1, nb_nonces):
        b[l][j] = int.from_bytes(hl.sha256(b''.join([(j).to_bytes(4, 'big')] + [(Xtildes[l].x.val).to_bytes(N_bytes, 'big')] + [(
            Rn[l][i].x.val).to_bytes(N_bytes, 'big') for i in range(len(Rn[l]))] + [bytearray(M, 'utf-8')])).digest(), 'big') % n

#on calcule R
Rsign = [E]*NB_SIMUL
for l in range(NB_SIMUL):
    for j in range(nb_nonces):
        Rsign[l] = Rsign[l].complete_add_unsafe(b[l][j] * Rn[l][j])
    Rsign[l] = Rsign[l].to_affine()

#on calcule c
c = [int.from_bytes(hl.sha256(b''.join([(Xtildes[l].x.val).to_bytes(N_bytes, 'big'), (Rsign[l].x.val).to_bytes(N_bytes, 'big'), bytearray(M, 'utf-8')])).digest(), 'big') % n for l in range(NB_SIMUL)]


#on calcule s
s = [0]*NB_SIMUL
for i in range(NB_SIMUL):
    temp = 0
    for j in range(nb_nonces):
        temp += ((SimulSigners[i]).list_r[j] * b[i][j]) % n
    s[i] = (c[i]*SimulSigners[i].selfa*(SimulSigners[i]).key + temp) % n
    print(f"s{i}")
    print(s[i])


print(f"On a calculé les signatures partielles, Voulez vous continuez la signature ? (Envoies des signatures partielles)");
cont = input_yes_no()
if cont == False:
    sys.exit()

#On envoie s_i
mes_sign = [messageSign(SimulSigners[i].KEY,s[i]) for i in range(NB_SIMUL)]
count_sign = 0
while count_sign < NB_SIMUL:
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((ADRESSE, PORT))
        client.send(
            bytes(mes_sign[count_sign]))
        client.close()
        count_sign += 1
    finally:
        client.close()


print(f"On a envoyé les signatures partielles, Voulez vous continuez la signature ? (Reception des signatures partielles)");
cont = input_yes_no()
if cont == False:
    sys.exit()

#Reception des signatures
Sign = [[0] * nb_participant for l in range(NB_SIMUL)] 

count_sign = 0
while count_sign < NB_SIMUL:
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((ADRESSE, PORT))
        donnees = client.recv(MEM)
        Sign[count_sign] = bytes_to_listint(donnees)
        client.close()
        count_sign += 1
    finally:
        client.close()

ssign = (sum(Sign[0])) % n

print(f"La signature est {ssign}")

print(f"La vérification du Signeur 1 donne {(ssign * G) == (Rsign[0] + (c[0] * Xtildes[0]))}")

R,s = FakeKey(G)
print(f"Une signature aléatoire donne : {(s * G) == (R + (c[0] * Xtildes[0]))}")

print(f"On a finit simul")