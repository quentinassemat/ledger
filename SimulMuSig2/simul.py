#CE PYTHON SIMULE N-1 SIGNEURS AVEC UN NOMBRE DÉFINI DE SIGNEUR DE CONFIANCE 

#pour pouvoir utiliser les objets de tools.py comme un #include "lib.h"
from tools import *
import copy

SimulSigners = [Signer(nb_nonces) for i in range(nb_participant)]

#les nonces qui sont publiques  
R = [[E]*nb_nonces for i in range(nb_participant)]
Nonces = [R] * nb_participant #Nonces contient nb_participant fois la même chose mais c'est pour simuler qu'il y a bien plusieurs signeurs simulé par ce py

#Envoie des clefs publiques au serveur
for i in range(nb_participant):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((ADRESSE, PORT))
    client.send(repr(SimulSigners[i].KEY).encode())
    client.close()

#Reception des clefs publiques des autres:
PUBKEYS = [[] for i in range(nb_participant)]
for l in range(nb_participant):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((ADRESSE, PORT))
    donnees = client.recv(MEM)
    PUBKEYS[l] = bytes_to_list(donnees)
    client.close()

#Envoie des nonces au serveur
#First Signing step (Sign and communication round)
for i in range(nb_participant):
    SimulSigners[i].gen_r()
    for j in range(nb_nonces):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((ADRESSE, PORT))
        client.send(
            bytes(messagePoint(SimulSigners[i].KEY, ((SimulSigners[i].list_r[j]) * G))))
        client.close()

#Reception des nonces 
for l in range(nb_participant):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((ADRESSE, PORT))
    donnees = client.recv(MEM)
    Nonces[l] = bytes_to_matPoint(donnees)
    client.close()

#Calcul individuel des ai/Xtilde

A = [] # correspond à nb_participant fois les ai pour simuler les signeurs indépendants
for i in range(nb_participant):
    A.append([(int.from_bytes(hl.sha256(b''.join([(PUBKEYS[i][l].x.val).to_bytes(N_bytes, 'big') for l in range(
    nb_participant)] + [(PUBKEYS[i][i].x.val).to_bytes(N_bytes, 'big')])).digest(), 'big') % n) for i in range(nb_participant)])

Xtildes = [E] * nb_participant
for l in range(nb_participant):
    for i in range(nb_participant):
        Xtildes[l] = Xtildes[l].complete_add_unsafe(A[l][i] * PUBKEYS[l][i])

#on calcule les Rj pour j entre 1 et v
Rn = [[E]*nb_nonces for i in range(nb_participant) ] #encore une fois on simule qu'il y a nb_participant signeurs indépendants
for l in range(nb_participant):
    for j in range(nb_nonces):
        for i in range(nb_participant):
            Rn[l][j] = Rn[l][j].complete_add_unsafe(Nonces[l][i][j])

#on calcule le vecteur b
b = [[1] * nb_nonces for i in range(nb_participant)]
for l in range(nb_participant):
    for j in range(1, nb_nonces):
        b[l][j] = int.from_bytes(hl.sha256(b''.join([bytes(j), (Xtildes[l].x.val).to_bytes(N_bytes, 'big')] + [(
            Rn[l][i].x.val).to_bytes(N_bytes, 'big') for i in range(len(Rn[l]))] + [bytearray(M, 'utf-16')])).digest(), 'big') % n

#on calcule R
Rsign = [E]*nb_participant
for l in range(nb_participant):
    for j in range(nb_nonces):
        Rsign[l] = Rsign[l].complete_add_unsafe(b[l][j] * Rn[l][j])

#on calcule c
c = [int.from_bytes(hl.sha256(b''.join([(Xtildes[l].x.val).to_bytes(N_bytes, 'big'), (Rsign[l].x.val).to_bytes(N_bytes, 'big'), bytearray(M, 'utf-16')])).digest(), 'big') % n for l in range(nb_participant)]


#on calcule s
s = [0]*nb_participant
for i in range(nb_participant):
    temp = 0
    for j in range(nb_nonces):
        temp += ((SimulSigners[i]).list_r[j] * b[i][j]) % n
    s[i] = (c[i]*A[i][i]*(SimulSigners[i]).key + temp) % n


#On envoie s_i
mes_sign = [messageSign(SimulSigners[i].KEY,s[i]) for i in range(nb_participant)]
for i in range(nb_participant):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((ADRESSE, PORT))
    client.send(
        bytes(mes_sign[i]))
    client.close()

#Reception des signatures
Sign = [[0] * nb_participant] 
for l in range(nb_participant):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((ADRESSE, PORT))
    donnees = client.recv(MEM)
    Nonces[l] = bytes_to_listint(donnees)
    client.close()

ssign = (sum(s)) % n

print(f"La signature est {ssign}")

print(f"La vérification du Signeur 1 donne {(ssign * G) == (Rsign[0] + (c[0] * Xtildes[0]))}")

R,s = FakeKey(G)
print(f"Une signature aléatoire donne : {(s * G) == (R + (c[0] * Xtildes[0]))}")

print(f"On a finit simul")
