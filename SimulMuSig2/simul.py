#CE PYTHON SIMULE N-1 SIGNEURS AVEC UN NOMBRE DÉFINI DE SIGNEUR DE CONFIANCE 

#pour pouvoir utiliser les objets de tools.py comme un #include "lib.h"
from os import wait
from tools import *

SimulSigners = [Signer(nb_nonces) for i in range(nb_participant)]

#Envoie des clefs publiques au serveur
for i in range(nb_participant):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((ADRESSE, PORT))
    client.send(repr(SimulSigners[i].KEY).encode())
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


