#CE PYTHON EST LE SERVEUR ENTRE LES N SIGNEURS DONT CERTAINS SONT CORROMPUS. C'EST LUI QUI DÉROULE L'ALGO

#pour pouvoir utiliser les objets de tools.py comme un #include "lib.h"
from tools import *

#on écoute sur le port
serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serveur.bind((ADRESSE, PORT))
serveur.listen(1)

#Collecte des id (clé publiques) des signeurs:
PUBKEYS = []

while len(PUBKEYS) < nb_participant:
    try:
        client, adresseClient = serveur.accept()
        donnees = client.recv(MEM)
        if not donnees:
            print("Erreur de reception")
        else:
            PUBKEYS.append(str_to_point(donnees.decode()))
            print(f"On a {len(PUBKEYS)} clefs publiques")
            client.close()
    finally:
        client.close()

#On a récolté les clé publiques. On ne travaillera plus qu'avec ces personnes la (et ça nous permet de savoir de qui viennent les messages parce que dans la vraie vie on ne saura pas l'ordre)

#Maintenant les signeurs calculent de leur côté le nonce et on le récolte
#First Signing step (Sign and communication round)

# R[i][j] is Rij.
# Rij est (Rij.x, Rij.y) (attention deux coordonnées)
R = [[E]*nb_nonces for i in range(nb_participant)]
count_nonce = 0

while count_nonce < nb_nonces * nb_participant:
    try:
        client, adresseClient = serveur.accept()
        donnees = client.recv(MEM)
        if not donnees:
            print("Erreur de reception")
        else:
            mes = bytesrep_to_messagePoint(donnees)
            for j in range(nb_participant)

            print(f"On a {len(PUBKEYS)} clefs publiques")
            client.close()
    finally:
        client.close()
