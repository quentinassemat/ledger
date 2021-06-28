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
#On renvoie les clés publiques pour chaque signeurs possède la liste (bien que dans la vraie vie ils ont déjà la liste des clés publiques)

count_pubkeys = 0

while count_pubkeys < nb_participant:
    try:
        client, adresseClient = serveur.accept()
        client.sendall(listPoint_to_bytes(PUBKEYS))
        count_pubkeys += 1
    finally:
        client.close()

#Maintenant les signeurs calculent de leur côté le nonce et on le récolte
#First Signing step (Sign and communication round)

# R[i][j] is Rij.
# Rij est (Rij.x, Rij.y) (attention deux coordonnées)

R = [[] for i in range(nb_participant)] #on remplit à la première étape
count_nonce = 0

while count_nonce < nb_nonces * nb_participant:
    try:
        client, adresseClient = serveur.accept()
        donnees = client.recv(MEM)
        if not donnees:
            print("Erreur de reception")
        else:
            mes = bytesrep_to_messagePoint(donnees)
            for i in range(nb_participant):
                if PUBKEYS[i] == mes.id: 
                    R[i].append(mes.point) #on suppose ques les nonces sont envoyés dans l'ordre pour chaque joueur
                    count_nonce += 1
            print(f"On a {count_nonce} nonce")
            client.close()
    finally:
        client.close()

#On a reçu les nonces. 
#Second Signing step (Sign' and communication round)
#On envoie aux signeurs les nonces qui lui sont destinés et les signeurs calculent les ai/Xtilde...
#On garde le rôle de serveur donc on attend que les Signeurs "veuillent" recevoir leur nonce:

count_signers = 0

while count_signers < nb_participant:
    try:
        client, adresseClient = serveur.accept()
        client.sendall(matPoint_to_bytes(R))
        count_signers += 1
    finally:
        client.close()
