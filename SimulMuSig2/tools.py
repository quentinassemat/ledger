#Importation des librairies

from operator import truediv
from sympy import isprime

#On prend secrets car random n'est pas fiable pour la cryptographie
import secrets as sct

#pour les fonctions de hash
import hashlib as hl

#pour gérer les courbes elliptiques
from arithm.ecc.curves import secp256k1
from arithm.ecc.ecc import Point
from arithm.field import Field, FieldElement

#pour la communication tcp
import socket

import sys

#on travaille avec secp256K1 : voici quelques constantes :
#G est le générateur de notre groupe
G = secp256k1.G

#ordre du groupe
n = secp256k1.order

#F est le corps de définition de la courbe
F = secp256k1.a.field

#nombre de bytes necessaire pour stocker en byte les entiers
N_bytes = 32

#E est le neutre du groupe
E = Point(F(0), F(1), F(0), secp256k1)

#Données de communication serveur 
ADRESSE = 'localhost'
PORT = 1234
MEM = 16496 #mémoire nécessaire pour communiquer les infos durant les étapes de communications

#Paramètres pour la signature
nb_participant = 6
nb_corromp = 0
nb_nonces = 3
M = "Alice donne 1 Bitcoin à Bob"

#Class signer à sa clef publique (self.KEY), sa clef prive (self.key), une fonction de generation aleatoire
class Signer:
    #constructeurs
    def __init__(self, nb_nonces):
        self.key = sct.randbelow(n - 1) + 1
        self.KEY = self.key * G
        self.list_r = [0]*nb_nonces

    def gen_r(self):
        for i in range(len(self.list_r)):
            self.list_r[i] = sct.randbelow(n)

def point_to_bytes(p):
    res = bytearray(b"(")
    res.extend((p.x.val).to_bytes(N_bytes, 'big'))
    res.extend(b' : ')
    res.extend((p.y.val).to_bytes(N_bytes, 'big'))
    res.extend(b' : ')
    res.extend((p.z.val).to_bytes(N_bytes, 'big'))
    res.extend(b')')
    return bytes(res)

def bytes_to_point(bytes_point):
    temp = bytes_point[1:len(bytes_point)-1]
    list_temp = temp.split(b' : ')
    return Point(FieldElement(int.from_bytes(list_temp[0], 'big'),F),FieldElement(int.from_bytes(list_temp[1], 'big'),F), FieldElement(int.from_bytes(list_temp[2], 'big'),F), secp256k1)

def bytesrep_to_messagePoint(bytesrep):
    bytesrep_list = bytesrep.split(b' ] ')
    str_id = bytesrep_list[0][5:]
    str_point = bytesrep_list[1]
    return messagePoint(bytes_to_point(str_id),bytes_to_point(str_point))

def matPoint_to_bytes(R): #pour envoyer matrice de point 
    n = len(R) #censé être nb_participant
    m = len(R[0]) #censé être nb_nonces
    L = []
    for i in range(n-1):
        for j in range(m - 1):
            L.append(point_to_bytes(R[i][j]))
            L.append(b' ; ')
        L.append(point_to_bytes(R[i][m-1]))
        L.append(b' \n ')
    for j in range(m- 1):
        L.append(point_to_bytes(R[n-1][j]))
        L.append(b' ; ')
    L.append(point_to_bytes(R[n-1][m-1]))
    return b''.join(L)

def bytes_to_matPoint(bytes):
    R = [[E]*nb_nonces for i in range(nb_participant)]
    list1 = bytes.split(b' \n ')
    for i in range(nb_participant):
        L = list1[i].split(b' ; ')
        for j in range(nb_nonces):
            R[i][j] = bytes_to_point(L[j])
    return R
        
def listPoint_to_bytes(L):
    n = len(L)
    res = []
    for i in range(n-1):
        res.append(point_to_bytes(L[i]))
        res.append(b' ; ')
    res.append(point_to_bytes(L[n-1]))
    return b''.join(res)

def listint_to_bytes(L):
    n = len(L)
    res = []
    for i in range(n-1):
        res.append(hex(L[i]).encode())
        res.append(b' ; ')
    res.append(hex(L[n-1]).encode())
    return b''.join(res)

def bytes_to_list(bytes): #pour communiquer la liste des clefs publiques (même si censé déjà les avoir)
    L = [E] * nb_participant
    temp = bytes.split(b' ; ')
    assert len(temp) == nb_participant
    for i in range(nb_participant):
        L[i] = bytes_to_point(temp[i])
    return L

def bytes_to_listint(bytes):
    L = [0] * nb_participant
    temp = bytes.split(b' ; ')
    assert len(temp) == nb_participant
    for i in range(nb_participant):
        L[i] = int(temp[i],16)
    return L


#class pour wrapper l'envoie de message en ayant l'information de où vient le message
class messagePoint:
    def __init__(self, _id, _point):
        self.point = _point
        self.id = _id

    def __bytes__(self):
        return b''.join(["[ID :".encode('utf-8') ,point_to_bytes(self.id)," ] ".encode('utf-8') , point_to_bytes(self.point)])

def bytesrep_to_messageSign(bytes):
    str_list = bytes.split(b']')
    str_id = str_list[0][5:]
    str_sign = str_list[1]
    return messageSign(bytes_to_point(str_id),int.from_bytes(str_sign, 'big'))

#class pour wrapper l'envoie de message en ayant l'information de où vient le message
class messageSign:
    def __init__(self, _id, _sign):
        self.sign = _sign
        self.id = _id

    def __bytes__(self):
        return b''.join(["[ID :".encode('utf-8') ,point_to_bytes(self.id),"]".encode('utf-8') , hex(self.sign).encode('utf-8')])

#Génération de signature aléatoire
def FakeKey(G):
    return (sct.randbelow(n) * G, sct.randbelow(n))

def input_yes_no():
    while True:
        str = input("")
        if str == "yes":
            return True
        elif str == "no":
            return False
        else:
            print("Please enter a valid input (yes/no)")