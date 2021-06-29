#Importation des librairies

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
MEM = 4096 #mémoire nécessaire pour communiquer les infos durant les étapes de communications

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

def str_to_point(str_point):
    temp = str_point[1:len(str_point)-1]
    list_temp = temp.split(" : ")
    return Point(FieldElement(int(list_temp[0],16),F),FieldElement(int(list_temp[1],16),F) , FieldElement(int(list_temp[2],16),F), secp256k1)

def bytesrep_to_messagePoint(bytes):
    str_rep = bytes.decode()
    str_list = str_rep.split(']')
    str_id = str_list[0][5:]
    str_point = str_list[1]
    return messagePoint(str_to_point(str_id),str_to_point(str_point))

def matPoint_to_bytes(R): #pour envoyer matrice de point 
    n = len(R) #censé être nb_participant
    m = len(R[0]) #censé être nb_nonces
    L = []
    for i in range(n-1):
        for j in range(m - 1):
            L.append(repr(R[i][j]).encode())
            L.append(b';')
        L.append(repr(R[i][m-1]).encode())
        L.append(b'\n')
    for j in range(m- 1):
        L.append(repr(R[n-1][j]).encode())
        L.append(b';')
    L.append(repr(R[n-1][m-1]).encode())
    return b''.join(L)

def bytes_to_matPoint(bytes):
    R = [[E]*nb_nonces for i in range(nb_participant)]
    s = bytes.decode()
    list1 = s.split('\n')
    for i in range(nb_participant):
        L = list1[i].split(';')
        for j in range(nb_nonces):
            R[i][j] = str_to_point(L[j])
    return R
        
def listPoint_to_bytes(L):
    n = len(L)
    res = []
    for i in range(n-1):
        res.append(repr(L[i]).encode())
        res.append(b';')
    res.append(repr(L[n-1]).encode())
    return b''.join(res)

def listint_to_bytes(L):
    n = len(L)
    res = []
    for i in range(n-1):
        res.append(hex(L[i]).encode())
        res.append(b';')
    res.append(hex(L[n-1]).encode())
    return b''.join(res)

def bytes_to_list(bytes): #pour communiquer la liste des clefs publiques (même si censé déjà les avoir)
    L = [E] * nb_participant
    s = bytes.decode()
    temp = s.split(';')
    assert len(temp) == nb_participant
    for i in range(nb_participant):
        L[i] = str_to_point(temp[i])
    return L

def bytes_to_listint(bytes):
    L = [0] * nb_participant
    s = bytes.decode()
    temp = s.split(';')
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
        return b''.join(["[ID :".encode('utf-8') ,repr(self.id).encode('utf-8'),"]".encode('utf-8') , repr(self.point).encode('utf-8')])

def bytesrep_to_messageSign(bytes):
    str_rep = bytes.decode()
    str_list = str_rep.split(']')
    str_id = str_list[0][5:]
    str_sign = str_list[1]
    return messageSign(str_to_point(str_id),int(str_sign,16))


#class pour wrapper l'envoie de message en ayant l'information de où vient le message
class messageSign:
    def __init__(self, _id, _sign):
        self.sign = _sign
        self.id = _id

    def __bytes__(self):
        return b''.join(["[ID :".encode('utf-8') ,repr(self.id).encode('utf-8'),"]".encode('utf-8') , hex(self.sign).encode('utf-8')])

#Déroulement de l'algo
class SignScheme:
    def __init__(self, nb_participant, nb_nonces):
        self.nb_participant = nb_participant
        self.nb_nonces = nb_nonces
        self.SignersPUBKEY = [E]  # (Alice, Bob)


    def Sign(self):
        nb_participant = self.nb_participant
        nb_nonces = self.nb_nonces

        # R[i][j] is Rij. Rij est (Rij.x, Rij.y) (attention deux coordonnées)
        R = [[E]*nb_nonces for i in range(nb_participant)]

        #First Signing step (Sign and communication round)
        for i in range(nb_participant):
            self.Signers[i].gen_r()
            for j in range(nb_nonces):
                R[i][j] = (self.Signers[i].list_r[j]) * G  # partage des R.

        #Second Signing step (Sign' and communication round)

        #on calcule les ai
        a = [(int.from_bytes(hl.sha256(b''.join([(L[l].x.val).to_bytes(N_bytes, 'big') for l in range(
            nb_participant)] + [(L[i].x.val).to_bytes(N_bytes, 'big')])).digest(), 'big') % n) for i in range(nb_participant)]

        #on calcule Xtilde
        Xtilde = E
        for i in range(nb_participant):
            Xtilde = Xtilde.complete_add_unsafe(a[i] * L[i])
        self.Xtilde = Xtilde

        #on calcule les Rj pour j entre 1 et v
        Rn = [E]*nb_nonces
        for j in range(nb_nonces):
            for i in range(nb_participant):
                Rn[j] = Rn[j].complete_add_unsafe(R[i][j])

        #on calcule le vecteur b
        b = [1] * nb_nonces
        for j in range(1, nb_nonces):
            b[j] = int.from_bytes(hl.sha256(b''.join([bytes(j), (Xtilde.x.val).to_bytes(N_bytes, 'big')] + [(
                Rn[i].x.val).to_bytes(N_bytes, 'big') for i in range(len(Rn))] + [bytearray(M, 'utf-16')])).digest(), 'big') % n

        #on calcule R
        Rsign = E
        for j in range(nb_nonces):
            Rsign = Rsign.complete_add_unsafe(b[j] * Rn[j])

        #on calcule c
        c = int.from_bytes(hl.sha256(b''.join([(Xtilde.x.val).to_bytes(N_bytes, 'big'), (
            Rsign.x.val).to_bytes(N_bytes, 'big'), bytearray(M, 'utf-16')])).digest(), 'big') % n
        self.c = c

        #on calcule s
        s = [0]*nb_participant
        for i in range(nb_participant):
            temp = 0
            for j in range(nb_nonces):
                temp += ((self.Signers[i]).list_r[j] * b[j]) % n
            s[i] = (c*a[i]*(self.Signers[i]).key + temp) % n
        ssign = (sum(s)) % n

        #on renvoie la signature
        return (Rsign, ssign)

    def verif(self, R, s):
        return (s * G) == (R + (self.c * self.Xtilde))


#Génération de signature aléatoire
def FakeKey(G):
    return (sct.randbelow(n) * G, sct.randbelow(n))


