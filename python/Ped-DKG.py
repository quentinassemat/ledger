#Importation des librairies

from sympy import isprime

#On prend secrets car random n'est pas fiable pour la cryptographie
import secrets as sct

#pour les fonctions de hash
import hashlib as hl

#pour gérer les courbes elliptiques
from arithm.ecc.curves import secp256k1
from arithm.ecc.ecc import Point
from arithm.field import Field

#on travaille avec secp256K1 : voici quelques constantes :
#G est le générateur de notre groupe
G = secp256k1.G

#ordre du groupe
p = secp256k1.order

#F est le corps de définition de la courbe
F = secp256k1.a.field

#nombre de bytes necessaire pour stocker en byte les entiers
N_bytes = 32

#E est le neutre du groupe
E = Point(F(0), F(1), F(0), secp256k1)

#Class signer à sa clef publique (self.KEY), sa clef prive (self.key),
#une fonction de génération aléatoire des coefficients de la fonction polynomiale (coef)

#class qui stocke ce qui est nécessaire sur chaque DKG et qui donne les fonctions de calculs
#on aura donc deux PedDKG par Signer


class PedKDG:
    def __init__(self, t, n, index):
        self.index = index  # correspond au numéro du Signer
        self.t = t
        self.n = n
        self.coef = [0]*t  # de a_0 à a_{t-1}
        for i in range(t):
            self.coef[i] = sct.randbelow(p)
        # correspond aux shares qui seront stocké (les f_i(j) pour 1 <= i <= n)
        self.shares = [0] * n
        self.complains = [False] * n  # correspond aux plaintes

    def poly(self, z):  # fonction poly aléatoire, calculé avec Horner
        res = self.coef[self.t-1]
        for i in range(self.t - 2, -1, 1):
            res = res * z + self.coef[i]
        return res


class Signer:
    #constructeurs
    def __init__(self, t, n, index):
        self.index = index
        self.key = sct.randbelow(p - 1) + 1
        self.KEY = self.key * G

        self.DKG1 = PedKDG(t, n, index)  # pour les clés privés
        self.DKG2 = PedKDG(t, n, index)  # pour les nombres aléatoires


#Déroulement de l'algo


class SignScheme:
    def __init__(self, n, t):
        self.n = n
        self.t = t
        self.Signers = [Signer(t, n, i) for i in range(n)]  # (Alice, Bob)

    def KeyGen(self):
        # correspond à la liste des Xik dans le papier mais pour le premier DKG
        self.X1 = [[E]*self.t for l in range(self.n)]

        #Étape 1 Ped-KG
        for i in range(self.n):
            self.Signers[i].DKG1.poly()  # on génère les coefficients
            for k in range(self.t):
                self.X1[i][k] = self.Signers[i].DKG1.coef[k] * G
            self.Signers[i].key = self.Signers[i].DKG1.coef[0]
            self.Signers[i].KEY = self.Signers[i].key * G
            for j in range(self.n):
                # le Signer j () a toutes les valeurs f_i(j +1 ) pour 0 <= i,j <= n-1. On a xij = self.Signers[j].DKG1.shares[i]
                self.Signers[j].DKG1.shares[i] = self.Signers[i].DKG1.poly(
                    j + 1)

        #Étape 2 Ped-KG
        for j in range(self.n):
            for i in range(self.n):
                temp = E
                for k in range(self.t):
                    temp = temp.complete_add_unsafe(
                        pow(j+1, k) * self.X1[i][k])
                self.Signers[j].DKG1.complains[i] = (
                    self.Signers[j].DKG1.shares[i] * G == temp)
        #on vient de remplir les tableaux de plaintes

        #Étape 3 Ped-KG
        # counter_plaints[i] est le nombre de plaintes contre le Signer i
        counter_plaints = [0] * self.n
        for i in range(self.n):
            for j in range(self.n):
                if(self.Signers[i].DKG1.complains[j]):
                    counter_plaints[j] += 1

        for i in range(self.n):
            if (counter_plaints[i] >= self.t):  # si trop de plaintes : disqualifié
                self.Signers[i].key = 0
                self.Signers[i].KEY = E

    def DKG(self):
        # correspond à la liste des Xik dans le papiers
        self.X = [[E]*self.t for l in range(self.n)]
        for i in range(self.n):
            self.Signers[i].gen_poly()  # on génère les coefficients
            for k in range(self.t):
                self.X[i][k] = self.Signers[i].coef[k] * G
            self.Signers[i].key = self.Signers[i].coef[0]
        return 1

    def Sign(self):
        return 1

    def verif(self, R, s):
        return 1
