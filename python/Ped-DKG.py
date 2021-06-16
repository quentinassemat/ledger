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
        assert t < n
        self.index = index  # correspond au numéro du Signer
        self.t = t
        self.n = n
        self.coef = [0]*t  # de a_0 à a_{t-1}
        for i in range(t):
            self.coef[i] = sct.randbelow(p)

        # correspond aux shares qui seront stocké (les f_i(j) pour 1 <= i <= n)
        self.shares = [0] * n

        # correspond aux plaintes (vrai si plainte contre i)
        self.complains = [False] * n

    def poly(self, z):  # fonction poly aléatoire, optimisable avec Horner
        res = 0
        for i in range(self.t):
            res = res + pow(z, i)*self.coef[i]
        return res % p

    # def poly(self, z):  # Fausse fonction aléatoire pour coder les cas qui n'arrive pas normalement
    #     res = 0
    #     for i in range(self.t):
    #         res = res + pow(3,i)
    #     return res % p

    #reste à coder un truc qui fait en sorte qu'il y ait un traitre sur deux afin de tester la reconstruction

class Signer:
    #constructeurs
    def __init__(self, t, n, index):
        self.index = index

        #on génère clefs publiques/privés mais elles seront redéfini lors de la signature Threshold
        self.key = sct.randbelow(p - 1) + 1
        self.KEY = self.key * G

        self.DKG1 = PedKDG(t, n, index)  # pour les clés privés
        self.DKG2 = PedKDG(t, n, index)  # pour les nombres aléatoires

        #on génère nonces publiques/privés mais elles seront redéfini lors de la signature Threshold
        self.nonce = sct.randbelow(p - 1) + 1
        self.NONCE = self.nonce * G


#Déroulement de l'algo


class SignScheme:
    def __init__(self, n, t):
        self.n = n
        self.t = t
        self.Signers = [Signer(t, n, i) for i in range(n)]  # (Alice, Bob)
        #c'est à cette étape que sont générés les fonctions polynomiales aléatoires

    def KeyGen(self):
        # correspond à la liste des Xik dans le papier mais pour le premier DKG
        self.X1 = [[E]*self.t for l in range(self.n)]

        #Étape 1 Ped-KG
        for i in range(self.n):
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
                    self.Signers[j].DKG1.shares[i] * G != temp)
        #on vient de remplir les tableaux de plaintes

        #Étape 3 Ped-KG (on tourne un peu en rond comme on vérifie plusieurs fois la même chose)
        # counter_plaints[i] est le nombre de plaintes contre le Signer i
        counter_plaints = [0] * self.n
        for i in range(self.n):
            for j in range(self.n):
                if(self.Signers[i].DKG1.complains[j]):
                    counter_plaints[j] += 1

        #En fonctions de plaintes on disqualifie ou non
        for i in range(self.n):
            if (counter_plaints[i] >= self.t):  # si trop de plaintes : disqualifié
                self.Signers[i].key = 0
                self.Signers[i].KEY = E
            # si au moins une plainte on regarde les shares
            elif (counter_plaints[i] > 0):
                for j in range(self.n):
                    # ici on calcule deux fois la même chose pour suivre à la lettre l'algo du papier
                    if (self.Signers[j].DKG1.complains[i]):
                        temp = E
                        for k in range(self.t):
                            temp = temp.complete_add_unsafe(
                                pow(j+1, k) * self.X1[i][k])
                        # si bel et bien équation pas correct on disqualifie
                        if (self.Signers[j].DKG1.shares[i] * G != temp):
                            print(
                                'Il y a trop de plainte, ce signeur est disqualifié (2)')
                            self.Signers[i].key = 0
                            self.Signers[i].KEY = E

        #Étape 4 Ped-KG :
        self.PUBKEY = E
        for i in range(self.n):
            self.PUBKEY = self.PUBKEY.complete_add_unsafe(self.Signers[i].KEY)

        #peut être rajouter le calcul de la clé publique à voir

    def NonceGen(self):
        # correspond à la liste des Xik dans le papier mais pour le premier DKG
        self.X2 = [[E]*self.t for l in range(self.n)]

        #Étape 1 Ped-KG
        for i in range(self.n):
            for k in range(self.t):
                self.X2[i][k] = self.Signers[i].DKG2.coef[k] * G
            self.Signers[i].nonce = self.Signers[i].DKG2.coef[0]
            self.Signers[i].NONCE = self.Signers[i].nonce * G
            for j in range(self.n):
                # le Signer j () a toutes les valeurs f_i(j +1 ) pour 0 <= i,j <= n-1. On a xij = self.Signers[j].DKG1.shares[i]
                self.Signers[j].DKG2.shares[i] = self.Signers[i].DKG2.poly(
                    j + 1)

        #Étape 2 Ped-KG
        for j in range(self.n):
            for i in range(self.n):
                temp = E
                for k in range(self.t):
                    temp = temp.complete_add_unsafe(
                        pow(j+1, k) * self.X2[i][k])
                self.Signers[j].DKG2.complains[i] = (
                    self.Signers[j].DKG2.shares[i] * G != temp)
        #on vient de remplir les tableaux de plaintes

        #Étape 3 Ped-KG (on tourne un peu en rond comme on vérifie plusieurs fois la même chose)
        # counter_plaints[i] est le nombre de plaintes contre le Signer i
        counter_plaints = [0] * self.n
        for i in range(self.n):
            for j in range(self.n):
                if(self.Signers[i].DKG2.complains[j]):
                    counter_plaints[j] += 1

        #En fonctions de plaintes on disqualifie ou non
        for i in range(self.n):
            if (counter_plaints[i] >= self.t):  # si trop de plaintes : disqualifié
                self.Signers[i].nonce = 0
                self.Signers[i].NONCE = E
            # si au moins une plainte on regarde les shares
            elif (counter_plaints[i] > 0):
                for j in range(self.n):
                    # ici on calcule deux fois la même chose pour suivre à la lettre l'algo du papier
                    if (self.Signers[j].DKG2.complains[i]):
                        temp = E
                        for k in range(self.t):
                            temp = temp.complete_add_unsafe(
                                pow(j+1, k) * self.X2[i][k])
                        # si bel et bien équation pas correct on disqualifie
                        if (self.Signers[j].DKG2.shares[i] * G != temp):
                            self.Signers[i].nonce = 0
                            self.Signers[i].NONCE = E

        #Étape 4 Ped-KG :
        self.PUBNONCE = E
        for i in range(self.n):
            self.PUBNONCE = self.PUBNONCE.complete_add_unsafe(
                self.Signers[i].NONCE)

        #peut être rajouter ici le calcul du nonce privé

    def Sign(self):
        #Inputs (papier)
        self.KeyGen()
        #Étape 1
        self.NonceGen()

        #Étape 2
        c = int.from_bytes(hl.sha256(b''.join([bytearray(
            M, 'utf-16'), self.PUBNONCE.x.val.to_bytes(N_bytes, 'big')])).digest(), 'big') % p

        #Étape 3
        # pour compter combien de Signer ont envoyé la bonne share. Cela permettra de reconstruire la share des personnes ayant tricher. 1 correspond à bonne signature.
        trust_count = [1] * self.n
        self.keyshare = [0] * self.n
        for i in range(self.n):
            self.keyshare[i] = self.Signers[i].nonce + c * self.Signers[i].key % p
            if ((self.Signers[i].KEY.is_at_infinity()) or (self.keyshare[i] * G != self.Signers[i].NONCE.complete_add_unsafe(c * self.Signers[i].KEY))):
                trust_count[i] = 0

        #cas qui n'arrivera pas où pas assez de bonne signature
        if (sum(trust_count) < self.t):
            print(
                f"Il n'y a seulement que {sum(trust_count)} bonne share alors que t = {self.t}. ")
            print("La signature échoue")
            return (G, 1)


        trust_count[0] = 0 #pour tester la reconstruction

        print(f"Ancienne signature : {self.keyshare[0]}")

        #cas qui n'arrivera pas où assez de signature mais reconstruction nécessaire.
        #on stocke liste indice avec vrai signature
        L = []
        h = 0
        while(len(L) < self.t):
            if (trust_count[h] == 1):
                L.append(h)
            h += 1

        print(f"La liste des Signers de confiances {L} ")

        #reconstruction à partir d'une liste fiable des potentiels fausse signatures
        for i in range(self.n):
            if (trust_count[i] == 0):
                #reconstruction de xi avec Lagrange à partir des shares stockées
                print(f"Ancien xi : {self.Signers[i].key}")
                coef = [1] * self.t
                for k in range(self.t):
                    inv = 1
                    for j in L:
                        if (j != L[k]):
                            coef[k] *= j
                            inv *= (j - L[k])
                    coef[k] *= pow(inv, -1, p) * \
                        self.Signers[L[k]].DKG1.shares[i]
                xi = 1
                for k in range(self.t):
                    xi *= coef[i]

                self.Signers[i].key = xi % p
                print(f"Nouveau xi : {self.Signers[i].key}")

                #reconstruction de ki avec Lagranfe à partir des shares stockées
                print(f"Ancien ki : {self.Signers[i].nonce}")
                coef = [1] * self.t
                for k in range(self.t):
                    inv = 1
                    for j in L:
                        if (j != L[k]):
                            coef[k] *= j
                            inv *= (j - L[k])
                    coef[k] *= pow(inv, -1, p) * \
                        self.Signers[L[k]].DKG2.shares[i]
                ki = 1
                for k in range(self.t):
                    ki *= coef[i]

                self.Signers[i].nonce = ki % p
                print(f"nouveau ki : {self.Signers[i].nonce}")

                #reconstruction de la signature
                self.keyshare[i] = self.Signers[i].nonce + \
                    c * self.Signers[i].key % p
                
                print(f"Nouvelle signature : {self.keyshare[i]}")

        s = sum(self.keyshare) % p
        return (self.PUBNONCE, s)

    def verif(self, R, s):
        c = int.from_bytes(hl.sha256(b''.join(
            [bytearray(M, 'utf-16'), R.x.val.to_bytes(N_bytes, 'big')])).digest(), 'big') % p
        if (self.PUBKEY.is_at_infinity()):
            return False
        return (s * G == R.complete_add_unsafe(c * self.PUBKEY))


def FakeKey(G):
    return (sct.randbelow(p) * G, sct.randbelow(p))


#paramètre pour signer :
M = 'Alice donne 1 Bitcoin à Bob'

nb_participant = 3
threshold = 2

#Déroulement de l'algo


Signsch = SignScheme(nb_participant, threshold)
R, s = Signsch.Sign()
print(f"La signature est : {R},{s}")
print(f"La vérification donne : {Signsch.verif(R,s)}")
#on créé une signature aléatoire :
(Rrand, srand) = FakeKey(G)
print(
    f"La vérification sur une clé aléatoire donne {Signsch.verif(Rrand, srand)}")
