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
n = secp256k1.order

#F est le corps de définition de la courbe
F = secp256k1.a.field

#nombre de bytes necessaire pour stocker en byte les entiers
N_bytes = 32

#E est le neutre du groupe
E = Point(F(0), F(1), F(0), secp256k1)

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

#Déroulement de l'algo


class SignScheme:
    def __init__(self, nb_participant, nb_nonces):
        self.nb_participant = nb_participant
        self.nb_nonces = nb_nonces
        self.Signers = [Signer(nb_nonces)
                        for i in range(nb_participant)]  # (Alice, Bob)

    def Sign(self):
        nb_participant = self.nb_participant
        nb_nonces = self.nb_nonces

        #Les Signeurs ont chacun une clef privée, une clef publique a ce moment
        L = [self.Signers[i].KEY for i in range(nb_participant)]
        # R[i][j] is Rij. Rij est (Rij.x, Rij.y) (attention deux coordonnées)
        R = [[E]*nb_nonces for i in range(nb_participant)]

        #First Signing step (Sign and communication round)
        for i in range(nb_participant):
            self.Signers[i].gen_r()
            for j in range(nb_nonces):
                R[i][j] = (self.Signers[i].list_r[j]) * G  # partage des R.
                print(R[i][j])

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

#Génération des différentes paramètres pour une signature


nb_participant = 4
nb_nonces = 3
M = "Alice donne 1 Bitcoin à Bob"

print(f"On tente de signer le message : {M}")
print(f"Le nombre de participant est {nb_participant}")
print(f"Le nombre de nonces (MuSig2) est : {nb_nonces} \n")

#Génération de signature aléatoire


def FakeKey(G):
    return (sct.randbelow(n) * G, sct.randbelow(n))

#Déroulement de l'algo


Signsch = SignScheme(nb_participant, nb_nonces)
R, s = Signsch.Sign()
print(f"La signature est : {R},{s}")
print(f"La vérification donne : {Signsch.verif(R,s)}")
#on créé une signature aléatoire :
(Rrand, srand) = FakeKey(G)
print(
    f"La vérification sur une clé aléatoire donne {Signsch.verif(Rrand, srand)}")
