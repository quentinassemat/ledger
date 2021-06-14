#Importation des librairies

from sympy import isprime

#On prend secrets car random n'est pas fiable pour la cryptographie
import secrets as sct 

#pour les fonctions de hash
import hashlib as hl



#Class Group qui contient un generateur (self.g), son ordre (self.p)...    
class SchnorrGroup:
    def __init__(self,p,q,r,h):
        assert(isprime(p))
        self.p = p
        assert(isprime(q))
        self.order = q
        assert(p == q*r +1)
        g = pow(h,r,p)
        assert(pow(h,r,p) != 1)
        self.g = g
        
    def elem(self,i):
        return pow(self.g,i,self.p)
    
    def gprint(self):
        print('ordre : {self.order}')
        print("On travaille dans Z/{self.p}Z")
        for i in range(self.order):
            print(f"element {i} : {self.elem(i)}")
            
#Ici le groupe de Schnorr est un sous groupe des inversibles de Zp. Lordre est note p pour la suite par cohérence
#avec les papiers (notamment dans la classe Signer)
            
            
#Class signer à sa clef publique (self.KEY), sa clef prive (self.key), une fonction de generation aleatoire
class Signer:
    #constructeurs
    def __init__(self,G, nb_nonces):
        self.key = sct.randbelow(G.order - 1) +1
        self.KEY = G.elem(self.key)
        self.p = G.order
        self.list_r = [0]*nb_nonces
    
    def r(self):
        return sct.randbelow(self.p - 1)
    
    def gen_r(self):
        for i in range(len(self.list_r)):
            self.list_r[i] = sct.randbelow(G.order)

#Déroulement de l'algo 

#FONCTION DE HASH A REVOIR (j'ai fait la somme pour les listes et non pas une séquence predefinie)

class SignScheme:
    def __init__(self, G,nb_participant, nb_nonces):
        self.G = G
        self.nb_participant = nb_participant
        self.nb_nonces = nb_nonces
        self.Signers = [Signer(G,nb_nonces) for i in range (nb_participant)] #(Alice, Bob)
    
    def Sign(self):
        G = self.G
        nb_participant = self.nb_participant
        nb_nonces = self.nb_nonces
        #Les Signeurs ont chacun une clef privée, une clef publique a ce moment
        L = [self.Signers[i].KEY for i in range(nb_participant)]
        R = [[0]*nb_nonces for i in range(nb_participant)] #R[i][j] is Rij

        #First Signing step (Sign and communication round)
        for i in range(nb_participant):
            self.Signers[i].gen_r()
            for j in range(nb_nonces):
                R[i][j] = G.elem(self.Signers[i].list_r[j]) #partage des R
    
        #Second Signing step (Sign' and communication round)
        
        #on calcule les ai
        a = [ (int.from_bytes(hl.sha256(b''.join([sum(L).to_bytes(sum(L).bit_length()//7,'big'),L[i].to_bytes(L[i].bit_length()//7,'big')])).digest(),'big')%G.order) for i in range(nb_participant)] 
        
        #on calcule Xtilde
        Xtilde = 1
        for i in range (nb_participant):
            Xtilde = Xtilde * pow(L[i],a[i],G.p)
        Xtilde = Xtilde % G.p
        self.Xtilde = Xtilde
        
        #on calcule les Rj pour j entre 1 et v
        Rn = [1]*nb_nonces
        for j in range(nb_nonces):
            for i in range(nb_participant):
                Rn[j] = Rn[j] * R[i][j]
        
        #on calcule le vecteur b
        b = [1] * nb_nonces
        for j in range(1,nb_nonces):
            b[j] = int.from_bytes(hl.sha256(b''.join([bytes(j),Xtilde.to_bytes(Xtilde.bit_length()//7,'big')] + [Rn[i].to_bytes(Rn[i].bit_length()//7,'big') for i in range(len(Rn))] + [bytearray(M,'utf-16')])).digest(),'big')%G.order
        
        #on calcule R
        Rsign=1
        for j in range(nb_nonces):
            Rsign *= pow(Rn[j],b[j],G.p)
        Rsign = Rsign % G.p
        
        #on calcule c
        c = int.from_bytes(hl.sha256(b''.join([Xtilde.to_bytes(Xtilde.bit_length()//7,'big'), Rsign.to_bytes(Rsign.bit_length()//7,'big'), bytearray(M,'utf-16')])).digest(),'big')%G.order
        self.c = c
        
        #on calcule s
        s=[0]*nb_participant
        for i in range(nb_participant):
            temp = 0
            for j in range(nb_nonces):
                temp += ((self.Signers[i]).list_r[j] * b[j])%G.order
            s[i] = (c*a[i]*(self.Signers[i]).key + temp)%G.order
        ssign = (sum(s))%G.order
        
        #on renvoie la signature
        return (Rsign,ssign)

    def verif(self,R,s):
        return ((self.G).elem(s) == (R*pow(self.Xtilde,self.c,G.p)) % self.G.p )             



#Génération des différentes paramètres pour une signature 

#choix de p,q pour le groupe de Schnorr (le q sera l'ordre du groupe G.order et le p du papier)
#p, q, r, h = 23, 11, 2, 7
p, q, r, h = 115792089237316195423570985008687907852837564279074904382605163141518161494337, 341948486974166000522343609283189,338624364920977752681389262317185522840540224,3141592653589793238462643383279502884197

#on vérifie que les choix de p,q,r,h sont bon
print("Choississons un bon groupe de Schnorr pour effectuer la multisignature : ")
print(f"p est-il  premier : {isprime(p)}")
print(f"q est-il  premier : {isprime(p)}")
print(f" a t on la bonne relation : {p == q*r +1}")
print(f"on a un générateur : {pow(h,r,p) != 1}\n")

G = SchnorrGroup(p,q,r,h)

nb_participant = 4
nb_nonces = 3
M = "Alice donne 1BT à Bob"

print(f"On tente de signer le message : {M}")
print(f"Le nombre de participant est {nb_participant}")
print(f"Le nombre de nonces (MuSig2) est : {nb_nonces} \n")

#Génération de signature aléatoire
def FakeKey(G):
    return (G.elem(sct.randbelow(G.order)),sct.randbelow(G.order))


#Déroulement de l'algo

Signsch = SignScheme(G,nb_participant,nb_nonces)
R,s= Signsch.Sign()
print(f"La signature est : {R},{s}")
print(f"La vérification donne : {Signsch.verif(R,s)}")
#on créé une signature aléatoire :
(Rrand,srand) = FakeKey(G)
print(f"La vérification sur une clé aléatoire donne {Signsch.verif(Rrand, srand)}")