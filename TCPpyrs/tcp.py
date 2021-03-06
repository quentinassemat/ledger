import socket

ADRESSE = 'localhost'
PORT = 1234

serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serveur.bind((ADRESSE, PORT))
serveur.listen(1)

while True:
    try:
        client, adresseClient = serveur.accept()
        donnees = client.recv(1024)
        if not donnees:
            print("Erreur de reception")
        else:
            print(f"[{adresseClient}] : {donnees.decode()}")
            if ((donnees.decode() == "shutdown\n") or (donnees.decode() == "shutdown\r\n")):
                client.close()
                break
            n = client.sendall(donnees)
            client.close()
    finally:
        client.close()


serveur.close()
