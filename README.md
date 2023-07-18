# IDS Projet Dev 2020-2021

Membres:

* Deleuze Romain

Compilation:

```bash
gcc -o ids main.c populate.c rule.c -lpcap
```

Exécution

```bash
sudo ./ids ids.rules (ou autre fichier de règles peut importe le nom)
```

Versions:

* 0.1

  1. Lire les règles de base et les appliquer
  2. Vérifier l'encryption des paquets
  3. Utilisation de argv pour récupérer le fichier de règles
  4. Gestion de TCP/UDP/HTTP

* 0.2

  1. Ajout du FTP
  2. Faire tourner l'application en tache de fond
  3. Détecter les attaques XSS
