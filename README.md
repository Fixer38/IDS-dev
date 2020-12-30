# IDS Projet Dev 2020-2021

Membres:

* Dinon Jérémie
* Deleuze Romain

Compilation:

```bash
gcc -o ids main.c populate.c -lpcap
```

Exécution

```bash
sudo ./ids
```

Versions:

* 0.1

  1. Lire les règles de base et les appliquer
  2. Vérifier l'encryption des paquets
  3. Utilisation de argv pour récupérer le fichier de règles
  4. Gestion de TCP/UDP/HTTP

* 0.2

  1. Ajout de protocoles supplémentaires
  2. SYN flood
  3. Faire tourner l'application en tache de fond
  4. Détecter attaque XSS
