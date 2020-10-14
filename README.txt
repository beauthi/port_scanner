==========================
Scanner de ports simplifié
==========================

===========
Description
===========

Ce programme permet de scanner les ports d'une ou plusieurs cibles de manière simple et rapide, et de créer un rapport de scan.

===========
Utilisation
===========

Deux types d'utilisation sont permis par l'outil :
python3 port-scanner.py --targets 192.168.0.1 example.com 8.8.8.8
python3 port-scanner.py --file fichier.txt

Le premier cas d'utilisation consiste à fournir comme entrée à l'outil une liste d'une ou plusieurs cibles.
Le second cas d'utilisation consiste à fournir comme entrée à l'outil un chemin vers un fichier contenant une liste d'une ou plusieurs cibles, séparées par des '\n'.

Plus précisément, les options disponibles sont les suivantes :
```
-h, --help                          afficher l'aide
--targets [target [target ...]]     hôte/ipv4/ipv6/cidr
--file filename, -f filename        fichier.txt, hôtes/ipv4/ipv6/cidr séparés par des sauts à la ligne
--soft, -s                          scan léger et rapide, moins précis
```

===========
Déploiement
===========

Avant de faire quoi que ce soit, s'assurer que les versions des OS/paquets sont à jour.
Aussi, il est nécessaire de vérifier que les versions des paquets utilisés (dans requirements.txt) sont à jour.
Pour ce faire, on peut par exemple utiliser safety (pip install safety) pour savoir quels paquets sont potentiellement vulnérables : safety check requirements.txt.

Il est recommandé d'utiliser python3 dans un environnement dédié à l'outil.
Pour pouvoir utiliser ce projet, il faut effectuer les actions suivantes :
* Installer python3.
* Installer python3-venv.
* Créer une virtualenv (python3 -m venv venv) puis l'activer (source venv/bin/activate).
* Installer le gestionnaire de paquets python-pip.
* Installer le paquet python-nmap via pip.
* S'assurer que les éléments dans le fichier config.json (fichier de configuration) vous sont convenables
    - NMAP_BINARY_PATH : chemin absolu vers le binaire nmap que vous souhaitez utiliser
    - OUTPUT_DIRECTORY : chemin relatif vers le dossier de sortie (pour stocker les html)
    - LOGGING_OUTPUT : chemin relatif vers le fichier de logs

=====
Tests
=====

Les fichiers d'input pour les tests se trouvent dans test/.
Vous pouvez rajouter des tests dans le dossier test/, du moment qu'ils suivent la syntaxe des inputs fichier (voir option "-f").
Ils seront testés à la fois comme soft et non-soft.
Ce sont des tests fonctionnels qui permettent de vérifier que certains éléments sont bien présents dans les résultats.

Avant tout cela, assurez-vous que votre daemon docker est apte à gérer ipv6 : https://docs.docker.com/config/daemon/ipv6/.

L'architecture de tests comporte :
    - un serveur web nginx (172.20.128.2, 2001:3200:3200::2) qui écoute sur les ports 80/tcp, 2011/tcp, 1702/udp
    - un serveur de base de donées (172.20.128.3, 2001:3200:3200::3) qui écoute sur les ports 27000/tcp, 27001/tcp

Pour un soft scan on doit retrouver :
    - 172.20.128.2, 2001:3200:3200::2 : 80/tcp
    - 172.20.128.3, 2001:3200:3200::3 : aucun
Pour un hard scan, on doit retrouver tous les ports tcp/udp.

En ce qui concerne scanme.nmap.org, étant donné que l'on n'est pas maître du serveur, on ne peut pas prévoir quels seront les services qui
tournent dessus. Cependant, il y a normalement plusieurs services.

Pour lancer les tests :
$ cd test && docker-compose up
$ cd ../ && docker build -f test/Dockerfile . -t debian_test
$ docker run --name test_host_local_ipv4 --net=test_static-network -e TEST_SET=ipv4_test debian_test
$ docker run --name test_host_local_ipv6 --net=test_static-network-ipv6 -e TEST_SET=ipv6_test debian_test
$ docker run --name internet_test -e TEST_SET=internet_test debian_test
