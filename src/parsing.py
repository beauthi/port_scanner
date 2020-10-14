"""
Recuperation des arguments du programme et pre-traitement.

:file parsing.py
:author Thibaut PASSILLY
:date 07.10.2020
"""

import argparse
import logging


def parse_file(filename):
    """
    Parsing d'un argument de type fichier, et recuperation du contenu du
    fichier en question.

    :param filename: nom du fichier
    :return contenu du fichier sous forme de liste de cibles (list(str))
    """
    logging.info(
        "Recuperation des donnees d'entrees"
        " dans le fichier {}".format(filename)
    )
    # ouverture du fichier
    file_object = open(file=filename, mode="r")
    # lecture
    content = file_object.read()
    # separation du contenu du fichier en differents tokens:
    # IPv4, IPv6, cidr, hosts...
    splitted_content = content.split("\n")
    return splitted_content


def parse_args():
    """
    Recuperation des arguments via argparse.ArgumentParser.

    :param None
    :return None
    """
    # Utilisation de la bibliotheque argparse, qui permet
    # de simplifier le parsing des arguments.
    logging.info("parsing des arguments de la ligne de commande")
    parser = argparse.ArgumentParser(description="Scanner de ports simplifie")

    # on ne peut pas utiliser a la fois l'option -t (targets : ip/host/cidr...)
    # et l'option -f (fichier contenant des targets)
    # les deux parametres seront donc mutuellement exclusifs.
    args_group = parser.add_mutually_exclusive_group(required=True)
    args_group.add_argument(
        "--targets",
        "-t",
        metavar="target",
        nargs="*",
        help="hote/ipv4/ipv6/cidr",
    )
    args_group.add_argument(
        "--file",
        "-f",
        metavar="filename",
        help="fichier.txt, hotes/ipv4/ipv6/cidr "
        "separes par des sauts a la ligne",
    )

    # cette option permet d'ordonner a nmap de faire un scan plus rapide mais
    # avec beaucoup moins de details
    parser.add_argument(
        "--soft",
        "-s",
        action="store_true",
        help="scan leger et rapide, moins precis",
    )

    return parser.parse_args()


def parse():
    """
    Fonction de wrapping permettant d'appeler les fonctions de recuperation
    des arguments.

    :param None
    :return tuple : booleen indiquant le type de scan,
            liste de cibles a scanner (list(str))
    """
    args_namespace = parse_args()
    if args_namespace.file is not None:
        logging.info(
            "argument de type fichier : {}".format(args_namespace.file)
        )
        targets = parse_file(args_namespace.file)
        # suppression des lignes vides
        targets = [t for t in targets if t != ""]
    else:
        logging.info(
            "argument de type target : {}".format(args_namespace.targets)
        )
        targets = args_namespace.targets

    if args_namespace.soft:
        logging.info("le scan sera soft (rapide mais peu detaille)")

    # suppression des doublons
    unique_targets = list(set(targets))
    if len(unique_targets) != len(targets):
        targets = unique_targets
    return args_namespace.soft, targets
