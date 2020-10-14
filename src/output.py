"""
Classe et fonctions specifiques aux sorties du programme : console, html.

:file output.py
:author Thibaut PASSILLY
:date 07.10.2020
"""

import logging
import os
import time
from .config import config_dict
from jinja2 import Environment, PackageLoader


class Output:
    """
    Gestion des sorties (ecritures) de l'application

    :class Output
    """

    def __init__(self, targets_reports):
        """
        Initialisation des objets de type Output.

        :param self: reference vers l'objet Output parent
        :param targets_reports: liste de rapports sur chaque cible scannee
        :return None
        """
        logging.info("ecriture des resultats")
        self.time = time.time()
        self.targets_reports = targets_reports
        self.set_output_directory()

    def set_output_directory(self):
        """
        Configuration et creation du dossier de sortie.

        :param self: reference vers l'objet Output parent
        :return None
        """
        # creation du dossier de sortie d'apres les donnees de configuration
        if not os.path.exists(config_dict["OUTPUT_DIRECTORY"]):
            os.mkdir(config_dict["OUTPUT_DIRECTORY"])
        self.output_filename = self.targets_reports["summary"]["filename"]

    def print_results(self):
        """
        Affichage d'un resume des resultats dans les logs.

        :param self: reference vers l'objet Output parent
        :return None
        """
        logging.info("BILAN DU SCAN")
        # Les donnees affichees ici sont issues des informations
        # recuperees lors des scans dans le fichier src/dispatcher.py
        logging.info(
            "Nombre de machines scannees : {}".format(
                self.targets_reports["summary"]["totalhosts"]
            )
        )
        logging.info(
            "Machines detectees en ligne : {}".format(
                self.targets_reports["summary"]["uphosts"]
            )
        )
        logging.info(
            "Temps de scan : {} secondes".format(
                self.targets_reports["summary"]["scan_time"]
            )
        )

    def output_html(self):
        """
        Ecriture des resultats dans le template html.

        :param self: reference vers l'objet Output parent
        :return None
        """
        # recuperation d'un environnement de templating Jinja
        environment = Environment(
            loader=PackageLoader("static"), autoescape=True
        )
        template = environment.get_template("template.html")
        filename = os.path.join(
            config_dict["OUTPUT_DIRECTORY"],
            "{}.html".format(self.output_filename),
        )
        # ecriture des resultats
        with open(filename, "w") as html_file:
            html_file.write(
                template.render(targets_reports=self.targets_reports)
            )
        logging.info(
            "Le resultat a ete sauvegarde dans le fichier {}".format(filename)
        )


def finalize(targets_reports):
    """
    Finalisation du programme : ecriture des elements de sortie.
    Fonction d'appel de la classe Output.

    :param targets_reports: liste de rapports sur les scans de cibles
    :return None
    """
    output = Output(targets_reports=targets_reports)
    output.output_html()
    output.print_results()
