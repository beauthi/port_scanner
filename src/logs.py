"""
Gestion de la journalisation.

:file logs.py
:author Thibaut PASSILLY
:date 11.10.2020
"""

import logging
import multiprocessing
import sys
from .config import config_dict
from logging.handlers import QueueHandler, QueueListener


def set_logging():
    """
    Mise en place de la journalisation :
    celle-ci sera faite a la fois sur la sortie standard et dans un fichier
    dont le nom est configure dans config.py

    :param None
    :return handler sur la sortie, handler sur le fichier de logs
    """
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    output_file_handler = logging.FileHandler(config_dict["LOGGING_OUTPUT"])
    stdout_handler = logging.StreamHandler(sys.stdout)

    # Un format special est utilise pour avoir plus de lisibilite
    formatter = logging.Formatter("[%(asctime)s][%(levelname)s] %(message)s")
    stdout_handler.setFormatter(formatter)
    output_file_handler.setFormatter(formatter)

    logger.addHandler(output_file_handler)
    logger.addHandler(stdout_handler)

    logging.info("initialisation du logger effectuee")

    # les handlers sur la sortie et sur le fichier de logs sont
    # utiles pour la suite, notamment le multiprocessing, afin de
    # relier la file de messages a ces handlers.
    return stdout_handler, output_file_handler


def worker_init(queue):
    """
    Initialisation du worker: file d'attente pour stocker
    les logs a afficher dans le cadre du multiprocessing.

    :param queue : file d'attente sur laquelle on va placer le handler
    :return None
    """
    queue_handler = QueueHandler(queue)
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.addHandler(queue_handler)


def multiprocessing_logger_init(stream_handler, file_handler):
    """
    Initialisation du logging pour le multiprocessing.

    :param stream_handler : handler vers stdout
    :param file_handler : handler vers le fichier de logs
    :return le processus d'ecoute des messages entrants et la file
            d'attente des messages.
    """
    queue = multiprocessing.Queue()
    queue_listener = QueueListener(queue, stream_handler, file_handler)
    queue_listener.start()
    return queue_listener, queue
