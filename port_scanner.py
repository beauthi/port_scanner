"""
Coeur du programme, partie principale permettant d'appeler les autres
composants.

:file port_scanner.py
:author Thibaut PASSILLY
:date 07.10.2020
"""

import sys
from src.dispatcher import launch_processes
from src.logs import set_logging
from src.output import finalize
from src.parsing import parse


def main():
    """
    Fonction principale appelant les autres methodes.

    :param None
    :return Code de retour
        1 = erreur(s)
        0 = succes
    """
    try:
        stdout_handler, output_file_handler = set_logging()
        soft, targets = parse()
        targets_reports = launch_processes(
            soft, targets, stdout_handler, output_file_handler
        )
        finalize(targets_reports)
    except Exception as exception:
        sys.stderr.write(
            "le programme a echoue avec l'erreur suivante : {}\n".format(
                exception
            )
        )
        return 1
    return 0


if __name__ == "__main__":
    return_code = main()
    sys.exit(return_code)
