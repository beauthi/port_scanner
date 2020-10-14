"""
Repartition des taches a effectuer de maniere a optimiser l'efficacite.

:file dispatcher.py
:author Thibaut PASSILLY
:date 07.10.2020
"""

import datetime
import ipaddress
import logging
import multiprocessing
import nmap
import socket
import time
from .config import config_dict
from .logs import multiprocessing_logger_init, worker_init


def run_request(args):
    """
    Lancement d'une requete nmap.

    :param args: tuple contenant les metadonnees concernant le scan et la liste
                 des rapports de scan partagee entre les processus.
    :return None (les resultats sont stockes dans targets_reports_list)
    """
    metadata, targets_reports_list = args

    name = multiprocessing.current_process().name

    # PortScanner est la classe de la bibliotheque nmap permettant
    # de scanner des cibles. Ici, on choisit de chercher le binaire
    # nmap uniquement a l'endroit precise dans la configuration, pour
    # des raisons de securite.
    port_scanner = nmap.PortScanner(
        nmap_search_path=(config_dict["NMAP_BINARY_PATH"],)
    )

    logger = logging.getLogger()
    logger.info(
        "lancement du process pour (nom={}, ip/host={}, transport={},"
        "ports={})".format(
            name,
            metadata["ip_host"],
            metadata["transport_protocol"],
            metadata["port_range"],
        )
    )

    # option concernant le protocole utilise pour la couche transport
    # -sTV : scan des services TCP et de leurs versions
    # -sUV : scan des services UDP et de leurs versions
    transport_option = "-s{}V".format(metadata["transport_protocol"])

    # option concernant le protocole IP, notamment la version
    if metadata["target_type"] in (4, 6):
        ip_option = "-{}".format(metadata["target_type"])
    else:
        ip_option = ""

    arguments = "{} {}".format(transport_option, ip_option)
    # si port_range est a nul, cela signifie que c'est un scan soft.
    # ainsi, on met le temps a la vitesse 4, la vitesse 5 faisant
    # souvent abstraction des services...
    if metadata["port_range"] is None:
        arguments += " -T4"

    target_report = port_scanner.scan(
        hosts=metadata["ip_host"],
        ports=metadata["port_range"],
        arguments=arguments,
        # l'option "sudo" est requise pour obtenir les adresses MAC
        sudo=True,
    )
    if target_report is not None:
        target_report["metadata"] = metadata
        targets_reports_list.append(target_report)
    logger.info(
        "le scan {} est termine (cible = {})".format(name, metadata["target"])
    )


class NmapScan:
    """
    Cette classe rassemble les methodes utiles pour le scan de ports via nmap.
    """

    def __init__(
        self,
        targets,
        queue,
        soft=False,
        port_steps=1000,
        max_port=65535,
        transport_protocols=["T", "U"],
    ):
        """
        Methode permettant d'initialiser les attributs de la classe NmapScan.

        :param self : reference vers l'objet NmapScan parent.
        :param targets : liste de cibles a scanner : ipv4/ipv6/cidr/host
        :param queue : file de messages pour les logs
        :param soft : booleen indiquant le type de scan a effectuer
        :port_steps : intervalle de ports utilise pour la parallelisation.
        :param max_port : numero de port maximal a scanner
        :param transport_protocols : protocoles de transport disponibles
        :return None
        """
        self.targets = targets
        self.queue = queue
        self.soft = soft
        self.port_steps = port_steps
        self.max_port = max_port
        self.transport_protocols = transport_protocols

        # La classe Manager de la bibliotheque de multiprocessing
        # permet de creer des classes qui sont utilisables au sein de
        # plusieurs processus. Cela permet d'eviter de gerer les
        # locks et autres soucis lies au multiprocessing.
        self.manager = multiprocessing.Manager()
        # liste de rapports de scan partagee entre les processus
        self.targets_reports_list = self.manager.list()
        # dictionnaire des listes d'IP/hosts et leurs versions
        # (IPv4, IPv6) lies a une cible
        self.ip_host_list = {}

    def build_targets_reports(self):
        """
        Creation du dictionnaire de resultats, simple a manipuler.

        :param self : reference vers l'objet NmapScan parent.
        :return dictionnaire de resultats
        """
        # targets_reports est la variable contenant le dictionnaire final
        # il est organise de la facon suivante :
        # targets_reports = {
        #   "summary": {
        #   }
        #   "reports": {
        #       "192.168.0.0/24": {
        #           "report": {
        #               "192.168.0.1": {
        #                   "type": 4,
        #                   "mac": "ab:cd:ef:01:23:45",
        #                   ...
        #               },
        #               "192.168.0.2": {
        #               },
        #               ...
        #           }
        #       }
        #   }
        # }
        targets_reports = {}
        targets_reports["reports"] = {}
        # summary_stats est une variable temporaire permettant de stocker
        # des informations globales sur le scan. Les donnees seront stockees
        # dans targets_reports["summary"].
        summary_stats = {
            "totalhosts": 0,
            "uphosts": 0,
        }

        for target in self.targets:
            targets_reports["reports"][target] = {}
            targets_reports["reports"][target]["report"] = {}

            # la liste d'ip/host courante contient uniquement les
            # cibles qui ont ete scannees comme "up".
            # la transformation en set permet de supprimer les doublons.
            # les ip/host sont testes un par un, il ne peut donc y avoir
            # qu'une seul ip dans la case "scan" logiquement.
            current_ip_host_list = set(
                [
                    r["metadata"]["ip_host"]
                    for r in self.targets_reports_list
                    if r["metadata"]["target"] == target
                    and r["nmap"]["scanstats"]["uphosts"] != "0"
                ]
            )

            # le summary d'une cible contient quelques informations
            # telles que le nombre de machines scannees, le nombre
            # de machines en marche.
            targets_reports["reports"][target]["summary"] = {
                "totalhosts": len(
                    set(
                        [
                            r["metadata"]["ip_host"]
                            for r in self.targets_reports_list
                            if r["metadata"]["target"] == target
                        ]
                    )
                ),
                "uphosts": len(current_ip_host_list),
            }

            # ajout aux summary_stats des donnees courantes concernant le
            # nombre total de machines scannees et le nombre de machines
            # en marche.
            summary_stats["totalhosts"] += targets_reports["reports"][target][
                "summary"
            ]["totalhosts"]
            summary_stats["uphosts"] += targets_reports["reports"][target][
                "summary"
            ]["uphosts"]

            for ip_host in current_ip_host_list:
                # pour chaque IP faisant partie d'une target
                # (ipv4, ipv6, cidr...), on va stocker les
                # informations dont on a besoin, c'est-a-dire
                # le type d'IP (v4 ou v6), l'adresse MAC,
                # les noms d'hotes, les ports ouverts, et les
                # eventuelles erreurs rencontrees lors du scan.
                targets_reports["reports"][target]["report"][ip_host] = {
                    "type": self.ip_host_list[target]["type"],
                    "mac": None,
                    "hostnames": [],
                    "ports": {},
                    "errors": [],
                }

                # on avance dans les couches superieures, et on
                # stocke alors, pour les protocoles TCP et UDP,
                # les services ouverts et leurs versions.
                for transport_protocol in self.transport_protocols:
                    targets_reports["reports"][target]["report"][ip_host][
                        "ports"
                    ][transport_protocol] = {}

                    # selection des rapports concernes
                    # pour qu'un rapport soit "concerne", il
                    # faut qu'il concerne la target que l'on cherche,
                    # l'IP/host que l'on cherche, et le protocole
                    # de transport que l'on cherche.
                    # on cherche ces elements dans la liste
                    # targets_reports_list, qui contient tous les
                    # resultats de nos scans.
                    selected_rep = [
                        r
                        for r in self.targets_reports_list
                        if (
                            r["metadata"]["target"] == target
                            and r["metadata"]["ip_host"] == ip_host
                            and r["metadata"]["transport_protocol"]
                            == transport_protocol
                        )
                    ]
                    for report in selected_rep:
                        # cette condition en trois temps
                        # permet simplement de stocker
                        # la cle ("tcp" ou "udp") au lieu d'avoir
                        # a ecrire var["tcp"] or var["udp"] a
                        # chaque condition.
                        if "tcp" in report["scan"][ip_host]:
                            transport_key = "tcp"
                        elif "udp" in report["scan"][ip_host]:
                            transport_key = "udp"
                        else:
                            continue

                        # stockage des erreurs et des avertissements
                        # dans les metadonnees liees a la cible courante.
                        if "error" in report["nmap"]["scaninfo"]:
                            targets_reports["reports"][target]["report"][
                                ip_host
                            ]["errors"].append(
                                report["nmap"]["scaninfo"]["error"]
                            )
                        if "warning" in report["nmap"]["scaninfo"]:
                            targets_reports["reports"][target]["report"][
                                ip_host
                            ]["errors"].append(
                                report["nmap"]["scaninfo"]["warning"]
                            )

                        # stockage des informations concernant les ports TCP
                        # et UDP
                        targets_reports["reports"][target]["report"][ip_host][
                            "ports"
                        ][transport_protocol].update(
                            report["scan"][ip_host][transport_key]
                        )

                        # stockage de l'adresse MAC si elle est presente
                        if "mac" in report["scan"][ip_host]["addresses"]:
                            targets_reports["reports"][target]["report"][
                                ip_host
                            ]["mac"] = report["scan"][ip_host]["addresses"][
                                "mac"
                            ]

                        # stockage des eventuels noms d'hote
                        for hostname in report["scan"][ip_host]["hostnames"]:
                            if (
                                hostname
                                not in targets_reports["reports"][target][
                                    "report"
                                ][ip_host]["hostnames"]
                            ):
                                targets_reports["reports"][target]["report"][
                                    ip_host
                                ]["hostnames"].append(hostname["name"])
        # recuperation de la date actuelle
        now = time.time()

        # stockage des informations recoltees lors des boucles
        # precedentes dans le summary de l'analyse.
        targets_reports["summary"] = {
            # filename correspond au nom de fichier de sortie
            "filename": datetime.datetime.fromtimestamp(now).strftime(
                "%Y_%m_%d_%H_%M_%S"
            ),
            "soft": self.soft,
            # date
            "timestr": datetime.datetime.fromtimestamp(now).strftime(
                "%d/%m/%Y %H:%M:%S"
            ),
            # temps de scan
            "scan_time": self.scan_time,
            # machines en marche
            "uphosts": summary_stats["uphosts"],
            # nombre de machines scannees
            "totalhosts": summary_stats["totalhosts"],
        }
        return targets_reports

    def process(self):
        """
        Creation des sets de donnees a fournir au multi-processing
        et demarrage de celui-ci.

        :param self : reference vers l'objet NmapScan parent.
        :return None
        """
        # lancement du chronometre
        scan_start_time = time.time()

        # args est une liste contenant, pour chaque processus
        # qui sera lance en parallele, un tuple d'arguments
        # a envoyer a la fonction de requetage nmap, run_request.
        # ce format est impose par la fonctionnalite de mapping
        # (map et map_async dans notre cas) des Pools de la
        # bibliotheque multiprocessing.
        args = []
        for target in self.targets:
            # pour chaque cible, on recupere le type de donnees
            # qu'est la cible : une IPv4, une IPv6, ou un hostname.
            ip_host_list, target_type = self.get_ip_type(target)
            # on stocke le resutat dans un dictionnaire
            self.ip_host_list[target] = {
                "list": ip_host_list,
                "type": target_type,
            }
            for ip_host in ip_host_list:
                # Dans le cas d'un scan "soft", seuls les ports
                # TCP seront testes, ainsi que les ports les plus
                # connus (well-known ports).
                if self.soft:
                    metadata = {
                        "target": target,
                        "target_type": target_type,
                        "ip_host": ip_host,
                        "transport_protocol": "T",
                        "port_range": None,
                    }
                    args.append(
                        (
                            metadata,
                            self.targets_reports_list,
                        )
                    )
                else:
                    for transport_protocol in self.transport_protocols:
                        # creation des intervalles de ports dont
                        # le scan est a paralleliser
                        ports_ranges = list(
                            range(0, self.max_port + 1, self.port_steps)
                        )

                        # si le dernier port n'est pas dans la liste,
                        # c'est que les intervalles ne tombent pas
                        # "pile" sur le dernier numero de port, on
                        # le rajoute donc "a la main".
                        if ports_ranges[-1] != self.max_port:
                            ports_ranges.append(self.max_port)
                        for index in range(1, len(ports_ranges)):
                            min_port = ports_ranges[index - 1]
                            max_port = ports_ranges[index]
                            port_range = "{}-{}".format(min_port, max_port)
                            # creation du dictionnaire de metadonnees pour
                            # l'appel a la fonction de requetage
                            metadata = {
                                "target": target,
                                "target_type": target_type,
                                "ip_host": ip_host,
                                "transport_protocol": transport_protocol,
                                "port_range": port_range,
                            }
                            # ajout dans la liste de tuples d'arguments
                            args.append(
                                (
                                    metadata,
                                    self.targets_reports_list,
                                )
                            )
        # s'il n'y a aucun argument, alors on peut quitter cette fonction
        # puisque cela signifie que l'on n'a pas d'appel a faire a la
        # fonction de requetage.
        if len(args) == 0:
            return
        # Pool est une classe issue de la bibliotheque multiprocessing
        # permettant de creer des groupes d'appels a une fonction qui
        # vont etre automatiquement schedules pour etre executes.
        # Pool detecte automatiquement le nombre maximal de CPU utilisables,
        # et donc le nombre maximal de processus que l'on peut paralleliser.
        # c'est pourquoi il n'est pas utile de le preciser.
        pool = multiprocessing.Pool(
            initializer=worker_init, initargs=[self.queue]
        )
        # la fonction map asynchrone permet, par rapport a la
        # fonction map de continuer l'execution du programme principal
        # parallelement au pool de processus.
        result = pool.map_async(run_request, args)
        # Ainsi, on peut effectuer des actions en parallele, comme
        # par exemple afficher des messages sur la progression du
        # scan, comme ci-dessous.
        total_processes = len(args)

        # Tant que le resultat n'est pas pret, c'est-a-dire
        # tant que le pool n'a pas fini
        while not result.ready():
            # on compte les processus du pool qui sont termines
            done = len(self.targets_reports_list)

            # calcul de la difference de temps entre le debut du scan
            # et le moment courant
            now = time.time()
            progress_percentage = (done / total_processes) * 100
            time_delta = str(datetime.timedelta(seconds=now - scan_start_time))

            logging.info(
                "progression du scan : {:.1f}%, temps ecoule : {}".format(
                    progress_percentage, time_delta
                )
            )
            time.sleep(10)
        pool.close()
        # Pour pas que les processus ne quittent avant la fonction principale
        pool.join()

        # calcul de la duree du scan
        now = time.time()
        time_delta = str(datetime.timedelta(seconds=now - scan_start_time))
        logging.info(
            "progression du scan : 100%, temps ecoule : {}".format(time_delta)
        )
        self.scan_time = time_delta

    def get_ip_type(self, target):
        """
        Pour une cible donnee, recuperation de la liste d'IP que l'on va
        devoir scanner.

        :param target : cible (ipv4, ipv6, cidr, host...)
        :return tuple IP/Hote, type (ipv4, ipv6 ou 0 pour un nom d'hote)
        """
        try:
            # recuperation des adresses, tres utile pour les CIDR.
            # l'option strict=False permet d'autoriser des entrees comme
            # 192.168.1.1/24, le dernier "1" etant illegitime dans
            # une representation reseau classique, mais autorise avec nmap.
            ip_addresses = ipaddress.ip_network(address=target, strict=False)
        except ValueError:
            # si cela echoue, c'est que la string ne correspond
            # ni a une IPv4 ni a une IPV6.
            # 0 correspond a un hostname, on recupere alors son IP
            corresponding_ip = socket.gethostbyname(target)
            return self.get_ip_type(corresponding_ip)
        ip_host_list = [str(ip) for ip in ip_addresses]
        host_type = ip_addresses.version
        return ip_host_list, host_type


def launch_processes(soft, targets, stdout_handler, output_file_handler):
    """
    Lancement des processus pour scanner les cibles.

    :param soft : booleen indiquant le type de scan (soft ou non)
    :param targets : liste de cibles [list(str)]
    :param stdout_handler : reference vers la sortie standard des logs
    :param output_file_handler : reference vers la sortie des logs dans un
                                 fichier
    :return liste de rapports sur chaque cible
    """
    if len(targets) == 0:
        return {}

    # initialisation de la file et du listener pour gerer les logs
    # multi-process.
    queue_listener, queue = multiprocessing_logger_init(
        stream_handler=stdout_handler, file_handler=output_file_handler
    )
    scan = NmapScan(targets=targets, queue=queue, soft=soft)
    # lancement du scan
    scan.process()
    # creation du dictionnaire de sortie
    targets_reports = scan.build_targets_reports()

    queue_listener.stop()
    logging.info("scans effectues avec succes")
    return targets_reports
