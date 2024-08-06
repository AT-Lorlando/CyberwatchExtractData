import database as database
from utils import print_progress_bar
from models import Cve, Package, Server, Update, Correctif, SecurityIssue
import concurrent.futures
from typing import Dict, List, Tuple, Any
from logger import setup_logger

logger = setup_logger(__name__)


def get_cves_data_for_group(
    group_id: int,
    days: int = 0,
    capec_data: Dict = {},
    cwes_data: Dict = {},
    environmental_configuration: Dict = {},
    configuration_cyberwatch: Dict = {},
) -> Tuple[List[Server], str]:
    """
    Retrieves CVEs data for a specific group.

    Args:
        group_id (int): The ID of the group.
        days (int, optional): The number of days to consider for the data retrieval. Defaults to 0.
        capec_data (Dict, optional): The CAPEC data. Defaults to an empty dictionary.
        cwes_data (Dict, optional): The CWEs data. Defaults to an empty dictionary.
        environmental_configuration (Dict, optional): The environmental configuration data. Defaults to an empty dictionary.
        configuration_cyberwatch (Dict, optional): The Cyberwatch configuration data. Defaults to an empty dictionary.

    Returns:
        Tuple[List[Server], str]: A tuple containing a list of servers and the group name.

    """
    logger.info("Asking politely the database...")

    with database.get_db_connection(configuration_cyberwatch) as connection:
        servers_data = database.fetch_servers_for_group(connection, group_id)
        group_name = database.get_group_name(connection, group_id)["name"]

    logger.info(f"Group {group_name} has {len(servers_data)} servers")

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(
                process_server,
                server,
                group_id,
                capec_data,
                cwes_data,
                environmental_configuration,
                configuration_cyberwatch,
                days,
            )
            for server in servers_data
        ]
        results = [
            future.result() for future in concurrent.futures.as_completed(futures)
        ]

    logger.info(f"All servers in group {group_name} have been processed.")
    return results, group_name


def process_server(
    server_data: Dict,
    group_id: int,
    capec_data: Dict,
    cwes_data: Dict,
    environmental_configuration: Dict,
    configuration_cyberwatch: Dict,
    days: int,
) -> Server:
    """
    Process server data and return a Server object.

    Args:
        server_data (Dict): The server data.
        group_id (int): The group ID.
        capec_data (Dict): The CAPEC data.
        cwes_data (Dict): The CWEs data.
        environmental_configuration (Dict): The environmental configuration.
        configuration_cyberwatch (Dict): The Cyberwatch configuration.
        days (int): The number of days.

    Returns:
        Server: The processed Server object.
    """
    with database.get_db_connection(configuration_cyberwatch) as connection:
        logger.info(f"Processing server: {server_data['host']}")
        server = initialize_server(server_data, environmental_configuration)
        server_packages = database.fetch_packages_for_server(connection, server.id)
        cve_announcements = database.fetch_cve_for_server(
            connection, server.id, days=days
        )
        server_updates = database.fetch_server_updates_for_cve(connection, server.id)
        server_current_affected_packages = (
            database.fetch_current_affected_packages_for_server(connection, server.id)
        )
        server_target_affected_packages = (
            database.fetch_target_affected_packages_for_server(connection, server.id)
        )
        server_security_issues = database.fetch_security_issues_for_server(
            connection, server.id
        )

        process_packages(
            server,
            server_packages,
            server_current_affected_packages,
            server_target_affected_packages,
        )
        process_security_issues(server, server_security_issues)
        process_updates(server, server_updates)
        process_cve_announcements(server, cve_announcements, cwes_data, capec_data)

        logger.info(
            f"\n{server.hostname} got {len(server.cves)} cve->affected packages for {len(server_packages)} packages"
        )
        return server


def initialize_server(server_data: Dict, environmental_configuration: Dict) -> Server:
    """
    Initializes a server object with the given server data and environmental configuration.

    Args:
        server_data (Dict): A dictionary containing server data.
        environmental_configuration (Dict): A dictionary containing environmental configuration.

    Returns:
        Server: The initialized server object.
    """
    server_os = (
        {
            "id": server_data.get("os_id"),
            "name": server_data.get("os_name"),
            "key": server_data.get("os_key"),
            "arch": server_data.get("os_arch"),
        }
        if server_data.get("os_id")
        else None
    )

    return Server(
        server_data["id"],
        server_data["host"],
        server_os,
        environmental_configuration,
    )


def process_packages(
    server: Server,
    server_packages: List[Dict],
    server_current_affected_packages: List[Dict],
    server_target_affected_packages: List[Dict],
) -> None:
    """
    Process the packages for the server.

    Args:
        server (Server): The server object.
        server_packages (List[Dict]): The list of server packages.
        server_current_affected_packages (List[Dict]): The list of current affected packages.
        server_target_affected_packages (List[Dict]): The list of target affected packages.

    Returns:
        None
    """
    for package in server_packages:
        server.packages[package["id"]] = Package(package)

    for affected_package in server_current_affected_packages:
        update_server_packages(server, affected_package)

    for affected_package in server_target_affected_packages:
        p = Package(affected_package)
        if p.type == "Packages::Kb":
            server.packages[p.id] = p
        server.affected_packages[p.id] = p


def update_server_packages(server: Server, affected_package: Dict) -> None:
    """
    Update the server packages based on the affected package.

    Args:
        server (Server): The server object to update.
        affected_package (Dict): The affected package information.

    Returns:
        None
    """
    if server.packages.get(affected_package["id"]):
        server.affected_packages[affected_package["id"]] = server.packages.get(
            affected_package["id"]
        )
    else:
        p = Package(affected_package)
        for id in server.packages.copy():
            serv_pkg = server.packages[id]
            if p.product in serv_pkg.product or serv_pkg.product in p.product:
                server.packages.pop(id)
                server.packages[p.id] = p
        if p.type == "Packages::Kb":
            server.packages[p.id] = p
        server.affected_packages[p.id] = p


def process_security_issues(server: Server, server_security_issues: List[Dict]) -> None:
    """
    Process the security issues for a server.

    Args:
        server (Server): The server object.
        server_security_issues (List[Dict]): A list of dictionaries representing the security issues.

    Returns:
        None
    """
    for security_issue in server_security_issues:
        server.security_issues[security_issue.get("id")] = SecurityIssue(security_issue)


def process_updates(server: Server, server_updates: List[Dict]) -> None:
    """
    Process the updates for a server.

    Args:
        server (Server): The server object.
        server_updates (List[Dict]): The list of server updates.

    Returns:
        None
    """
    for update in server_updates:
        p_current = server.affected_packages.get(update["current_id"])
        p_target = server.affected_packages.get(update["target_id"])
        _id = p_current.id if p_current else p_target.id
        if not server.updates.get(f"{update['id']}:{update['server_cve_id']}"):
            server.updates[f"{update['id']}:{update['server_cve_id']}"] = Update(
                update, p_current, p_target
            )
        if not server.correctifs.get(_id):
            server.correctifs[_id] = Correctif(p_current, p_target)
        server.correctifs[_id].add_cve(update["cve_code"])


def process_cve_announcements(
    server: Server, cve_announcements: List[Dict], cwes_data: Dict, capec_data: Dict
) -> None:
    """
    Process the CVE announcements for a given server.

    Args:
        server (Server): The server object.
        cve_announcements (List[Dict]): A list of dictionaries representing the CVE announcements.
        cwes_data (Dict): A dictionary containing CWEs data.
        capec_data (Dict): A dictionary containing CAPEC data.

    Returns:
        None
    """
    for cve_announcement in cve_announcements:
        print_progress_bar(
            cve_announcements.index(cve_announcement),
            len(cve_announcements),
            prefix="Processing CVE Announcements",
            suffix=f"Server {server.hostname}",
            length=50,
        )
        if (
            cve_announcement["content"]
            and "DO NOT USE THIS CANDIDATE NUMBER" in cve_announcement["content"]
        ):
            logger.info(
                f"\n{cve_announcement['cve_code']} is rejected.\n{cve_announcement['content']}"
            )
            continue

        cve_announcement_cves = get_cves_from_announcement(cve_announcement, server)
        for cve in cve_announcement_cves:
            try:
                cve.populate_cwes_data(cwes_data, capec_data)
            except Exception as e:
                logger.error(
                    f"\nError during populate_cwes_data of CVE {cve.cve_code} for server {server.hostname}\n",
                    exc_info=True,
                )
                logger.info(cve)
            try:
                cve.populate_environmental_vector(server)
            except Exception as e:
                logger.error(
                    f"\nError during populate_environmental_vector of CVE {cve.cve_code} for server {server.hostname}: {e}\n",
                    exc_info=True,
                )
                logger.info(cve)
            try:
                cve.compute()
            except Exception as e:
                logger.error(
                    f"\nError during computing of CVE {cve.cve_code} for server {server.hostname}: {e}\n",
                    exc_info=True,
                )
                logger.info(cve)
            finally:
                server.cves[cve.id] = cve


def get_cves_from_announcement(cve_announcement: Dict, server: Server) -> List[Cve]:
    """
    Retrieves a list of CVEs (Common Vulnerabilities and Exposures) from a given announcement.

    Args:
        cve_announcement (Dict): A dictionary containing information about the announcement.
        server (Server): An instance of the Server class.

    Returns:
        List[Cve]: A list of Cve objects representing the retrieved CVEs.

    Raises:
        Exception: If an error occurs during the retrieval process.
    """
    cve_announcement_cves = []
    try:
        for server_update in server.updates:
            if (
                str(server.updates[server_update].server_cve_id)
                == cve_announcement["server_cve_id"]
            ):
                target_id = server.updates[server_update].target_id
                current_id = server.updates[server_update].current_id
                target = server.affected_packages[target_id]
                if (
                    not current_id
                    and server.affected_packages[target_id].type == "Packages::Kb"
                ):
                    current_id = target_id
                current = server.affected_packages[current_id]
                cve_announcement_cves.append(
                    Cve(
                        f"{cve_announcement['cve_code']}:{current.id}",
                        cve_announcement,
                        server.updates[server_update],
                        server,
                    )
                )
        return cve_announcement_cves
    except Exception as e:
        raise Exception(f"Error in get_cves_from_announcement: {e}")
