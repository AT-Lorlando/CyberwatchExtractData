import pymysql
from typing import Dict, List, Any, Optional
from logger import setup_logger

logger = setup_logger(__name__)


def get_db_connection(configuration: Dict[str, str]) -> pymysql.connections.Connection:
    """
    Establishes and returns a connection to the database.

    Args:
        configuration (Dict[str, str]): A dictionary containing database connection parameters
                                        (host, user, password, database).

    Returns:
        pymysql.connections.Connection: The database connection object.

    Raises:
        Exception: If the connection to the database fails, the exception is caught, and the program exits.
    """
    try:
        connection = pymysql.connect(
            host=configuration["host"],
            user=configuration["user"],
            password=configuration["password"],
            database=configuration["database"],
            cursorclass=pymysql.cursors.DictCursor,
        )
        return connection
    except Exception as e:
        logger.error(
            "Error during get_db_connection, please check your credentials",
            exc_info=True,
        )
        exit(1)


def fetch_servers_for_group(
    connection: pymysql.connections.Connection, group_id: int
) -> Optional[List[Dict[str, Any]]]:
    """
    Fetches a list of servers for a specific group.

    Args:
        connection (pymysql.connections.Connection): The database connection object.
        group_id (int): The ID of the group for which to fetch servers.

    Returns:
        Optional[List[Dict[str, Any]]]: A list of dictionaries representing the servers, or None if an error occurs.
    """
    try:
        with connection.cursor() as cursor:
            sql = """
            SELECT servers.*, servers.os_id, os.key AS os_key, os.name AS os_name, os.arch AS os_arch
            FROM servers
            JOIN group_relations ON servers.id = group_relations.relation_id
            LEFT JOIN os ON servers.os_id = os.id
            WHERE group_relations.group_id = %s
            AND group_relations.relation_type = "Server";
            """
            cursor.execute(sql, (group_id,))
            return cursor.fetchall()
    except Exception as e:
        logger.error("Error during fetch_servers_for_group", exc_info=True)
        return None


def fetch_group_for_instance(
    connection: pymysql.connections.Connection,
) -> Optional[List[Dict[str, Any]]]:
    """
    Fetches a list of all groups.

    Args:
        connection (pymysql.connections.Connection): The database connection object.

    Returns:
        Optional[List[Dict[str, Any]]]: A list of dictionaries representing the groups, or None if an error occurs.
    """
    try:
        with connection.cursor() as cursor:
            sql = "SELECT id, name FROM groups;"
            cursor.execute(sql)
            return cursor.fetchall()
    except Exception as e:
        return _fetch_group_for_instance_with_db_specified(connection, e)


def _fetch_group_for_instance_with_db_specified(
    connection: pymysql.connections.Connection, original_exception: Exception
) -> Optional[List[Dict[str, Any]]]:
    """
    Fetches a list of all groups, specifying the database in the query if an error occurs.

    Args:
        connection (pymysql.connections.Connection): The database connection object.
        original_exception (Exception): The original exception that occurred.

    Returns:
        Optional[List[Dict[str, Any]]]: A list of dictionaries representing the groups, or None if an error occurs.
    """
    try:
        logger.error(
            "Error during fetching groups database, trying to specify the database",
        )
        database = connection.db.decode("utf-8")
        with connection.cursor() as cursor:
            sql = f"SELECT id, name FROM {database}.groups;"
            cursor.execute(sql)
            return cursor.fetchall()
    except Exception as e:
        logger.error("Error during fetch_group_for_instance", exc_info=True)
        return None


def get_group_name(
    connection: pymysql.connections.Connection, group_id: int
) -> Optional[Dict[str, Any]]:
    """
    Fetches the name of a group by its ID.

    Args:
        connection (pymysql.connections.Connection): The database connection object.
        group_id (int): The ID of the group to fetch the name for.

    Returns:
        Optional[Dict[str, Any]]: A dictionary representing the group's name, or None if an error occurs.
    """
    try:
        with connection.cursor() as cursor:
            sql = f"SELECT name FROM groups WHERE id = {group_id};"
            cursor.execute(sql)
            return cursor.fetchone()
    except Exception as e:
        return _get_group_name_with_db_specified(connection, group_id, e)


def _get_group_name_with_db_specified(
    connection: pymysql.connections.Connection,
    group_id: int,
    original_exception: Exception,
) -> Optional[Dict[str, Any]]:
    """
    Fetches the name of a group by its ID, specifying the database in the query if an error occurs.

    Args:
        connection (pymysql.connections.Connection): The database connection object.
        group_id (int): The ID of the group to fetch the name for.
        original_exception (Exception): The original exception that occurred.

    Returns:
        Optional[Dict[str, Any]]: A dictionary representing the group's name, or None if an error occurs.
    """
    try:
        logger.error(
            "Error during fetching groups database, trying to specify the database",
        )
        database = connection.db.decode("utf-8")
        with connection.cursor() as cursor:
            sql = f"SELECT name FROM {database}.groups WHERE id = %s"
            cursor.execute(sql, (group_id,))
            return cursor.fetchone()
    except Exception as e:
        logger.error("Error during get_group_name", exc_info=True)
        return None


def fetch_cve_for_server(
    connection: pymysql.connections.Connection,
    server_id: int,
    date_from: str = None,
    date_to: str = None,
) -> Optional[List[Dict[str, Any]]]:
    """
    Fetches a list of CVEs for a specific server.

    Args:
        connection (pymysql.connections.Connection): The database connection object.
        server_id (int): The ID of the server for which to fetch CVEs.
        days (int, optional): The number of days to filter CVEs by. Defaults to 0.

    Returns:
        Optional[List[Dict[str, Any]]]: A list of dictionaries representing the CVEs, or None if an error occurs.
    """
    try:
        with connection.cursor() as cursor:
            sql = _build_cve_query(server_id, days)
            cursor.execute(sql)
            results = cursor.fetchall()
            return _process_cve_results(results)
    except Exception as e:
        logger.error("Error during fetch_cve_for_server", exc_info=True)
        return None


def _build_cve_query(server_id: int, days: int) -> str:
    """
    Builds the SQL query for fetching CVEs for a specific server.

    Args:
        server_id (int): The ID of the server for which to build the query.
        days (int): The number of days to filter CVEs by.

    Returns:
        str: The SQL query string.
    """
    where_clauses = []
    if date_from and date_to:
        where_clauses.append(
            f"(cve_announcements.published_date BETWEEN '{date_from}' AND '{date_to}') OR (cve_announcements.last_modified_date BETWEEN '{date_from}' AND '{date_to}') OR (cve_announcements.published IS NULL AND cve_announcements.updated_at BETWEEN '{date_from}' AND '{date_to}')"
        )
    elif date_from:
        where_clauses.append(
            f"(cve_announcements.published_date >= '{date_from}' OR cve_announcements.last_modified_date >= '{date_from}' OR (cve_announcements.published IS NULL AND cve_announcements.updated_at >= '{date_from}'))"
        )
    elif date_to:
        where_clauses.append(
            f"(cve_announcements.published_date <= '{date_to}' OR cve_announcements.last_modified_date <= '{date_to}' OR (cve_announcements.published IS NULL AND cve_announcements.updated_at <= '{date_to}'))"
        )
    base_query = f"""
    SELECT cve_announcements.*, cvss_v3.*, 
    cvss.access_vector AS cvss_access_vector,
    cvss.access_complexity AS cvss_access_complexity,
    cvss.authentication AS cvss_authentication,
    cvss.confidentiality_impact AS cvss_confidentiality_impact,
    cvss.integrity_impact AS cvss_integrity_impact,
    cvss.availability_impact AS cvss_availability_impact,
    GROUP_CONCAT(DISTINCT server_cves.id SEPARATOR '; ') AS server_cve_ids,
    GROUP_CONCAT(DISTINCT sas_cves.security_announcement_id SEPARATOR '; ') AS security_announcement_ids,
    GROUP_CONCAT(DISTINCT CASE WHEN technologies.product IS NOT NULL THEN CONCAT_WS('|', technologies.product, technologies.vendor) ELSE NULL END SEPARATOR '; ') AS full_technos,
    GROUP_CONCAT(DISTINCT CASE WHEN cve_references.source IS NOT NULL THEN CONCAT_WS('|', cve_references.source, cve_references.code, cve_references.url, cve_references.tags, cve_references.title) ELSE NULL END SEPARATOR '; ') AS full_references
    FROM cve_announcements
    JOIN server_cves ON cve_announcements.id = server_cves.cve_announcement_id
    LEFT JOIN cvss ON cve_announcements.cvss_id = cvss.id
    LEFT JOIN cvss_v3 ON cve_announcements.cvss_v3_id = cvss_v3.id
    LEFT JOIN technos_cves ON cve_announcements.id = technos_cves.cve_announcement_id
    LEFT JOIN technologies ON technos_cves.technology_id = technologies.id
    LEFT JOIN cve_references ON cve_announcements.id = cve_references.cve_announcement_id
    LEFT JOIN sas_cves ON cve_announcements.id = sas_cves.cve_announcement_id
    WHERE server_cves.server_id = {server_id}
    { "AND " + " AND ".join(where_clauses) if where_clauses else "" }
    AND server_cves.active = 1
    """
    return base_query


def _process_cve_results(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Processes the results of a CVE query.

    Args:
        results (List[Dict[str, Any]]): The list of dictionaries representing the CVEs.

    Returns:
        List[Dict[str, Any]]: The processed list of dictionaries representing the CVEs.
    """
    for result in results:
        result["full_technos"] = _split_technos(result.get("full_technos"))
        result["full_references"] = _split_references(result.get("full_references"))
        result["security_announcement_ids"] = _split_ids(
            result.get("security_announcement_ids")
        )
        result["server_cve_ids"] = _split_ids(result.get("server_cve_ids"))
        if result["server_cve_ids"]:
            ids = result["server_cve_ids"]
            result["server_cve_id"] = ids[0]
            for server_cve_id in ids[1:]:
                new_cve = result.copy()
                new_cve["server_cve_id"] = server_cve_id
                results.append(new_cve)
    return results


def _split_technos(full_technos: Optional[str]) -> List[Dict[str, str]]:
    """
    Splits a concatenated string of technologies into a list of dictionaries.

    Args:
        full_technos (Optional[str]): The concatenated string of technologies.

    Returns:
        List[Dict[str, str]]: A list of dictionaries representing the technologies.
    """
    if full_technos:
        return [
            dict(zip(["product", "vendor"], techno.split("|")))
            for techno in full_technos.split("; ")
        ]
    return []


def _split_references(full_references: Optional[str]) -> List[Dict[str, str]]:
    """
    Splits a concatenated string of references into a list of dictionaries.

    Args:
        full_references (Optional[str]): The concatenated string of references.

    Returns:
        List[Dict[str, str]]: A list of dictionaries representing the references.
    """
    if full_references:
        return [
            dict(zip(["source", "code", "url", "tags", "title"], ref.split("|")))
            for ref in full_references.split("; ")
        ]
    return []


def _split_ids(ids: Optional[str]) -> List[str]:
    """
    Splits a concatenated string of IDs into a list of strings.

    Args:
        ids (Optional[str]): The concatenated string of IDs.

    Returns:
        List[str]: A list of strings representing the IDs.
    """
    if ids:
        return ids.split("; ")
    return []


def fetch_server_updates_for_cve(
    connection: pymysql.connections.Connection, server_id: int
) -> Optional[List[Dict[str, Any]]]:
    """
    Fetches a list of server updates for a specific CVE.

    Args:
        connection (pymysql.connections.Connection): The database connection object.
        server_id (int): The ID of the server for which to fetch updates.

    Returns:
        Optional[List[Dict[str, Any]]]: A list of dictionaries representing the server updates, or None if an error occurs.
    """
    try:
        with connection.cursor() as cursor:
            sql = f"""
            SELECT server_updates.*, server_cves.id AS server_cve_id, cve_announcements.cve_code
            FROM server_updates
            JOIN server_cve_server_updates ON server_updates.id = server_cve_server_updates.server_update_id
            JOIN server_cves ON server_cve_server_updates.server_cve_id = server_cves.id
            JOIN cve_announcements ON server_cves.cve_announcement_id = cve_announcements.id
            WHERE server_cves.server_id = {server_id}
            """
            cursor.execute(sql)
            return cursor.fetchall()
    except Exception as e:
        logger.error("Error during fetch_server_updates_for_cve", exc_info=True)
        return None


def fetch_current_affected_packages_for_server(
    connection: pymysql.connections.Connection, server_id: int
) -> Optional[List[Dict[str, Any]]]:
    """
    Fetches a list of currently affected packages for a specific server.

    Args:
        connection (pymysql.connections.Connection): The database connection object.
        server_id (int): The ID of the server for which to fetch affected packages.

    Returns:
        Optional[List[Dict[str, Any]]]: A list of dictionaries representing the affected packages, or None if an error occurs.
    """
    try:
        with connection.cursor() as cursor:
            sql = f"""
            SELECT *
            FROM packages
            WHERE id IN (
                SELECT current_id 
                FROM server_updates 
                JOIN server_cve_server_updates ON server_updates.id = server_cve_server_updates.server_update_id 
                JOIN server_cves ON server_cve_server_updates.server_cve_id = server_cves.id 
                WHERE server_cves.server_id = {server_id}
            )
            """
            cursor.execute(sql)
            return cursor.fetchall()
    except Exception as e:
        logger.error(
            "Error during fetch_current_affected_packages_for_server", exc_info=True
        )
        return None


def fetch_target_affected_packages_for_server(
    connection: pymysql.connections.Connection, server_id: int
) -> Optional[List[Dict[str, Any]]]:
    """
    Fetches a list of target affected packages for a specific server.

    Args:
        connection (pymysql.connections.Connection): The database connection object.
        server_id (int): The ID of the server for which to fetch affected packages.

    Returns:
        Optional[List[Dict[str, Any]]]: A list of dictionaries representing the affected packages, or None if an error occurs.
    """
    try:
        with connection.cursor() as cursor:
            sql = f"""
            SELECT *
            FROM packages
            WHERE id IN (
                SELECT target_id 
                FROM server_updates 
                JOIN server_cve_server_updates ON server_updates.id = server_cve_server_updates.server_update_id 
                JOIN server_cves ON server_cve_server_updates.server_cve_id = server_cves.id 
                WHERE server_cves.server_id = {server_id}
            )
            """
            cursor.execute(sql)
            return cursor.fetchall()
    except Exception as e:
        logger.error(
            "Error during fetch_target_affected_packages_for_server", exc_info=True
        )
        return None


def fetch_security_issues_for_server(
    connection: pymysql.connections.Connection, server_id: int
) -> Optional[List[Dict[str, Any]]]:
    """
    Fetches a list of security issues for a specific server.

    Args:
        connection (pymysql.connections.Connection): The database connection object.
        server_id (int): The ID of the server for which to fetch security issues.

    Returns:
        Optional[List[Dict[str, Any]]]: A list of dictionaries representing the security issues, or None if an error occurs.
    """
    try:
        with connection.cursor() as cursor:
            sql = f"""
            SELECT server_security_issues.id, payload, security_issues.level, security_issues.title
            FROM server_security_issues
            JOIN security_issues ON server_security_issues.security_issue_id = security_issues.id
            WHERE server_security_issues.server_id = {server_id};
            """
            cursor.execute(sql)
            return cursor.fetchall()
    except Exception as e:
        logger.error("Error during fetch_security_issues_for_server", exc_info=True)
        return None


def fetch_packages_for_server(
    connection: pymysql.connections.Connection, server_id: int
) -> Optional[List[Dict[str, Any]]]:
    """
    Fetches a list of packages installed on a specific server.

    Args:
        connection (pymysql.connections.Connection): The database connection object.
        server_id (int): The ID of the server for which to fetch packages.

    Returns:
        Optional[List[Dict[str, Any]]]: A list of dictionaries representing the packages, or None if an error occurs.
    """
    try:
        with connection.cursor() as cursor:
            sql = f"""
            SELECT packages.*
            FROM packages
            JOIN server_packages ON packages.id = server_packages.package_id
            WHERE server_packages.server_id = {server_id};
            """
            cursor.execute(sql)
            return cursor.fetchall()
    except Exception as e:
        logger.error("Error during fetch_packages_for_server", exc_info=True)
        return None


def list_group(configuration: Dict[str, str]) -> None:
    """
    Lists all groups from the database.

    Args:
        configuration (Dict[str, str]): A dictionary containing database connection parameters.

    Returns:
        None
    """
    connection = get_db_connection(configuration)
    data = fetch_group_for_instance(connection)
    if data:
        for group in data:
            print(f"Group ID: {group['id']}, Name: {group['name']}")
