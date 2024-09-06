import pytz
import cvss
import json
from logger import setup_logger

logger = setup_logger(__name__)
"""
This module contains the implementation of several classes related to package management and security vulnerabilities.

Classes:
- Package: Represents a software package with its attributes such as id, vendor, product, version, type, title, and cves_number.
- Correctif: Represents a corrective action for a package, with attributes like id, vendor, product, target_version, current_version, and cves.
- Update: Represents an update action for a package, with attributes like id, target, current, cve, and server_cve_id.
- Cve: Represents a security vulnerability (CVE), with attributes like id, server_cve_id, cve_code, score, epss, maturity, published_date, reviewed_date, content, cwe_code, cvss_vector, cvss_version, update, package_type, package_vendor, package_product, package_version, cpe, correctif, technologies, references, security_announcement_ids, scores, environmental_score, temporal_score, computed_score, environmental_vector, temporal_vectors, full_cvss_vector, severity, cisa_flag, references_code, related_cwes, related_capecs, and related_taxonomies.
- Server: Represents a server with its attributes like id, hostname, os, packages, affected_packages, updates, correctifs, domain, surface, environmental_vectors_v2, environmental_vectors_v3, surface_vectors_maxs, surface_vectors_mins, surface_vectors, cves, and security_issues.
- SecurityIssue: Represents a security issue with its attributes like id, title, description, level, maturity, cve, and cwe.

Constants:
- CVSS3_MAP: A dictionary mapping CVSS3 attributes to their corresponding values.
- CVSS2_MAP: A dictionary mapping CVSS2 attributes to their corresponding values.
- CVSS3_LEVELS: A dictionary mapping CVSS3 attributes to their corresponding levels.
- MATURITY_LEVELS: A dictionary mapping maturity levels to their descriptions.
- SECURITY_ISSUE_LEVELS: A dictionary mapping security issue levels to their descriptions.
"""

CVSS3_MAP = {
    "AV": {0: "/AV:P", 1: "/AV:L", 2: "/AV:A", 3: "/AV:N"},
    "AC": {0: "/AC:H", 1: "/AC:L"},
    "PR": {0: "/PR:H", 1: "/PR:L", 2: "/PR:N"},
    "UI": {0: "/UI:R", 1: "/UI:N"},
    "S": {0: "/S:U", 1: "/S:C"},
    "C": {0: "/C:N", 1: "/C:L", 2: "/C:H"},
    "I": {0: "/I:N", 1: "/I:L", 2: "/I:H"},
    "A": {0: "/A:N", 1: "/A:L", 2: "/A:H"},
    "E": {0: "/E:X", 1: "/E:U", 2: "/E:P", 3: "/E:F", 4: "/E:H"},
    "RL": {0: "/RL:X", 1: "/RL:O", 2: "/RL:T", 3: "/RL:W", 4: "/RL:U"},
    "RC": {0: "/RC:X", 1: "/RC:U", 2: "/RC:R", 3: "/RC:C"},
}

CVSS2_MAP = {
    "AV": {0: "/AV:L", 1: "/AV:A", 2: "/AV:N"},
    "AC": {0: "/AC:H", 1: "/AC:M", 2: "/AC:L"},
    "Au": {0: "/Au:M", 1: "/Au:S", 2: "/Au:N"},
    "C": {0: "/C:N", 1: "/C:P", 2: "/C:C"},
    "I": {0: "/I:N", 1: "/I:P", 2: "/I:C"},
    "A": {0: "/A:N", 1: "/A:P", 2: "/A:C"},
    "E": {0: "/E:ND", 1: "/E:U", 2: "/E:POC", 3: "/E:F", 4: "/E:H"},
    "RL": {0: "/RL:ND", 1: "/RL:OF", 2: "/RL:TF", 3: "/RL:W", 4: "/RL:U"},
    "RC": {0: "/RC:ND", 1: "/RC:UC", 2: "/RC:UR", 3: "/RC:C"},
}

CVSS3_LEVELS = {
    "AV": {"P": 0, "L": 1, "A": 2, "N": 3},
    "AC": {"H": 0, "L": 1},
    "PR": {"H": 0, "L": 1, "N": 2},
    "UI": {"R": 0, "N": 1},
    "S": {"U": 0, "C": 1},
    "C": {"N": 0, "L": 1, "H": 2},
    "I": {"N": 0, "L": 1, "H": 2},
    "A": {"N": 0, "L": 1, "H": 2},
    "MAV": {"P": 0, "L": 1, "A": 2, "N": 3},
    "MAC": {"H": 0, "L": 1},
    "MPR": {"H": 0, "L": 1, "N": 2},
    "MUI": {"R": 0, "N": 1},
    "MS": {"U": 0, "C": 1},
    "MC": {"N": 0, "L": 1, "H": 2},
    "MI": {"N": 0, "L": 1, "H": 2},
    "MA": {"N": 0, "L": 1, "H": 2},
}

MATURITY_LEVELS = {
    1: "unproven",
    2: "proof-of-concept",
    3: "functional",
    4: "high",
}

SECURITY_ISSUE_LEVELS = {
    0: "Info",
    1: "Minor",
    2: "Moderate",
    3: "Major",
    4: "Critical",
}


class Package:
    """
    Represents a package.

    Attributes:
        id (str): The ID of the package.
        vendor (str): The vendor of the package.
        product (str): The product of the package.
        version (str): The version of the package.
        type (str): The type of the package.
        title (str): The title of the package.
        cves_number (list): A list of CVE numbers associated with the package.
            The list contains 6 elements representing the counts of CVEs in each severity level (C1, C2, C3, C4, C5) and the total count.
    """

    def __init__(self, server_package):
        self.id = server_package.get("id")
        self.vendor = server_package.get("vendor")
        self.product = server_package.get("product")
        self.version = server_package.get("version")
        self.type = server_package.get("type")
        self.title = server_package.get("title")
        self.cves_number = [0, 0, 0, 0, 0, 0]  # C1, C2, C3, C4, C5, Total

    def __str__(self):
        return f"\nPackage id: {self.id}\nvendor: {self.vendor}\nproduct: {self.product}\nversion: {self.version}\ntype: {self.type}\ntitle: {self.title}\ncves: {self.cves_number}\n"


class Correctif:
    """
    Initializes a Correctif object.

    Args:
        current_package: The current package object.
        target_package: The target package object.

    Attributes:
        id: The ID of the Correctif.
        product: The product of the Correctif.
        vendor: The vendor of the Correctif.
        current_version: The current version of the Correctif.
        target_version: The target version of the Correctif.
        cves: The list of CVEs associated with the Correctif.
    """

    def __init__(self, current_package, target_package):
        if target_package.type == "Packages::Kb":
            self.id = target_package.id
            self.product = "OS Knowledge Base"
            self.vendor = "Microsoft"
            self.current_version = "None"
            self.target_version = target_package.product
        else:
            self.id = current_package.id if current_package else target_package.id
            self.product = current_package.product if current_package else "None"
            self.vendor = current_package.vendor if current_package else "None"
            self.current_version = (
                current_package.version if current_package else "None"
            )
            self.target_version = (
                target_package.version
                if target_package and target_package.version
                else "Latest version"
            )
        self.cves = []

    def add_cve(self, cve):
        self.cves.append(cve)

    def __str__(self):
        return f"\nCorrectif id: {self.id}\nvendor: {self.vendor}\nproduct: {self.product}\ntarget_version: {self.target_version}\ncurrent_version: {self.current_version}\ncves: {self.cves}\n"


class Update:
    """
    Initializes an Update object.

    Args:
        update (dict): A dictionary containing update information.
        current (object): The current object.
        target (object): The target object.

    Attributes:
        id (str): The ID of the update.
        target_id (str): The ID of the target.
        target (object): The target object.
        current_id (str): The ID of the current object.
        current (object): The current object.
        cve (str): The CVE code.
        server_cve_id (str): The server CVE ID.
    """

    """
    Returns a string representation of the Update object.

    Returns:
        str: A string representation of the Update object.
    """

    def __init__(self, update, current, target):
        self.id = update.get("id")
        self.target_id = update.get("target_id")
        self.target = target
        if target.type == "Packages::Kb":
            self.current_id = self.target_id
            self.current = self.target
        else:
            self.current_id = update.get("current_id")
            self.current = current
        self.cve = update.get("cve_code")
        self.server_cve_id = update.get("server_cve_id")

    def __str__(self):
        return (
            f"\nUpdate id: {self.id}\ntarget: {self.target}\ncurrent: {self.current}\n"
        )


class Cve:
    """
    Represents a Common Vulnerabilities and Exposures (CVE) entry.

    Args:
        _id (str): The ID of the CVE.
        cve_announcement (dict): The announcement data of the CVE.
        update (Update): The update associated with the CVE.
        server (Server): The server associated with the CVE.

    Attributes:
        id (str): The ID of the CVE.
        server_cve_id (str): The server CVE ID.
        cve_code (str): The CVE code.
        score (float): The score of the CVE.
        epss (str): The EPSS (Exploit Publicly Spotted) status of the CVE.
        maturity (str): The maturity level of the exploit code.
        maturity_level (int): The maturity level of the exploit code.
        published_date (str): The published date of the CVE.
        reviewed_date (str): The last modified date of the CVE.
        content (str): The content of the CVE.
        cwe_code (str): The CWE (Common Weakness Enumeration) code of the CVE.
        cvss_vector (str): The CVSS (Common Vulnerability Scoring System) vector of the CVE.
        cvss_version (int): The CVSS version of the CVE.
        update (Update): The update associated with the CVE.
        package_type (str): The type of the package.
        package_vendor (str): The vendor of the package.
        package_product (str): The product of the package.
        package_version (str): The version of the package.
        cpe (str): The CPE (Common Platform Enumeration) of the package.
        correctif (None): The correctif of the CVE.
        technologies (list): The list of technologies associated with the CVE.
        references (list): The list of references associated with the CVE.
        security_announcement_ids (list): The list of security announcement IDs associated with the CVE.
        scores (list): The list of scores (Base, Temporal, Env).
        environmental_score (None): The environmental score of the CVE.
        temporal_score (None): The temporal score of the CVE.
        computed_score (None): The computed score of the CVE.
        environmental_vector (str): The environmental vector of the CVE.
        temporal_vectors (str): The temporal vectors of the CVE.
        full_cvss_vector (str): The full CVSS vector of the CVE.
        severity (None): The severity of the CVE.
        cisa_flag (bool): The CISA (Cybersecurity and Infrastructure Security Agency) flag of the CVE.
        references_code (None): The references code of the CVE.
        related_cwes (list): The list of related CWEs (Common Weakness Enumerations) of the CVE.
        related_capecs (list): The list of related CAPECs (Common Attack Pattern Enumerations and Classifications) of the CVE.
        related_taxonomies (list): The list of related taxonomies of the CVE.
        cve (dict): The announcement data of the CVE.

    Methods:
        populate_environmental_vector(server): Populates the environmental vector of the CVE.
        populate_cwes_data(cwes_data, capec_data): Populates the CWEs and CAPECs data of the CVE.
        compute_score(): Computes the score of the CVE.
        compute_severity(): Computes the severity of the CVE.
        compute_references(): Computes the references of the CVE.
    """

    def __init__(self, _id, cve_announcement, update, server):
        self.id = _id
        self.server_cve_id = cve_announcement.get("server_cve_id")
        self.cve_code = cve_announcement.get("cve_code")
        self.score = cve_announcement.get("score")
        self.epss = cve_announcement.get("epss")
        self.maturity = maturity_level_to_string(
            cve_announcement.get("exploit_code_maturity")
        )
        self.maturity_level = cve_announcement.get("exploit_code_maturity")
        self.published_date = cve_announcement.get("published")
        self.reviewed_date = cve_announcement.get("last_modified")
        self.content = cve_announcement.get("content")
        self.cwe_code = cve_announcement.get("cwe_code")
        self.cvss_vector = ""
        self.cvss_version = 0
        try:
            # if cve_announcement.get("cvss_v4_id"):
            #    cvss_dict_vector = {
            #    }
            #    self.cvss_vector = cvss_vector_dict_to_string(cvss_dict_vector, 4)
            #    self.cvss_version = 4
            if cve_announcement.get("cvss_v4"):
                self.cvss_vector = cve_announcement.get("cvss_v4")
                self.cvss_version = 4
            elif cve_announcement.get("cvss_v3_id"):
                cvss_dict_vector = {
                    "AV": cve_announcement.get("access_vector"),
                    "AC": cve_announcement.get("access_complexity"),
                    "PR": cve_announcement.get("privileges_required"),
                    "UI": cve_announcement.get("user_interaction"),
                    "S": cve_announcement.get("scope"),
                    "C": cve_announcement.get("confidentiality_impact"),
                    "I": cve_announcement.get("integrity_impact"),
                    "A": cve_announcement.get("availability_impact"),
                }
                self.cvss_vector = cvss_vector_dict_to_string(cvss_dict_vector, 3)
                self.cvss_version = 3
            elif cve_announcement.get("cvss_id"):
                cvss_dict_vector = {
                    "AV": cve_announcement.get("cvss_access_vector"),
                    "AC": cve_announcement.get("cvss_access_complexity"),
                    "Au": cve_announcement.get("cvss_authentication"),
                    "C": cve_announcement.get("cvss_confidentiality_impact"),
                    "I": cve_announcement.get("cvss_integrity_impact"),
                    "A": cve_announcement.get("cvss_availability_impact"),
                }
                self.cvss_vector = cvss_vector_dict_to_string(cvss_dict_vector, 2)
                self.cvss_version = 2
        except Exception as e:
            raise Exception("Error getting CVSS vectors for ", cve_announcement, e)
        self.update = update
        self.package_type = (
            update.target.type if update.target and update.target.type else ""
        )
        self.package_vendor = (
            update.current.vendor
            if update.current and update.current.vendor
            else "Microsoft" if update.target.type == "Packages::Kb" else ""
        )
        self.package_product = (
            server.os["name"]
            if update.target.type == "Packages::Kb"
            else update.current.product if update.current.product else ""
        )
        self.package_version = (
            update.target.title
            if update.target.title
            else (
                "Last KB"
                if update.target.type == "Packages::Kb"
                else update.current.version if update.current.version else ""
            )
        )
        self.cpe = f"{':'.join([self.package_type,self.package_vendor,self.package_product,self.package_version])}"
        self.correctif = None

        self.technologies = cve_announcement.get("full_technos")
        self.references = cve_announcement.get("full_references")
        self.security_announcement_ids = cve_announcement.get(
            "security_announcement_ids"
        )

        self.scores = []  # Base, Temporal, Env
        self.environmental_score = None  # Base vector + environmental one
        self.temporal_score = None  # Base vector + temporal one
        self.computed_score = None  # Base vector + environmental one + temporal one
        self.environmental_vector = ""
        self.temporal_vectors = ""
        self.full_cvss_vector = ""
        self.severity = None

        self.cisa_exploit_at = cve_announcement.get("cisa_exploit_add_at")
        self.cisa_flag = True if self.cisa_exploit_at else False
        self.references_code = None
        self.related_cwes = []
        self.related_capecs = []
        self.related_taxonomies = []

        self.cve = cve_announcement

    def populate_environmental_vector(self, server):
        try:
            if self.cvss_vector and self.cvss_version == 3:
                env_vectors = server.environmental_vectors_v3
                surface_vectors = get_surface_vectors_for_cve_from_server(
                    self.cvss_vector, server
                )
                self.environmental_vector = env_vectors + surface_vectors
            elif self.cvss_vector and self.cvss_version == 2:
                env_vectors = server.environmental_vectors_v2
                self.environmental_vector = env_vectors
        except Exception as e:
            raise Exception(f"Error in populate_cve_environmental_vector: {e}")

    def populate_cwes_data(self, cwes_data, capec_data):
        try:
            cwe_code = (
                self.cwe_code[4:]
                if self.cwe_code is not None and self.cwe_code.startswith("CWE")
                else None
            )
            if cwe_code is not None and cwe_code in cwes_data:
                cwe = cwes_data.get(cwe_code)
                id_array = [cwe["CWE_ID"]]
                related_weaknesses = [{"CWE_ID": cwe["CWE_ID"], "ParentOf": "Root"}]
                related_attack_patterns = [
                    atk for atk in cwe["Related_Attack_Patterns"]
                ]
                add_related_weaknesses(
                    cwes_data,
                    cwe,
                    id_array,
                    related_weaknesses,
                    related_attack_patterns,
                )
                self.related_cwes = related_weaknesses
                self.related_capecs = related_attack_patterns

                for capec in self.related_capecs:
                    if capec in capec_data:
                        capec = capec_data.get(capec)
                        for taxonomy in capec["Taxonomy_Mappings"]:
                            if taxonomy not in self.related_taxonomies:
                                self.related_taxonomies.append(taxonomy)
        except Exception as e:
            raise Exception(f"Error in populate_cve_cwes_data: {e}")

    def compute_score(self):
        try:
            self.temporal_vectors = get_temporal_vectors_from_cve_and_remediation(self)
            self.full_cvss_vector = (
                (self.cvss_vector + self.environmental_vector + self.temporal_vectors)
                if self.cvss_version != 4
                else self.cvss_vector
            )
            # Two get_cvss_env_from_vector because CVSS library return:
            # [X,Y,Z] with: X = Score with base vectors
            #               Y = Score with base + temporal vectors
            #               Z = Score with base + env vector + temporal vector
            #
            # Or, we want a Y' = Score with base + env vector
            # So we need to compute a score without temp vector
            self.scores = get_cvss_env_from_vector(
                self.cvss_vector, self.environmental_vector
            )
            self.environmental_score = self.scores[2] if self.scores[2] else self.score
            self.scores = get_cvss_env_from_vector(
                self.cvss_vector, self.environmental_vector, self.temporal_vectors
            )

            self.score = self.scores[0] if self.scores[0] else self.score
            self.temporal_score = self.scores[1] if self.scores[1] else self.score
            self.computed_score = (
                self.scores[2] if self.scores[2] else self.temporal_score
            )

            self.update.current.cves_number[-1] += 1
        except Exception as e:
            raise Exception(
                "Error computing score env for CVE: " + self.cve_code,
                e,
            )

    def compute_severity(self):
        try:
            score = self.computed_score
            if type(score) is int or type(score) is float:
                if score >= 9.0:
                    self.severity = 1
                elif score >= 7.0:
                    self.severity = 2
                elif score >= 4.0:
                    self.severity = 3
                elif score >= 0.0:
                    self.severity = 4
            else:
                self.severity = 5
            self.update.current.cves_number[self.severity - 1] += 1
        except Exception as e:
            raise Exception(
                "Error computing severity score env for CVE: " + self.cve_code,
                self.severity,
                self.update.__str__(),
                e,
            )

    def compute_references(self):
        try:
            self.references_code = ""
            for ref in self.references:
                self.references_code += (
                    ref.get("code", "") + " " if "CERTFR" in ref.get("code", "") else ""
                )
            self.references_code = self.references_code.strip()
        except Exception as e:
            raise Exception(
                "Error getting related references for ",
                self.cve_code,
                self.references,
                e,
            )

    def compute_dates(self):
        try:
            self.published_date = (
                (
                    self.published_date.astimezone(pytz.timezone("UTC")).strftime(
                        "%Y-%m-%d"
                    )
                )
                if self.published_date
                else "Unknown"
            )
            self.reviewed_date = (
                (
                    self.reviewed_date.astimezone(pytz.timezone("UTC")).strftime(
                        "%Y-%m-%d"
                    )
                )
                if self.reviewed_date
                else "Unknown"
            )
        except Exception as e:
            raise Exception("Error computing dates for ", self.cve_code, e)

    def compute_related_infos(self):
        try:
            self.related_cwes = array_to_string(self.related_cwes, " / ", "CWE_ID")
            self.related_capecs = array_to_string(
                self.related_capecs, " / ", prefix="CAPEC-"
            )
            self.related_taxonomies = "".join(
                [
                    f'T{tax["ID"]} ' if tax["Taxonomy_Name"] == "ATTACK" else ""
                    for tax in self.related_taxonomies
                ]
            ).strip()
        except Exception as e:
            raise Exception(
                "Error computing related informations for ",
                self.cve_code,
                self.related_cwes,
                self.related_capecs,
                self.related_taxonomies,
                e,
            )

    def compute_correctif(self):
        try:
            self.correctif = (
                f">= {self.update.target.version}"
                if self.update is not None
                and self.update.target is not None
                and self.update.target.version
                else (
                    f"N/A"
                    if self.update is not None and self.update.target is not None
                    else None
                )
            )
            if self.correctif is None:
                self.correctif = "N/A"
        except Exception as e:
            raise Exception("Error computing correctif for ", self.cve_code, e)

    def compute(self):
        self.content = (
            self.content.replace(";", ",").replace("\n", " ").encode("utf-8")
            if self.content
            else "Undefined"
        )
        try:
            self.compute_dates()
            self.compute_related_infos()
            self.compute_references()
            self.compute_correctif()
            self.compute_score()
            self.compute_severity()
        except Exception as e:
            raise Exception("Error computing CVE: " + self.cve_code, e)

    def __str__(self):
        return f"CVE id: {self.id}\ncve_code: {self.cve_code}\nscore: {self.score}\nenvironmental_score: {self.environmental_score}\ncomputed_score: {self.computed_score}\nepss: {self.epss}\nmaturity: {self.maturity}\npublished_date: {self.published_date}\nreviewed_date: {self.reviewed_date}\ncontent: {self.content}\ncwe_code: {self.cwe_code}\ncvss_vector: {self.cvss_vector}\nenvironmental_vector: {self.environmental_vector}\nupdate: {self.update.__str__()}\ncpe: {self.cpe}\nrelated_cwes: {self.related_cwes}\nrelated_capecs: {self.related_capecs}\nrelated_taxonomies: {self.related_taxonomies}\ntechnologies: {self.technologies}\nreferences: {self.references}\n"


class Server:
    """
    Represents a server.

    Attributes:
        id (int): The server ID.
        hostname (str): The hostname of the server.
        os (str): The operating system of the server.
        packages (dict): A dictionary of packages installed on the server.
        affected_packages (dict): A dictionary of affected packages on the server.
        updates (dict): A dictionary of updates available for the server.
        correctifs (dict): A dictionary of correctifs for the server.
        domain (str): The domain of the server.
        surface (str): The surface of the server.
        environmental_vectors_v2 (str): The environmental vectors V2 of the server.
        environmental_vectors_v3 (str): The environmental vectors V3 of the server.
        surface_vectors_maxs (str): The surface vectors maxs of the server.
        surface_vectors_mins (str): The surface vectors mins of the server.
        surface_vectors (dict): A dictionary of surface vectors for the server.
        cves (dict): A dictionary of CVEs (Common Vulnerabilities and Exposures) for the server.
        security_issues (dict): A dictionary of security issues for the server.

    Methods:
        __init__(self, _id, hostname, os, configuration): Initializes a new instance of the Server class.
        set_environmental_config(self, configuration): Sets the environmental configuration of the server.
        __str__(self): Returns a string representation of the server.
    """

    def __init__(self, _id, hostname, os, configuration):
        self.id = _id
        self.hostname = hostname
        self.os = os
        self.packages = {}
        self.affected_packages = {}
        self.updates = {}
        self.correctifs = {}
        self.domain = ""
        self.surface = ""
        self.environmental_vectors_v2 = ""
        self.environmental_vectors_v3 = ""
        self.surface_vectors_maxs = ""
        self.surface_vectors_mins = ""
        self.surface_vectors = {}
        self.cves = {}
        self.security_issues = {}
        try:
            self.set_environmental_config(configuration)
        except Exception as e:
            logger.error(
                f"Error/Warnings during Server.set_environmental_config for server {self.hostname}",
                exc_info=True,
            )

    def set_environmental_config(self, configuration):
        domains = configuration.get("DOMAINS")
        surfaces = configuration.get("SURFACES")
        surface_vectors_maxs = configuration.get("SURFACES_VECTORS_MAX")
        surface_vectors_mins = configuration.get("SURFACES_VECTORS_MIN")
        surface_vectors = configuration.get("SURFACES_VECTORS")
        warning = ""
        if domains:
            self.domain = domains.get(self.hostname)
        else:
            warning += f"\tWarning: No domains found in config file\n"
        if surfaces:
            self.surface = surfaces.get(self.hostname)
        else:
            warning += f"\tWarning: No surfaces found in config file\n"

        if self.domain:
            self.environmental_vectors_v3 = configuration.get(
                "ENVIRONMENTAL_VECTORS_V3"
            ).get(self.domain)
            self.environmental_vectors_v2 = configuration.get(
                "ENVIRONMENTAL_VECTORS_V2"
            ).get(self.domain)
        else:
            warning += (
                f"\tWarning: No domain found in config file for {self.hostname}\n"
            )
        if self.surface:
            self.surface_vectors_maxs = surface_vectors_maxs.get(self.surface)
            self.surface_vectors_mins = surface_vectors_mins.get(self.surface)
            if not surface_vectors:
                warning += f"\tWarning: No surface vector found in config file for {self.hostname}\n"
            else:
                self.surface_vectors = surface_vectors.get(self.surface)
        else:
            warning += f"\tWarning: No surface vector found in config file for {self.hostname}\n"
        if not self.environmental_vectors_v3:
            warning += (
                f"\tWarning: No environmental vector V3 found for {self.hostname}\n"
            )
        if not self.environmental_vectors_v2:
            warning += (
                f"\tWarning: No environmental vector V2 found for {self.hostname}\n"
            )
        if not self.surface_vectors_maxs:
            warning += f"\tWarning: No surface vector max found for {self.hostname}\n"
        if not self.surface_vectors_mins:
            warning += f"\tWarning: No surface vector min found for {self.hostname}\n"
        if not self.surface_vectors:
            warning += f"\tWarning: No surface vector found for {self.hostname}\n"
        if len(warning) > 0:
            raise Exception(warning)

    def __str__(self):
        return f"id: {self.id}\nhostname: {self.hostname}\nos: {self.os}\ndomain: {self.domain}\nsurface: {self.surface}\nenvironmental_vector: {self.environmental_vectors_v3}\nsurface_vector_maxs: {self.surface_vectors_maxs}\nsurface_vector_mins: {self.surface_vectors_mins}\naffected_packages: {self.affected_packages}\nupdates: {self.updates}\n"


class SecurityIssue:
    """
    Represents a security issue.

    Attributes:
        id (str): The ID of the security issue.
        payload (dict): The payload of the security issue.
        title (str): The title of the security issue.
        level (str): The level of the security issue.
        string_level (str): The string representation of the security issue level.
        product (str): The product associated with the security issue.
        eol (str): The end-of-life date associated with the security issue.
        image (str): The image associated with the security issue.

    Methods:
        __init__(security_issue): Initializes a new instance of the SecurityIssue class.
        __str__(): Returns a string representation of the SecurityIssue object.
    """

    def __init__(self, security_issue):
        self.id = security_issue.get("id")
        self.payload = json.loads(security_issue.get("payload"))
        self.title = security_issue.get("title")
        self.level = security_issue.get("level")
        self.string_level = SECURITY_ISSUE_LEVELS[self.level]
        self.product = ""
        self.eol = ""
        self.image = ""
        if self.payload:
            desc = self.payload.get("description", "")
            d_image = self.payload.get("docker_image_name", "")
            self.image = d_image
            if desc and "since" in desc:
                self.product = desc.split(" since ")[0]
                self.eol = desc.split(" since ")[1]
            p_name = self.payload.get("product_name", "")
            eol = self.payload.get("eol_date", "")
            if p_name:
                self.product = p_name
            if eol:
                self.eol = eol

    def __str__(self):
        return f"\nid:{self.id}\npayload:{self.payload}\ntitle:{self.title}"


def cvss_vector_dict_to_string(cvss_dict, version):
    """
    Converts a CVSS vector dictionary to a string based on the specified version.

    Args:
        cvss_dict (dict): The CVSS vector dictionary.
        version (int): The CVSS version (2 or 3).

    Returns:
        str: The CVSS vector string.
    """
    cvss = ""
    if version == 2:
        for key, value in cvss_dict.items():
            cvss += CVSS2_MAP[key][value]
        cvss = cvss[1:]  # Remove the leading character
    elif version == 3:
        cvss = "CVSS:3.1"
        for key, value in cvss_dict.items():
            cvss += CVSS3_MAP[key][value]
    # elif version == 4:
    #    cvss = "CVSS:4.0"
    #    for key, value in cvss_dict.items():
    #        cvss += CVSS4_MAP[key][value]
    return cvss


def maturity_level_to_string(maturity_level):
    """
    Converts a maturity level to its string representation.

    Args:
        maturity_level (str): The maturity level key.

    Returns:
        str: The string representation of the maturity level, or None if not found.
    """
    return MATURITY_LEVELS.get(maturity_level)


def add_related_weaknesses(
    cwes_data, cwe, id_array, related_weaknesses, related_attack_patterns
):
    """
    Recursively adds related weaknesses and attack patterns to the provided lists.

    Args:
        cwes_data (dict): The dictionary containing all CWE data.
        cwe (dict): The current CWE being processed.
        id_array (list): The list of CWE IDs that have been processed.
        related_weaknesses (list): The list to store related weaknesses.
        related_attack_patterns (list): The list to store related attack patterns.
    """
    for atk_pattern in cwe["Related_Attack_Patterns"]:
        if atk_pattern not in related_attack_patterns:
            related_attack_patterns.append(atk_pattern)

    for weakness in cwe["Related_Weaknesses"]:
        if weakness["Nature"] == "ChildOf":
            _id = weakness["CWE_ID"]
            if _id in id_array:
                continue
            id_array.append(_id)
            related_weaknesses.append({"CWE_ID": _id, "ParentOf": cwe["CWE_ID"]})
            add_related_weaknesses(
                cwes_data,
                cwes_data.get(_id),
                id_array,
                related_weaknesses,
                related_attack_patterns,
            )


def array_to_string(array, separator="", field="", prefix="", suffix=""):
    """
    Converts an array of items to a string with specified formatting.

    Args:
        array (list): The array of items to convert.
        separator (str): The separator to use between items.
        field (str): The field to extract from each item (if items are dictionaries).
        prefix (str): The prefix to add to each item.
        suffix (str): The suffix to add to each item.

    Returns:
        str: The formatted string.
    """
    if field:
        return separator.join(
            [f"{prefix}{item[field]}{suffix}" for item in array]
        ).strip()
    return separator.join([f"{prefix}{item}{suffix}" for item in array]).strip()


def get_cvss_env_from_vector(vector, env_vector="", temp_vector=""):
    """
    Extracts CVSS scores from a given vector.

    Args:
        vector (str): The CVSS vector.

    Returns:
        list: A list of CVSS scores.
    """
    scores = []
    if not vector:
        return ["Undefined", "Undefined", "Undefined"]

    if vector.startswith("CVSS:3"):
        c = cvss.CVSS3(vector + env_vector + temp_vector)
        scores = [s for s in c.scores()]
    elif vector.startswith("CVSS:4"):
        c = cvss.CVSS4(vector)
        scores = [s for s in c.scores()]
        return [c.base_score, c.base_score, c.base_score]
    else:
        c = cvss.CVSS2(vector + env_vector + temp_vector)
        scores = [s for s in c.scores()]
        if not temp_vector and not scores[1]:
            scores[1] = scores[0]
        if not env_vector and not scores[2]:
            scores[2] = scores[0]

    return scores


def get_environmental_cvss_vector_from_domain(configuration, domain):
    """
    Retrieves the environmental CVSS vector for a given domain.

    Args:
        configuration (dict): The configuration dictionary containing domains and environmental vectors.
        domain (str): The domain for which to retrieve the CVSS vector.

    Returns:
        str: The environmental CVSS vector.
    """
    domains = configuration.get("DOMAINS")
    env_cvss_vectors = configuration.get("ENVIRONMENTAL_VECTORS")

    if not domains or not env_cvss_vectors:
        return ""

    vector_key = domains.get(domain)
    if not vector_key:
        return ""

    return env_cvss_vectors.get(vector_key, "")


def get_surface_vectors_for_cve_from_server(cvss_vector, server):
    """
    Retrieves the surface vectors for a CVE from a server.

    Args:
        cvss_vector (str): The CVSS vector.
        server (object): The server object containing surface vectors.

    Returns:
        str: The surface vectors.
    """
    cvss_vector = cvss_vector.replace("CVSS:3.1", "").replace("CVSS:3.0", "")
    surface_vectors = ""

    def process_vectors(vectors, comparison, operator):
        nonlocal surface_vectors
        for cap_vector in vectors.split("/"):
            if not cap_vector:
                continue
            for vector in cvss_vector.split("/"):
                if not vector:
                    continue
                vector_name, vector_value = vector.split(":")
                cap_vector_name, cap_vector_value = cap_vector.split(":")
                if "M" + vector_name == cap_vector_name:
                    if operator(
                        CVSS3_LEVELS[vector_name][vector_value],
                        CVSS3_LEVELS[vector_name][cap_vector_value],
                    ):
                        surface_vectors += f"/M{vector_name}:{cap_vector_value}"

    if server.surface_vectors_maxs:
        process_vectors(server.surface_vectors_maxs, ">", lambda x, y: x > y)
    if server.surface_vectors_mins:
        process_vectors(server.surface_vectors_mins, "<", lambda x, y: x < y)

    for vec in cvss_vector.split("/"):
        if not vec:
            continue
        vector, value = vec.split(":")
        new_value = server.surface_vectors.get("M" + vector, {}).get(value, value)
        surface_vectors += f"/M{vector}:{new_value}"

    return surface_vectors


def get_temporal_vectors_from_cve_and_remediation(cve):
    """
    Retrieves the temporal vectors for a CVE and its remediation.

    Args:
        cve (object): The CVE object containing CVSS information.

    Returns:
        str: The temporal vectors.
    """
    if cve.cvss_version == 0 or cve.cvss_version == 4:
        return ""

    CVSS_MAP = {3: CVSS3_MAP, 2: CVSS2_MAP}.get(cve.cvss_version, {})

    try:
        temporal_vectors = CVSS_MAP["E"][cve.maturity_level]
    except KeyError as e:
        raise Exception(
            "Error getting temporal maturity_level vectors for ", cve.cve, CVSS_MAP, e
        )

    try:
        temporal_vectors += CVSS_MAP["RL"][
            1 if cve.correctif.startswith(("KB", ">=")) else 4
        ]
    except KeyError as e:
        raise Exception(
            "Error getting temporal correctif vectors for ",
            cve.cve_code,
            cve.correctif,
            e,
        )

    try:
        rc_vector = CVSS_MAP["RC"][
            (
                3
                if "CERTFR" in cve.references_code and cve.cisa_flag
                else 2 if "CERTFR" in cve.references_code or cve.cisa_flag else 1
            )
        ]
        temporal_vectors += rc_vector
    except KeyError as e:
        raise Exception(
            "Error getting temporal reference vectors for ",
            cve.cve_code,
            cve.references,
            e,
        )

    return temporal_vectors
