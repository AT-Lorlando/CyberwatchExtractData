CVE_REPORT = {
    "Headers": "Published Date;Last Reviewed Date;Domain;Surface;Server;CVE Code;CVSS Score;CVSS Temporal Score;CVSS Environmental Score;CVSS Computed Score;Criticity;Component;Product;Version;Update;Score EPSS;Maturity;Content;Vector;Environmental Vector;Temporal Vector;CWE Code;Related CWEs;Related CAPECs;Related ATK;Cisa Reference;CertFR References",
}


CPE_REPORT = {
    "Headers": "Domain;Server;CPE;CVE C1;CVE C2;CVE C3;CVE C4;CVE C5;Total",
}


PATCH_REPORT = {
    "Headers": "Server;CPE;Current Version;Target Version;CVE Codes;CVE Number",
}


SECURITY_ISSUE_REPORT = {
    "Headers": "Server;Title;Level;Product;EndOfLife;DockerImage",
}


def get_row_for_cve(cve, server):
    return f"{cve.published_date};{cve.reviewed_date};{server.domain};{server.surface};{server.hostname};{cve.cve_code};{cve.score};{cve.temporal_score};{cve.environmental_score};{cve.computed_score};C{cve.severity};{cve.cpe};{cve.package_product};{cve.package_version};{cve.correctif};{cve.epss};{cve.maturity};{cve.content};{cve.cvss_vector};{cve.environmental_vector};{cve.temporal_vectors};{cve.cwe_code};{cve.related_cwes};{cve.related_capecs};{cve.related_taxonomies};{'Yes' if cve.cisa_flag else 'No'};{cve.references_code}\n"


def get_row_for_package(package, server):
    return f"{server.domain};{server.hostname};{package.type}:{package.product}:{package.version};{package.cves_number[0]};{package.cves_number[1]};{package.cves_number[2]};{package.cves_number[3]};{package.cves_number[4]};{package.cves_number[-1]}\n"


def get_row_for_correctif(correctif, server):
    return f"{server.hostname};{correctif.product};{correctif.current_version};{correctif.target_version};{' '.join(correctif.cves)};{len(correctif.cves)}\n"


def get_row_for_security_issue(security_issue, server):
    return f"{server.hostname};{security_issue.title};{security_issue.string_level};{security_issue.product};{security_issue.eol};{security_issue.image}\n"
