import datetime
import os
from data import get_cves_data_for_group
from report_models import (
    CVE_REPORT,
    CPE_REPORT,
    PATCH_REPORT,
    SECURITY_ISSUE_REPORT,
    get_row_for_cve,
    get_row_for_package,
    get_row_for_correctif,
    get_row_for_security_issue,
)
from utils import print_progress_bar
from logger import setup_logger

logger = setup_logger(__name__)


def generate_report(
    group,
    date_from=None,
    date_to=None,
    capec_data={},
    cwes_data={},
    environmental_configuration={},
    configuration_cyberwatch={},
    flag_split=False,
):
    """
    Generate a report for a given group.

    Args:
        group (str): The name of the group.
        days (int, optional): The number of days to consider for the report. Defaults to 0.
        capec_data (dict, optional): The CAPEC data. Defaults to {}.
        cwes_data (dict, optional): The CWEs data. Defaults to {}.
        environmental_configuration (dict, optional): The environmental configuration data. Defaults to {}.
        configuration_cyberwatch (dict, optional): The Cyberwatch configuration data. Defaults to {}.
        flag_split (bool, optional): Flag to indicate whether to split the report. Defaults to False.
    """
    group_data, group_name = get_cves_data_for_group(
        group,
        date_from=date_from,
        date_to=date_to,
        capec_data=capec_data,
        cwes_data=cwes_data,
        environmental_configuration=environmental_configuration,
        configuration_cyberwatch=configuration_cyberwatch,
    )
    generate_cve_report(group_data, group_name, split=flag_split)
    generate_cpe_report(group_data, group_name, split=flag_split)
    generate_patch_report(group_data, group_name, split=flag_split)
    generate_security_issue_report(
        group_data,
        group_name,
        split=flag_split,
    )


def generate_cve_report(group_data, group_name, split=False):
    if split:
        for server in group_data:
            filename = (
                server.hostname
                + "_"
                + "CVE_report_"
                + group_name
                + "_"
                + datetime.datetime.now().strftime("%Y-%m-%d-%Hh%M")
                + ".csv"
            )
            logger.info(
                "Generating CVE report at ./output/" + filename,
            )
            with open("output/" + filename, "w") as f:
                f.write(CVE_REPORT["Headers"] + "\n")
                for cve in server.cves:
                    print_progress_bar(
                        list(server.cves).index(cve),
                        len(server.cves),
                        prefix="Writing CVEs",
                        length=50,
                    )
                    _cve = server.cves[cve]
                    f.write(get_row_for_cve(_cve, server))
                os.chmod("output/" + filename, 0o777)
    else:
        filename = (
            "CVE_report_"
            + group_name
            + "_"
            + datetime.datetime.now().strftime("%Y-%m-%d-%Hh%M")
            + ".csv"
        )
        logger.info(
            "Generating CVE report at ./output/" + filename,
        )
        counter_error = 0
        with open("output/" + filename, "w") as f:
            f.write(CVE_REPORT["Headers"] + "\n")
            for server in group_data:
                for cve in server.cves:
                    print_progress_bar(
                        list(server.cves).index(cve),
                        len(server.cves),
                        prefix="Writing CVEs",
                        length=50,
                    )
                    _cve = server.cves[cve]
                    try:
                        f.write(get_row_for_cve(_cve, server))
                    except Exception as e:
                        logger.error(
                            "Error writing CVE: " + _cve.cve_code + " to file...",
                            exc_info=True,
                        )
                        logger.debug(_cve)
                        counter_error += 1
        os.chmod("output/" + filename, 0o777)
        if counter_error > 0:
            logger.error(f"/!\\ Error writing {counter_error} CVEs to file /!\\ ")


def generate_cpe_report(group_data, group_name, split=False):
    if split:
        for server in group_data:
            filename = (
                server.hostname
                + "_"
                + "CPE_report_"
                + group_name
                + "_"
                + datetime.datetime.now().strftime("%Y-%m-%d-%Hh%M")
                + ".csv"
            )
            logger.info(
                "Generating CPE report at ./output/" + filename,
            )
            with open("output/" + filename, "w") as f:
                f.write(CPE_REPORT["Headers"] + "\n")
                for package_id in server.packages:
                    print_progress_bar(
                        list(server.packages).index(package_id),
                        len(server.packages),
                        prefix="Counting CPEs",
                        length=50,
                    )
                    f.write(get_row_for_package(server.packages[package_id], server))
                os.chmod("output/" + filename, 0o777)
    else:
        filename = (
            "CPE_report_"
            + group_name
            + "_"
            + datetime.datetime.now().strftime("%Y-%m-%d-%Hh%M")
            + ".csv"
        )
        logger.info(
            "Generating CPE report at ./output/" + filename,
        )
        with open("output/" + filename, "w") as f:
            f.write(CPE_REPORT["Headers"] + "\n")
            for server in group_data:
                for package_id in server.packages:
                    print_progress_bar(
                        list(server.packages).index(package_id),
                        len(server.packages),
                        prefix="Counting CPEs",
                        length=50,
                    )
                    f.write(get_row_for_package(server.packages[package_id], server))
        os.chmod("output/" + filename, 0o777)


def generate_patch_report(group_data, group_name, split=False):
    if split:
        for server in group_data:
            filename = (
                server.hostname
                + "_"
                + "PATCH_report_"
                + group_name
                + "_"
                + datetime.datetime.now().strftime("%Y-%m-%d-%Hh%M")
                + ".csv"
            )
            logger.info(
                "Generating PATCH report at ./output/" + filename,
            )
            with open("output/" + filename, "w") as f:
                f.write(PATCH_REPORT["Headers"] + "\n")
                for correctif in server.correctifs:
                    print_progress_bar(
                        list(server.correctifs).index(correctif),
                        len(server.correctifs),
                        prefix="Counting patchs",
                        length=50,
                    )
                    _correctif = server.correctifs[correctif]
                    try:
                        f.write(get_row_for_correctif(_correctif, server))
                    except Exception as e:
                        logger.error("\nError writing patch to file...", exc_info=True)
                        logger.debug(_correctif)
                os.chmod("output/" + filename, 0o777)
    else:
        filename = (
            "PATCH_report_"
            + group_name
            + "_"
            + datetime.datetime.now().strftime("%Y-%m-%d-%Hh%M")
            + ".csv"
        )
        logger.info(
            "Generating CORRECTIF report at ./output/" + filename,
        )
        counter_error = 0
        with open("output/" + filename, "w") as f:
            f.write(PATCH_REPORT["Headers"] + "\n")
            for server in group_data:
                for correctif in server.correctifs:
                    print_progress_bar(
                        list(server.correctifs).index(correctif),
                        len(server.correctifs),
                        prefix="Counting Correctifs",
                        length=50,
                    )
                    _correctif = server.correctifs[correctif]
                    try:
                        f.write(get_row_for_correctif(_correctif, server))
                    except Exception as e:
                        logger.error(
                            "Error writing correctif to file...", exc_info=True
                        )
                        logger.debug(_correctif.__str__())
                        counter_error += 1
        os.chmod("output/" + filename, 0o777)
        if counter_error > 0:
            logger.error(f"/!\\ Error writing {counter_error} lines to file /!\\ ")


def generate_security_issue_report(group_data, group_name, split=False):
    if split:
        for server in group_data:
            filename = (
                server.hostname
                + "_"
                + "SECURITY_ISSUE_report_"
                + group_name
                + "_"
                + datetime.datetime.now().strftime("%Y-%m-%d-%Hh%M")
                + ".csv"
            )
            logger.info(
                "Generating security_issue report at ./output/" + filename,
            )
            with open("output/" + filename, "w") as f:
                f.write(SECURITY_ISSUE_REPORT["Headers"] + "\n")
                for security_issue in server.security_issues:
                    print_progress_bar(
                        list(server.security_issues).index(security_issue),
                        len(server.security_issues),
                        prefix="Counting security_issues",
                        length=50,
                    )
                    _security_issue = server.security_issues[security_issue]
                    try:
                        f.write(get_row_for_security_issue(_security_issue, server))
                    except Exception as e:
                        logger.error(
                            "\nError writing security_issue to file...", exc_info=True
                        )
                        logger.debug(_security_issue)
                os.chmod("output/" + filename, 0o777)
    else:
        filename = (
            "SECURITY_ISSUE_report_"
            + group_name
            + "_"
            + datetime.datetime.now().strftime("%Y-%m-%d-%Hh%M")
            + ".csv"
        )
        logger.info(
            "Generating security_issue report at ./output/" + filename,
        )
        counter_error = 0
        with open("output/" + filename, "w") as f:
            f.write(SECURITY_ISSUE_REPORT["Headers"] + "\n")
            for server in group_data:
                for security_issue in server.security_issues:
                    print_progress_bar(
                        list(server.security_issues).index(security_issue),
                        len(server.security_issues),
                        prefix="Counting security_issues",
                        length=50,
                    )
                    _security_issue = server.security_issues[security_issue]
                    try:
                        f.write(get_row_for_security_issue(_security_issue, server))
                    except Exception as e:
                        logger.error(
                            "Error writing security_issue to file...", exc_info=True
                        )
                        logger.debug(_security_issue.__str__())
                        counter_error += 1
        os.chmod("output/" + filename, 0o777)
        if counter_error > 0:
            logger.error(f"/!\\ Error writing {counter_error} lines to file /!\\")
