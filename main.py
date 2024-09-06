import sys
import os
from database import (
    list_group,
)
from config import load, parse
from xml_parsers import parse_capec_xml_to_dict, parse_cwe_xml_to_dict
from report_generator import generate_report
from utils import parse_date


def help():
    print("Usage: python main.py")
    print("This script will generate a report for a group of servers")
    print("The report will be saved in the output directory as report_date.csv")
    print("Options:")
    print("-h, --help: show this help message")
    print("-g, --group <group_ids>: group id to get the cve data for")
    print(
        "-from <date>: specify the start date for the report, format dd/mm/yyyy, default is none"
    )
    print(
        "-to <date>: specify the end date for the report, format dd/mm/yyyy, default is none"
    )
    print("-i, --instance <ip>: ip of the cyberwatch instance to use, choose wisely")
    print(
        "-c, --config <path/to/config/file>: Specify an environmental configuration file based on ./environment/example.json format"
    )
    print("-l, --list: list of all groups, don't forget to specify the instance IP.")
    print(
        "-s, --split, split the report for each server in the group in multiple files"
    )
    print("Example: python main.py -g 6 -from 01/01/2024 -i 172.0.0.1")
    print(
        "\t Generate a report for group 6 with data from 01/01/2024 using the cyberwatch instance at 172.0.0.1"
    )
    print("Example: python main.py -g 6 -i 172.0.0.1 -c ./environment/my_env.json")
    print("\t Generate a report for group 6 using the cyberwatch instance at 172.0.0.1")
    print("Example: python main.py -i 172.0.0.1 -g 1,2,3,4")
    print(
        "\t Generate a report for group 1,2,3,4 using the cyberwatch instance at 172.0.0.1"
    )
    sys.exit(1)


def main(
    group_ids,
    date_from,
    date_to,
    cbw_conf,
    env_conf_file,
    flag_split=False,
):
    """
    Main function that generates a report for the given group IDs.

    Args:
        group_ids (list): List of group IDs.
        days (int): Number of days to consider for the report.
        cbw_conf (str): Configuration for the report.
        env_conf_file (str): Path to the environmental configuration file.
        flag_split (bool, optional): Flag indicating whether to split the report. Defaults to False.
    """
    capec_data = parse_capec_xml_to_dict("assets/capec_v3.9.xml")
    cwes_data = parse_cwe_xml_to_dict("assets/cwec_v4.13.xml")
    environmental_configuration = load(env_conf_file) if env_conf_file else {}
    if not os.path.exists("output"):
        os.makedirs("output")
        os.chmod("output", 0o777)
    for group in group_ids:
        generate_report(
            group,
            date_from=date_from,
            date_to=date_to,
            capec_data=capec_data,
            cwes_data=cwes_data,
            environmental_configuration=environmental_configuration,
            configuration_cyberwatch=cbw_conf,
            flag_split=flag_split,
        )


if __name__ == "__main__":
    args = sys.argv[1:]
    group_ids = []
    instance = ""
    group_list_flag = False
    flag_split = False
    env_conf_file = ""
    date_from = None
    date_to = None
    if len(args) == 0:
        help()
    for i in range(len(args)):
        if args[i] in ["-h", "--help"]:
            help()
        elif args[i] in ["-g", "--group"]:
            group_ids = args[i + 1]
            if "," in group_ids:
                group_ids = [int(x) for x in group_ids.split(",")]
            else:
                group_ids = [int(group_ids)]
        elif args[i] in ["-i", "--instance"]:
            instance = args[i + 1]
        elif args[i] in ["-c", "--config"]:
            env_conf_file = args[i + 1]
        elif args[i] in ["-l", "--list"]:
            group_list_flag = True
        elif args[i] in ["-s, --split"]:
            flag_split = True
        elif args[i] in ["-from"]:
            try:
                date_from = parse_date(args[i + 1])
            except ValueError as e:
                logger.error("Error parsing date from", exc_info=e)
                sys.exit(1)
        elif args[i] in ["-to"]:
            try:
                date_to = parse_date(args[i + 1])
            except ValueError as e:
                logger.error("Error parsing date to", exc_info=e)
                sys.exit(1)
        env = parse("environement/.env")
    cbw_conf = {
        "host": instance,
        "user": env["DB_USER"],
        "password": env["DB_PASSWORD"],
        "database": env["DB_NAME"],
    }
    if group_list_flag:
        list_group(cbw_conf)
        exit()
    if not len(group_ids):
        print("Group id is required")
        help()
    if not env_conf_file:
        print("#####################################################")
        print(
            "You have no environmental configuration file specified\nThis will generate a CVE Report without any environmentals vectors."
        )
        print(
            "To specify an environmental configuration file, use `-c path/to/config/file`"
        )
        print(
            "Some environmental configuration files are already defined in `./environments/xyz.json`"
        )
        print("#####################################################")
        answer = None
        while answer != "" and answer != "Y" and answer != "y" and answer != "n":
            answer = input(
                "Continue without environmental configuration file ? Y/n: "
            ).strip()
            if answer == "n":
                exit()

    main(
        group_ids,
        date_from,
        date_to,
        cbw_conf,
        env_conf_file,
        flag_split,
    )
