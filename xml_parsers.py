import xml.etree.ElementTree as ET
from logger import setup_logger

logger = setup_logger(__name__)


def xml_data(element, data, ns):
    _data = element.find(data, ns)
    return _data.text.strip() if _data is not None and _data.text else None


def normalize_capec_data(element):
    return "".join(
        [
            element.text.strip() if element.text else "",
            "".join([child.text.strip() if child.text else "" for child in element]),
        ]
    )


def parse_capec_xml_to_dict(filename):
    tree = ET.parse(filename)
    root = tree.getroot()
    namespaces = {
        "capec": "http://capec.mitre.org/capec-3",
        "xhtml": "http://www.w3.org/1999/xhtml",
    }
    capec_data = {}
    for atk_pattern in root.findall(f".//capec:Attack_Pattern", namespaces):
        # Parse the data
        # There is three types of data: attributes, text and children
        # Attributes are parsed using the get method
        #   <Attack_Pattern ID="1> -> atk_pattern.get("ID")
        # Text is parsed using the text attribute
        #   <Description>Some text</Description> -> atk_pattern.find("capec:Description", namespaces).text
        # Children are parsed using generators and methods above
        #   <Related_Attack_Patterns>
        #       <Related_Attack_Pattern Nature="ChildOf" CAPEC_ID="122"/>
        #       <Related_Attack_Pattern Nature="ChildOf" CAPEC_ID="123"/>
        #   </Related_Attack_Patterns>
        # -> [
        #       {
        #           "Nature": related_pattern.get("Nature"),
        #           "CAPEC_ID": related_pattern.get("CAPEC_ID"),
        #       }
        #   for related_pattern in atk_pattern.findall("capec:Related_Attack_Patterns/capec:Related_Attack_Pattern", namespaces)
        #   ]
        try:
            related_attack_patterns = [
                {
                    "CAPEC_ID": related_pattern.get("CAPEC_ID"),
                    "Nature": related_pattern.get("Nature"),
                }
                for related_pattern in atk_pattern.findall(
                    "capec:Related_Attack_Patterns/capec:Related_Attack_Pattern",
                    namespaces,
                )
            ]
            execution_flow = [
                {
                    "Step": xml_data(step, "capec:Step", namespaces),
                    "Phase": xml_data(step, "capec:Phase", namespaces),
                    "Description": xml_data(step, "capec:Description", namespaces),
                    "Techniques": [
                        normalize_capec_data(technique)
                        for technique in step.findall("capec:Technique", namespaces)
                    ],
                }
                for step in atk_pattern.findall(
                    "capec:Execution_Flow/capec:Attack_Step", namespaces
                )
            ]
            mitigations = [
                normalize_capec_data(mitigation)
                for mitigation in atk_pattern.findall(
                    "capec:Mitigations/capec:Mitigation", namespaces
                )
            ]
            related_weaknesses = [
                related_weakness.get("CWE_ID")
                for related_weakness in atk_pattern.findall(
                    "capec:Related_Weaknesses/capec:Related_Weakness", namespaces
                )
            ]
            prerequisites = [
                normalize_capec_data(prerequisite)
                for prerequisite in atk_pattern.findall(
                    "capec:Prerequisites", namespaces
                )
            ]
            skills_required = [
                {
                    "Level": skill.get("Level"),
                    "Description": normalize_capec_data(skill),
                }
                for skill in atk_pattern.findall(
                    "capec:Skills_Required/capec:Skill", namespaces
                )
            ]
            resources_required = [
                normalize_capec_data(resource)
                for resource in atk_pattern.findall(
                    "capec:Resources_Required/capec:Resource", namespaces
                )
            ]
            consequences = [
                {
                    "Scope": xml_data(consequence, "capec:Scope", namespaces),
                    "Impact": [
                        normalize_capec_data(impact)
                        for impact in consequence.findall("capec:Impact", namespaces)
                    ],
                    "Note": xml_data(consequence, "Note", namespaces) or "None",
                }
                for consequence in atk_pattern.findall(
                    "capec:Consequences/capec:Consequence", namespaces
                )
            ]
            taxonomy_mappings = [
                {
                    "Taxonomy_Name": taxonomy.get("Taxonomy_Name"),
                    "ID": xml_data(taxonomy, "capec:Entry_ID", namespaces),
                    "Name": xml_data(taxonomy, "capec:Entry_Name", namespaces),
                }
                for taxonomy in atk_pattern.findall(
                    "capec:Taxonomy_Mappings/capec:Taxonomy_Mapping", namespaces
                )
            ]
            id = atk_pattern.get("ID")
            capec_data[id] = {
                "Name": atk_pattern.get("Name"),
                "Description": xml_data(atk_pattern, "capec:Description", namespaces),
                "Likelihood_Of_Attack": xml_data(
                    atk_pattern, "capec:Likelihood_Of_Attack", namespaces
                ),
                "Typical_Severity": xml_data(
                    atk_pattern, "capec:Typical_Severity", namespaces
                ),
                "Related_Attack_Patterns": related_attack_patterns,
                "Execution_Flow": execution_flow,
                "Mitigations": mitigations,
                "Related_Weaknesses": related_weaknesses,
                "Prerequisites": prerequisites,
                "Skills_Required": skills_required,
                "Resources_Required": resources_required,
                "Consequences": consequences,
                "Taxonomy_Mappings": taxonomy_mappings,
            }
        except Exception as e:
            logger.error(
                "Error parsing data for pattern",
                atk_pattern.get("ID"),
                "... ",
                exc_info=e,
            )

    return capec_data


def parse_cwe_xml_to_dict(filename):
    tree = ET.parse(filename)
    root = tree.getroot()
    namespaces = {
        "cwe": "http://cwe.mitre.org/cwe-7",
        "xhtml": "http://www.w3.org/1999/xhtml",
    }
    cwe_data = {}
    for weakness in root.findall(f".//cwe:Weakness", namespaces):
        try:
            related_weaknesses = [
                {
                    "CWE_ID": related_weakness.get("CWE_ID"),
                    "Nature": related_weakness.get("Nature"),
                }
                for related_weakness in weakness.findall(
                    "cwe:Related_Weaknesses/cwe:Related_Weakness", namespaces
                )
            ]
            cwe_data[weakness.get("ID")] = {
                "CWE_ID": weakness.get("ID"),
                "Name": weakness.get("Name"),
                "Description": xml_data(weakness, "cwe:Description", namespaces),
                "Extended_Description": xml_data(
                    weakness, "cwe:Extended_Description", namespaces
                ),
                "Related_Attack_Patterns": [
                    related_pattern.get("CAPEC_ID")
                    for related_pattern in weakness.findall(
                        "cwe:Related_Attack_Patterns/cwe:Related_Attack_Pattern",
                        namespaces,
                    )
                ],
                "Related_Weaknesses": related_weaknesses,
            }
        except Exception as e:
            logger.error(
                "Error parsing data for weakness",
                weakness.get("ID"),
                "... ",
                exc_info=True,
            )

    return cwe_data
