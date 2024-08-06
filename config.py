import json


def load(f):
    """
    Load data from a JSON file.

    Parameters:
    f (str): The file path of the JSON file to load.

    Returns:
    dict: The loaded data from the JSON file.
    """
    data = {}
    with open(f, "r") as file:
        try:
            data = json.load(file)
        except json.JSONDecodeError as e:
            raise json.JSONDecodeError(
                f"Error decoding '{f}': {e}", e.doc, e.pos
            ) from e
    return data


def parse(dotenv_path=".env"):
    """
    Parses the given dotenv file and returns a dictionary containing the environment variables.

    Args:
        dotenv_path (str): The path to the dotenv file. Defaults to ".env".

    Returns:
        dict: A dictionary containing the environment variables parsed from the dotenv file.

    Raises:
        FileNotFoundError: If the dotenv file is not found.
        Exception: If there is an error parsing the dotenv file.
    """
    env_dict = {}
    try:
        with open(dotenv_path, "r") as file:
            for line in file:
                stripped_line = line.strip()
                if stripped_line.startswith("#") or not stripped_line:
                    continue
                key, value = stripped_line.split("=", 1)
                value = value.strip().strip("'\"")
                env_dict[key] = value
    except FileNotFoundError as e:
        raise FileNotFoundError(f"Error: '{dotenv_path}' file not found.") from e
    except Exception as e:
        raise Exception(f"Error parsing '{dotenv_path}': {e}") from e

    return env_dict
