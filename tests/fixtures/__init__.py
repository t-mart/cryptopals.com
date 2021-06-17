from pathlib import Path


FIXTURE_ROOT = Path(__file__).parent


def data_file_path(file_name: str) -> Path:
    return FIXTURE_ROOT / file_name


def data_file_lines(file_name: str) -> list[str]:
    path = data_file_path(file_name)

    with path.open("r") as data_file:
        return [line.strip() for line in data_file]


def data_file_contents(file_name: str) -> str:
    path = data_file_path(file_name)

    with path.open("r") as data_file:
        return "".join(line.strip() for line in data_file)
