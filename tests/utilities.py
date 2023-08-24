from pathlib import Path

def get_resource(path: str) -> str:
    base_path = Path(__file__).parent / "resources"
    target_path = base_path / path

    return target_path.read_text()