from pathlib import Path
from typing import List


def load_lines_from_file(p: Path, encoding='ascii') -> List[str]:
    with open(p, 'r', encoding=encoding) as f:
        return f.readlines()