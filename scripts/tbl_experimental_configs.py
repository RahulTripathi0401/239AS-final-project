#!/usr/bin/env python3
from artifact_utils import FIGURES, write_csv, write_tex_table


def main() -> None:
    rows = [
        {"Detector": "Random forest", "Configuration": "18 numeric + char TF-IDF; 80/20 test"},
        {"Detector": "Regex harness", "Configuration": "decoded fields + callbacks; 80/20 test"},
    ]
    write_csv(FIGURES / "tbl_experimental_configs.csv", rows)
    write_tex_table(FIGURES / "tbl_experimental_configs.tex", ["Detector", "Configuration"], [[r["Detector"], r["Configuration"]] for r in rows])


if __name__ == "__main__":
    main()
