#!/usr/bin/env python3
from artifact_utils import FIGURES, ML_RUNTIME, read_csv, write_csv, write_tex_table


def main() -> None:
    ml_runtime = float(read_csv(ML_RUNTIME)[0]["runtime_seconds"])
    rows = [
        {"Pipeline": "Regex harness", "Time": "2.78 s"},
        {"Pipeline": "Reproduced ML baseline", "Time": f"{ml_runtime:.2f} s"},
        {"Pipeline": "Reproduced ML baseline wall clock", "Time": "63.52 s"},
    ]
    write_csv(FIGURES / "tbl_runtime.csv", rows)
    write_tex_table(FIGURES / "tbl_runtime.tex", ["Pipeline", "Time"], [[r["Pipeline"], r["Time"]] for r in rows])


if __name__ == "__main__":
    main()
