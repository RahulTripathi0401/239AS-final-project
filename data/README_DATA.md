# Data Provenance

This project uses the CSIC 2010 web-application attack dataset.

- Dataset page: <https://www.kaggle.com/datasets/ispangler/csic-2010-web-application-attacks>
- Local raw copy: `data/raw/csic_database.csv`
- Compatibility copy used by the original scripts: `project/csic_database.csv`
- Rows: 61,065 HTTP requests
- Labels: `classification=0` for normal requests and `classification=1` for anomalous requests

The committed CSV is small enough for this course artifact and is included so
the paper results can be reproduced without relying on Kaggle authentication.
If you want to recreate the file from Kaggle instead, download the dataset from
the page above and place `csic_database.csv` in both locations:

```bash
cp csic_database.csv data/raw/csic_database.csv
cp csic_database.csv project/csic_database.csv
```

No BigQuery or SQL setup is required for this project. The `data/sql/` directory
is intentionally empty.
