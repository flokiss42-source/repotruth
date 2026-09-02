# Contributing

Every rule must be deterministic, explainable, and covered by at least one positive and one negative fixture. RepoTruth does not execute repository code during a scan.

Run the suite with:

```bash
python -m unittest discover -s tests -v
```

