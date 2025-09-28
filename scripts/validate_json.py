import json, sys
from pathlib import Path
from jsonschema import validate, Draft202012Validator

def load(p): return json.loads(Path(p).read_text(encoding="utf-8"))

def main():
    try:
        scanner = load("data/scan_results_raw.json")
        mapper = load("data/mapper_final_results.json")
        sch_s = load("schemas/scanner.schema.json")
        sch_m = load("schemas/mapper.schema.json")
        Draft202012Validator.check_schema(sch_s)
        Draft202012Validator.check_schema(sch_m)
        validate(scanner, sch_s)
        validate(mapper, sch_m)
        print("OK: JSON schema validation passed")
    except Exception as e:
        print("JSON schema validation failed:", e)
        sys.exit(1)

if __name__ == "__main__":
    main()
