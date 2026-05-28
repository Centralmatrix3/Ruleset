#!/usr/bin/env python3

import sys
import json
import shutil
import argparse
from pathlib import Path
from collections import defaultdict


EGERN_RULE_MAP = {
    "DOMAIN": "domain_set",
    "DOMAIN-SUFFIX": "domain_suffix_set",
    "DOMAIN-KEYWORD": "domain_keyword_set",
    "DOMAIN-WILDCARD": "domain_wildcard_set",
    "IP-CIDR": "ip_cidr_set",
    "IP-CIDR6": "ip_cidr6_set",
    "IP-ASN": "asn_set",
    "GEOIP": "geoip_set"
}
EGERN_RULE_QUOTE = {"domain_wildcard_set"}


SINGBOX_RULE_MAP = {
    "DOMAIN": "domain",
    "DOMAIN-SUFFIX": "domain_suffix",
    "DOMAIN-KEYWORD": "domain_keyword",
    "IP-CIDR": "ip_cidr",
    "IP-CIDR6": "ip_cidr"
}


def process_source():
    source_path = Path("ios_rule_script/rule/Clash")
    target_config = {Path("Egern"): ".yaml", Path("Singbox"): ".json"}
    for target_path in target_config:
        if target_path.exists():
            shutil.rmtree(target_path)
        target_path.mkdir(parents=True, exist_ok=True)
    for source_file in source_path.rglob("*.list"):
        relative_path = source_file.relative_to(source_path)
        for target_root, suffix in target_config.items():
            target_file = target_root / relative_path.with_suffix(suffix)
            target_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(source_file, target_file)
            print(f"Copied {source_file} -> {target_file}")


def content_read(file_path: Path):
    rule_data = []
    for raw_line in file_path.read_text(encoding="utf-8").splitlines():
        raw_line = raw_line.strip()
        if not raw_line or raw_line.startswith("#"):
            continue
        rule_data.append(tuple((raw_line.split(",", 2) + ["", ""])[:3]))
    return rule_data


def content_write(file_path, rule_name, rule_count, rule_data, platform):
    with file_path.open("w", encoding="utf-8", newline="\n") as file:
        if platform == "Singbox":
            file.write(json.dumps(rule_data, indent=2, ensure_ascii=False) + "\n")
        else:
            file.write(f"# 规则名称: {rule_name}\n")
            file.write(f"# 规则统计: {rule_count}\n\n")
            file.writelines(f"{line}\n" for line in rule_data)
    print(f"Processed ({platform}): {file_path}")


def convert_egern(file_path: Path):
    rule_name = file_path.stem
    rule_dict = defaultdict(list)
    no_resolve = False
    for style, value, param in content_read(file_path):
        no_resolve |= param == "no-resolve"
        if style in EGERN_RULE_MAP:
            rule_type = EGERN_RULE_MAP[style]
            rule_value = f"'{value}'" if rule_type in EGERN_RULE_QUOTE else value
            rule_dict[rule_type].append(rule_value)
    output = ["no_resolve: true"] if no_resolve else []
    for rule_type, rule_data in rule_dict.items():
        output.append(f"{rule_type}:")
        output.extend(f"  - {value}" for value in rule_data)
    rule_count = sum(line.startswith("  - ") for line in output)
    content_write(file_path, rule_name, rule_count, output, "Egern")
    platform_root = next(path for path in file_path.parents if path.name == "Egern")
    relative_yaml = file_path.relative_to(platform_root.parent)
    readme_file = file_path.parent / "readme.md"
    with readme_file.open("w", encoding="utf-8", newline="\n") as f:
        f.write(f"# 🧸 {rule_name}\n\n")
        f.write(f"https://raw.githubusercontent.com/Centralmatrix3/Ruleset/master/{relative_yaml.as_posix()}")


def convert_singbox(file_path: Path):
    rule_name = file_path.stem
    rule_dict = defaultdict(list)
    for style, value, param in content_read(file_path):
        if style in SINGBOX_RULE_MAP:
            rule_type = SINGBOX_RULE_MAP[style]
            rule_dict[rule_type].append(value)
    rule_data = [{rule_type: value} for rule_type, value in rule_dict.items()]
    output = {"version": 3, "rules": rule_data}
    content_write(file_path, None, None, output, "Singbox")
    platform_root = next(path for path in file_path.parents if path.name == "Singbox")
    relative_json = file_path.relative_to(platform_root.parent)
    relative_srs = file_path.with_suffix(".srs").relative_to(platform_root.parent)
    readme_file = file_path.parent / "readme.md"
    with readme_file.open("w", encoding="utf-8", newline="\n") as f:
        f.write(f"# 🧸 {rule_name}\n\n")
        f.write(f"https://raw.githubusercontent.com/Centralmatrix3/Ruleset/master/{relative_json.as_posix()}\n\n")
        f.write(f"https://raw.githubusercontent.com/Centralmatrix3/Ruleset/master/{relative_srs.as_posix()}")


def parse_arguments():
    parser = argparse.ArgumentParser("Rule Build")
    parser.add_argument("platform", choices=["Source", "Egern", "Singbox"])
    parser.add_argument("file_path", nargs="?", type=Path)
    return parser.parse_args()


def main():
    args = parse_arguments()
    if args.platform == "Source":
        process_source()
        print("Processed Completed.")
        return
    if not args.file_path or not args.file_path.exists():
        sys.exit(f"{args.file_path} Not Found or Unknown Type.")
    convert_function = {
        "Egern": convert_egern,
        "Singbox": convert_singbox,
    }[args.platform]
    process_file = (
        [args.file_path]
        if args.file_path.is_file()
        else sorted(file for file in args.file_path.rglob("*") if file.is_file())
    )
    if not process_file:
        print(f"No File Found in: {args.file_path}")
        return
    for file_path in process_file:
        try:
            convert_function(file_path)
        except Exception as error:
            print(f"Failed to Process {file_path}: {error}")
    print("Processed Completed.")


if __name__ == "__main__":
    main()