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
    "IP-ASN": "asn_set"
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
    egern_path, singbox_path = Path("Egern"), Path("Singbox")
    for path in (egern_path, singbox_path):
        if path.exists():
            shutil.rmtree(path)
        path.mkdir(parents=True, exist_ok=True)
    for source_file in source_path.rglob("*.list"):
        relative_path = source_file.relative_to(source_path)
        for base, suffix in ((egern_path, ".yaml"), (singbox_path, ".json")):
            target_path = base / relative_path.with_suffix(suffix)
            target_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(source_file, target_path)
            print(f"Copied {source_file} -> {target_path}")

def content_read(file_path: Path):
    rule_data = []
    for raw_line in file_path.read_text(encoding="utf-8").splitlines():
        raw_line = raw_line.strip()
        if not raw_line or raw_line.startswith("#"):
            continue
        rule = raw_line.split(",", 2)
        while len(rule) < 3:
            rule.append("")
        rule_data.append(tuple(rule[:3]))
    return rule_data

def content_write(file_path, rule_name, rule_count, rule_data, platform):
    with file_path.open("w", encoding="utf-8", newline="\n") as f:
        if platform == "Singbox":
            f.write(json.dumps(rule_data, indent=2, ensure_ascii=False) + "\n")
        else:
            f.write(f"# 规则名称: {rule_name}\n")
            f.write(f"# 规则统计: {rule_count}\n\n")
            f.writelines(f"{line}\n" for line in rule_data)
    if platform:
        print(f"Processed ({platform}): {file_path}")

def convert_egern(file_path: Path):
    rule_name = file_path.stem
    rule_dict = defaultdict(list)
    no_resolve = False
    for style, value, field in content_read(file_path):
        no_resolve |= field == "no-resolve"
        if style in EGERN_RULE_MAP:
            rule_type = EGERN_RULE_MAP[style]
            rule_value = f'"{value}"' if rule_type in EGERN_RULE_QUOTE else value
            rule_dict[rule_type].append(rule_value)
    output = ["no_resolve: true"] if no_resolve else []
    for rule_type, rule_data in rule_dict.items():
        output.append(f"{rule_type}:")
        output.extend(f"  - {value}" for value in rule_data)
    rule_count = sum(line.startswith("  - ") for line in output)
    content_write(file_path, rule_name, rule_count, output, platform="Egern")
    platform_root = next(p for p in file_path.parents if p.name == "Egern")
    relative_yaml = file_path.relative_to(platform_root.parent)
    readme_file = file_path.parent / "readme.md"
    with readme_file.open("w", encoding="utf-8", newline="\n") as f:
        f.write(f"# 🧸 {rule_name}\n\n")
        f.write(f"https://raw.githubusercontent.com/Centralmatrix3/Ruleset/master/{relative_yaml.as_posix()}")

def convert_singbox(file_path: Path):
    rule_name = file_path.stem
    rule_dict = defaultdict(list)
    for style, value, field in content_read(file_path):
        if style in SINGBOX_RULE_MAP:
            rule_type = SINGBOX_RULE_MAP[style]
            rule_dict[rule_type].append(value)
    rule_data = [{rule_type: value} for rule_type, value in rule_dict.items()]
    output = {"version": 3, "rules": rule_data}
    content_write(file_path, None, None, output, platform="Singbox")
    platform_root = next(p for p in file_path.parents if p.name == "Singbox")
    relative_json = file_path.relative_to(platform_root.parent)
    relative_srs = file_path.with_suffix(".srs").relative_to(platform_root.parent)
    readme_file = file_path.parent / "readme.md"
    with readme_file.open("w", encoding="utf-8") as f:
        f.write(f"# 🧸 {rule_name}\n\n")
        f.write(f"https://raw.githubusercontent.com/Centralmatrix3/Ruleset/master/{relative_json.as_posix()}\n\n")
        f.write(f"https://raw.githubusercontent.com/Centralmatrix3/Ruleset/master/{relative_srs.as_posix()}")

def main():
    parser = argparse.ArgumentParser("Rule Convert Svript")
    parser.add_argument("platform", choices=["Source", "Egern", "Singbox"])
    parser.add_argument("file_path", nargs="?", type=Path)
    args = parser.parse_args()
    convert_function = {
        "Source": lambda _: process_source(),
        "Egern": convert_egern, "Singbox": convert_singbox
    }[args.platform]
    if args.platform == "Source":
        convert_function(None)
    else:
        path = args.file_path
        if not path or not path.exists():
            sys.exit(f"{path} Not Found or Unknown Type.")
        file_to_process = [path] if path.is_file() else sorted(f for f in path.rglob("*") if f.is_file())
        if not file_to_process:
            print(f"No File Found in: {path}")
            return
        for f in file_to_process:
            try:
                convert_function(f)
            except Exception as e:
                print(f"Failed to Process {f}: {e}")
    print("Processed Completed.")

if __name__ == "__main__":
    main()