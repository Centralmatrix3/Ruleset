#!/usr/bin/env python3

import argparse
import dataclasses
import json
import shutil
import sys
from collections import defaultdict
from pathlib import Path

RULESET_BASE_URL = "https://raw.githubusercontent.com/Centralmatrix3/Ruleset/master"

PLATFORM_EXTENSION = {"Egern": ".yaml", "Singbox": ".json"}

EGERN_QUOTED_TYPE = {"DOMAIN-WILDCARD", "IP-ASN"}

RULE_TYPE_MAPPING = {
    "DOMAIN": {
        "Egern": "domain_set",
        "Singbox": "domain"
    },
    "DOMAIN-SUFFIX": {
        "Egern": "domain_suffix_set",
        "Singbox": "domain_suffix"
    },
    "DOMAIN-KEYWORD": {
        "Egern": "domain_keyword_set",
        "Singbox": "domain_keyword"
    },
    "DOMAIN-WILDCARD": {
        "Egern": "domain_wildcard_set"
    },
    "IP-CIDR": {
        "Egern": "ip_cidr_set",
        "Singbox": "ip_cidr"
    },
    "IP-CIDR6": {
        "Egern": "ip_cidr6_set",
        "Singbox": "ip_cidr"
    },
    "IP-ASN": {
        "Egern": "asn_set"
    },
    "GEOIP": {
        "Egern": "geoip_set"
    }
}
# ==================== #
@dataclasses.dataclass(slots=True)
class Rule:
    type: str
    value: str
    param: str = ""

@dataclasses.dataclass(slots=True)
class RuleSet:
    name: str
    rules: list[Rule]
    @property
    def total(self):
        return len(self.rules)
# ==================== #
def sync_source():
    source_path = Path("ios_rule_script/rule/Clash")
    for platform in PLATFORM_EXTENSION:
        target_path = Path(platform)
        if target_path.exists():
            shutil.rmtree(target_path)
        target_path.mkdir(parents=True, exist_ok=True)
    for source_file in source_path.rglob("*.list"):
        relative_path = source_file.relative_to(source_path)
        for platform, extension in PLATFORM_EXTENSION.items():
            target_file = Path(platform) / relative_path.with_suffix(extension)
            target_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(source_file, target_file)
            print(f"Copied: {source_file} -> {target_file}")
# ==================== #
def read_ruleset(file_path):
    rules = []
    with file_path.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            rule = Rule(*map(str.strip, (line.split(",", 2) + ["", ""])[:3]))
            rules.append(rule)
    return RuleSet(file_path.stem, rules)

def write_ruleset(file_path, ruleset, content, platform):
    with file_path.open("w", encoding="utf-8", newline="\n") as file:
        if platform == "Singbox":
            json.dump(content, file, indent=2, ensure_ascii=False)
            file.write("\n")
        else:
            file.write(f"# 规则名称: {ruleset.name}\n")
            file.write(f"# 规则统计: {ruleset.total}\n\n")
            file.writelines(f"{line}\n" for line in content)
    print(f"Processed ({platform}): {file_path}")
# ==================== #
def convert_rule(ruleset, target_platform):
    type_mapping = {}
    for rule_type, mapping in RULE_TYPE_MAPPING.items():
        if target_platform in mapping:
            type_mapping[rule_type] = mapping[target_platform]
    ruleset.rules = [rule for rule in ruleset.rules if rule.type in type_mapping]
    if target_platform == "Egern":
        rule_dict = defaultdict(list)
        for rule in ruleset.rules:
            rule_type = type_mapping[rule.type]
            rule_value = f"'{rule.value}'" if rule.type in EGERN_QUOTED_TYPE else rule.value
            rule_dict[rule_type].append(rule_value)
        output = []
        if any(rule.param == "no-resolve" for rule in ruleset.rules):
            output.append("no_resolve: true")
        for rule_type, rule_values in rule_dict.items():
            output.append(f"{rule_type}:")
            output.extend(f"  - {rule_value}" for rule_value in rule_values)
        return output
    if target_platform == "Singbox":
        rule_dict = defaultdict(list)
        for rule in ruleset.rules:
            rule_type = type_mapping[rule.type]
            rule_dict[rule_type].append(rule.value)
        output = {"version": 3, "rules": [dict(rule_dict)] if rule_dict else []}
        return output
    raise ValueError(f"Unknown Platform: {target_platform}")
# ==================== #
def write_readme(file_path, platform):
    platform_root = next(path for path in file_path.parents if path.name == platform)
    relative_file = file_path.relative_to(platform_root.parent)
    rule_links = [f"{RULESET_BASE_URL}/{relative_file.as_posix()}"]
    if platform == "Singbox":
        relative_srs = file_path.with_suffix(".srs").relative_to(platform_root.parent)
        rule_links.append(f"{RULESET_BASE_URL}/{relative_srs.as_posix()}")
    readme_file = file_path.parent / "readme.md"
    with readme_file.open("w", encoding="utf-8", newline="\n") as file:
        file.write(f"# 🧸 {file_path.stem}\n\n")
        file.write("\n\n".join(rule_links))
# ==================== #
def collect_files(file_path, platform):
    if not file_path.exists():
        raise FileNotFoundError(f"{file_path} Not Found.")
    if not file_path.is_file() and not file_path.is_dir():
        raise ValueError(f"{file_path} Unknown Type.")
    extension = PLATFORM_EXTENSION[platform]
    file_source = [file_path] if file_path.is_file() else file_path.rglob(f"*{extension}")
    files = []
    for file in file_source:
        if file.is_file() and file.suffix.lower() == extension:
            files.append(file)
    if not files:
        raise ValueError("No Supported File Found.")
    return sorted(files)

def process_files(file_path, platform):
    files = collect_files(file_path, platform)
    failed_files = []
    print(f"Platform: {platform}")
    print(f"Collected {len(files)} file(s)")
    for file in files:
        try:
            ruleset = read_ruleset(file)
            content = convert_rule(ruleset, platform)
            write_ruleset(file, ruleset, content, platform)
            write_readme(file, platform)
        except Exception as error:
            failed_files.append(file)
            print(f"Failed to Process {file}: {error}")
    if failed_files:
        raise RuntimeError(f"Processed Failed: {len(failed_files)} file(s).")
# ==================== #
def parse_arguments():
    parser = argparse.ArgumentParser(description="Rule Build")
    parser.add_argument("platform", nargs="?", choices=["Egern", "Singbox"])
    parser.add_argument("file_path", nargs="?", type=Path)
    return parser.parse_args()
# ==================== #
def main():
    try:
        args = parse_arguments()
        if args.platform:
            if not args.file_path:
                raise ValueError("No File Path Specified.")
            process_files(args.file_path, args.platform)
        else:
            sync_source()
        print("Processed Completed.")
    except Exception as error:
        sys.exit(error)

if __name__ == "__main__":
    main()
