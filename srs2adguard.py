#!/usr/bin/env python3
"""
Script:
1. Reads an input file containing lines in the format geosite_<name> / geoip_<name>.
2. Downloads .srs files:
   - geosite_*  -> https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/<value>.srs
   - geoip_*    -> https://raw.githubusercontent.com/Loyalsoldier/geoip/release/srs/<value without geoip_>.srs
   By default .srs files saves into srs directory.
3. Decompiles each srs/*.srs file into JSON.
   By default .json files saves into json directory.
4. Compiles the final list for AdGuard VPN from all json/*.json files using jq and saves it in output file.
   By default output filename is adguard-exclusions.txt.

Requires:
1. sing-box
2. jq
"""

import argparse
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

GEOSITE_URL_TEMPLATE = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/{value}.srs"
GEOIP_URL_TEMPLATE = "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/srs/{name}.srs"

DEFAULT_SRS_DIR = Path("srs")
DEFAULT_JSON_DIR = Path("json")
DEFAULT_OUTPUT_FILE = Path("adguard-exclusions.txt")

SINGBOX_BIN = "sing-box"
JQ_BIN = "jq"

JQ_FILTER = '.rules[] | (.domain[]?, (.domain_suffix[]? | ltrimstr(".") | ., "*." + .), .ip_cidr[]?)'


def download_srs(url: str, dest: Path) -> None:
    """Download file from url and save into dest."""
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            status = getattr(response, "status", response.getcode())
            if status != 200:
                raise RuntimeError(f"Request to {url} finished with code {status}")
            data = response.read()
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Request to {url} finished with code {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Failed to execute request to {url}: {exc.reason}") from exc

    dest.write_bytes(data)
    print(f"[OK] Downloaded: {url} -> {dest}")


def process_input_file(input_path: Path, srs_dir: Path) -> None:
    """Downloads .srs files specified in the input_path to the srs_dir"""
    srs_dir.mkdir(parents=True, exist_ok=True)

    with input_path.open("r", encoding="utf-8") as f:
        for raw_line in f:
            value = raw_line.strip()

            if not value:
                continue

            if value.startswith("geosite"):
                url = GEOSITE_URL_TEMPLATE.format(value=value)
                dest = srs_dir / f"{value}.srs"
            elif value.startswith("geoip"):
                name = value[len("geoip_"):]
                url = GEOIP_URL_TEMPLATE.format(name=name)
                dest = srs_dir / f"{value}.srs"
            else:
                print(f"[WARN] String doesn't have geosite/geoip prefix, skipped: {value}")
                continue

            download_srs(url, dest)


def decompile_srs_files(srs_dir: Path, json_dir: Path) -> None:
    """Decompiles .srs files from srs_dir into json and saves them in json_dir"""
    json_dir.mkdir(parents=True, exist_ok=True)

    srs_files = sorted(srs_dir.glob("*.srs"))
    if not srs_files:
        print(f"[WARN] No .srs files in {srs_dir} directory, sing-box will not be launched")
        return

    for srs_file in srs_files:
        json_file = json_dir / f"{srs_file.stem}.json"
        cmd = [SINGBOX_BIN, "rule-set", "decompile", str(srs_file), "-o", str(json_file)]
        print(f"[RUN] {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            raise RuntimeError(f"Decompilation error in file {srs_file}:\n{result.stderr}")


def build_adguard_list(output_file: Path, json_dir: Path) -> None:
    """Generates list of domains and IPs stored in .json files and saves it to output_file"""
    json_files = sorted(json_dir.glob("*.json"))
    if not json_files:
        print(f"[WARN] No .json files in {json_dir} directory, jq will not be launched")
        return

    cmd = [JQ_BIN, "-r", JQ_FILTER] + [str(f) for f in json_files]
    print(f"[RUN] {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.returncode != 0:
        raise RuntimeError(f"jq execution error:\n{result.stderr}")
        
    lines = {line for line in result.stdout.splitlines() if line.strip()}
        
    with output_file.open("a", encoding="utf-8") as f:
        for line in sorted(lines):
            f.write(line + "\n")

    print(f"[OK] Result saved into {output_file}")
    
    
def create_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Download .srs sing-box rules and convert it to domain/ip list for AdGuard VPN."
    )
    parser.add_argument(
        "input_file",
        help="File with rules like geosite_<name> / geoip_<name>"
    )
    parser.add_argument(
        "-o",
        "--output",
        default=str(DEFAULT_OUTPUT_FILE),
        help=f"Output filename (default: {DEFAULT_OUTPUT_FILE})",
    )
    parser.add_argument(
        "-s",
        "--srs_dir",
        default=str(DEFAULT_SRS_DIR),
        help=f"Directory for .srs files (default: {DEFAULT_SRS_DIR})",
    )
    parser.add_argument(
        "-j",
        "--json_dir",
        default=str(DEFAULT_JSON_DIR),
        help=f"Directory for .json files (default: {DEFAULT_JSON_DIR})",
    )
    return parser


def main() -> None:
    parser = create_argument_parser()
    args = parser.parse_args()

    input_path = Path(args.input_file)
    if not input_path.is_file():
        print(f"File not found: {input_path}")
        sys.exit(1)
        
    output_file = Path(args.output)
    srs_dir     = Path(args.srs_dir)
    json_dir    = Path(args.json_dir)

    try:
        process_input_file(input_path, srs_dir)
        decompile_srs_files(srs_dir, json_dir)
        build_adguard_list(output_file, json_dir)
    except RuntimeError as exc:
        print(f"[ERROR] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
