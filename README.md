# nmap-converter-ng

Python script for converting nmap scan reports into XLSX or CSV.

This is a rewritten and modernized version of the old `nmap-converter.py`:
the abandoned `python-libnmap` dependency is gone, `.gnmap` and `.nmap`
(text output) input formats were added, along with a CSV output mode.

# Supported input formats

- `.xml` — nmap XML report (`-oX` / `-oA`)
- `.gnmap` — nmap grepable report (`-oG` / `-oA`)
- `.nmap` — nmap plain text report (`-oN`, best effort)

The format is detected by file extension, falling back to content sniffing.
Multiple files can be converted in a single run, mixing formats freely.

# Requirements

- Python 3.8+
- `xlsxwriter` — only needed for XLSX output:

```bash
pip install xlsxwriter
```

or

```bash
pip install -r requirements.txt
```

CSV output works with no dependencies at all (stdlib only).

# Usage

```bash
usage: nmap-converter.py [-h] [-o FILE] [-f {xlsx,csv,auto}] REPORT [REPORT ...]

positional arguments:
  REPORT                path to nmap report (xml, nmap or gnmap;
                        format is auto-detected)

options:
  -h, --help            show this help message and exit
  -o FILE, --output FILE
                        path to output file (default:
                        converted.xlsx or converted.csv)
  -f, --format {xlsx,csv,auto}
                        output format (default: auto — derived from
                        the output file extension, otherwise xlsx)
```

# Examples

```bash
# XML -> XLSX
./nmap-converter.py -o report.xlsx scan.xml

# gnmap -> CSV
./nmap-converter.py -o report.csv scan.gnmap
./nmap-converter.py -f csv -o report scan.gnmap     # same thing

# Mix several reports of different formats
./nmap-converter.py -o report.xlsx scan1.xml scan2.gnmap scan3.nmap
```

The XLSX workbook contains **Summary** (scan metadata), **Hosts** (hosts and
OS) and **Results** (ports/services) sheets. The CSV output contains the same
Results columns (plus a Report column) in a single file.

# Русская версия

См. [README.ru.md](README.ru.md).
