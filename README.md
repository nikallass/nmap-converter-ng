# nmap-converter-ng

Python-скрипт для конвертации отчётов nmap в XLSX или CSV.

Это переписанная и обновлённая версия старого `nmap-converter.py`: убрана
мёртвая зависимость `python-libnmap`, добавлены входные форматы
`.gnmap` и `.nmap` (текстовый вывод nmap) и CSV-режим вывода.

# Форматы входных файлов

- `.xml` — XML-отчёт nmap (`-oX` / `-oA`)
- `.gnmap` — grepable-отчёт (`-oG` / `-oA`)
- `.nmap` — обычный текстовый отчёт (`-oN`, best-effort)

Формат определяется по расширению, а для остальных файлов — по содержимому.
Можно передавать несколько файлов сразу (в одном обрабатываемом списке).

# Requirements

- Python 3.8+
- `xlsxwriter` — только для XLSX-вывода:

```bash
pip install xlsxwriter
```

или

```bash
pip install -r requirements.txt
```

CSV-вывод работает вообще без зависимостей (только stdlib).

# Usage

```bash
usage: nmap-converter.py [-h] [-o FILE] [-f {xlsx,csv,auto}] REPORT [REPORT ...]

positional arguments:
  REPORT                путь к отчёту nmap (xml, nmap или gnmap;
                        формат определяется автоматически)

options:
  -h, --help            show this help message and exit
  -o FILE, --output FILE
                        путь к выходному файлу (по умолчанию:
                        converted.xlsx или converted.csv)
  -f, --format {xlsx,csv,auto}
                        формат вывода (по умолчанию auto — берётся из
                        расширения выходного файла, иначе xlsx)
```

# Examples

```bash
# XML -> XLSX
./nmap-converter.py -o report.xlsx scan.xml

# gnmap -> CSV
./nmap-converter.py -o report.csv scan.gnmap
./nmap-converter.py -f csv -o report scan.gnmap     # то же самое

# Смешать несколько отчётов разных форматов
./nmap-converter.py -o report.xlsx scan1.xml scan2.gnmap scan3.nmap
```

XLSX содержит листы **Summary** (метаданные сканов), **Hosts** (хосты и ОС)
и **Results** (порты/сервисы). CSV содержит те же колонки Results
(с дополнительной колонкой Report) в одном файле.
