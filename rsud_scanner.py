#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
import sys
import os
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple

try:
    import requests
except Exception:
    print("Module 'requests' belum terpasang. Jalankan: pip install requests")
    raise

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    from rich.text import Text
except Exception:
    print("Module 'rich' belum terpasang. Jalankan: pip install rich")
    raise

# ---------------------------
# Banner
# ---------------------------
BANNER = r'''
  _____   _____ _    _ _____    __  __              _ ______ _   _          _   _  _____ 
 |  __ \ / ____| |  | |  __ \  |  \/  |   /\       | |  ____| \ | |   /\   | \ | |/ ____|
 | |__) | (___ | |  | | |  | | | \  / |  /  \      | | |__  |  \| |  /  \  |  \| | |  __ 
 |  _  / \___ \| |  | | |  | | | |\/| | / /\ \ _   | |  __| | . ` | / /\ \ | . ` | | |_ |
 | | \ \ ____) | |__| | |__| | | |  | |/ ____ \ |__| | |____| |\  |/ ____ \| |\  | |__| |
 |_|  \_\_____/ \____/|_____/  |_|  |_/_/    \_\____/|______|_| \_/_/    \_\_| \_|\_____|


                          Tools Security Directoary & Data Breach
                                     Author : @YogaGymn
'''

# ---------------------------
# Config
# ---------------------------
DIRECTORY_LIST_FILE = "directoary.txt"
DATABREACH_LIST_FILE = "databreach.txt"
DEFAULT_TIMEOUT = 8
MAX_WORKERS = 20

# Sites to scan for option 2
DATA_BREACH_SITES = [
    "https://google.com",
    "https://rsmajenang.cilacapkab.go.id/",
    "https://bangprima.rsmajenang.id/",
    "https://gajiku.rsmajenang.id/",
    "https://pacs.rsmajenang.id/",
    "https://report.rsmajenang.id/",
    "https://simbup.rsmajenang.id/",
    "https://simpas.rsmajenang.id/",
    "https://simpel-dev.rsmajenang.id/",
    "https://simpel.rsmajenang.id/",
    "https://simponitari-dev.rsmajenang.id/",
    "https://simponitari.rsmajenang.id/",
]

console = Console()

# ---------------------------
# Helper functions
# ---------------------------

def read_lines_strip(filename: str) -> List[str]:
    if not os.path.exists(filename):
        console.print(f"[bold red]File tidak ditemukan:[/] {filename}")
        return []
    with open(filename, "r", encoding="utf-8", errors="ignore") as f:
        lines = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    return lines

def make_url(base: str, path: str) -> str:
    base = base.strip()
    path = path.strip()
    if path.startswith("http://") or path.startswith("https://"):
        return path
    return urllib.parse.urljoin(base if base.endswith("/") else base + "/", path.lstrip("/"))

def http_get(url: str, timeout: int = DEFAULT_TIMEOUT) -> Tuple[int, str]:
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
        return resp.status_code, resp.reason
    except requests.exceptions.RequestException as e:
        return 0, str(e)

# ---------------------------
# Scanner Implementations
# ---------------------------

def scan_paths_on_target(target: str, paths: List[str], max_workers: int = MAX_WORKERS) -> List[dict]:
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_path = {}
        for p in paths:
            full_url = make_url(target, p)
            future = executor.submit(http_get, full_url)
            future_to_path[future] = (p, full_url)

        with Progress(SpinnerColumn(), TextColumn("{task.description}"), TimeElapsedColumn(),
                      console=console) as progress:
            task = progress.add_task("Scanning...", total=len(future_to_path))
            for future in as_completed(future_to_path):
                p, full_url = future_to_path[future]
                status, reason = future.result()
                entry = {"path": p, "url": full_url, "status": status, "reason": reason}
                results.append(entry)
                if 200 <= status < 300:
                    console.print(f"[green][{status}] {full_url}[/] - {reason}")
                elif 300 <= status < 400:
                    console.print(f"[cyan][{status}] {full_url}[/] - {reason} (redirect)")
                elif status >= 400:
                    console.print(f"[yellow][{status}] {full_url}[/] - {reason}")
                else:
                    console.print(f"[red][ERR] {full_url}[/] - {reason}")
                progress.update(task, advance=1)
    return results

def scan_databreach_sites(sites: List[str], breach_paths: List[str], max_workers: int = MAX_WORKERS) -> List[dict]:
    findings = []
    jobs = []
    for site in sites:
        for p in breach_paths:
            url = make_url(site, p)
            jobs.append((site, p, url))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_job = {executor.submit(http_get, job[2]): job for job in jobs}
        with Progress(SpinnerColumn(), TextColumn("{task.description}"), TimeElapsedColumn(),
                      console=console) as progress:
            task = progress.add_task("Scanning breaches...", total=len(future_to_job))
            for future in as_completed(future_to_job):
                site, p, url = future_to_job[future]
                status, reason = future.result()
                rec = {"site": site, "path": p, "url": url, "status": status, "reason": reason}
                findings.append(rec)
                if 200 <= status < 300:
                    console.print(f"[bold red][BREACH? {status}] {url}[/] -> {reason}")
                elif 300 <= status < 400:
                    console.print(f"[cyan][{status}] {url}[/] -> {reason}")
                elif 400 <= status < 500:
                    console.print(f"[yellow][{status}] {url}[/] -> {reason}")
                else:
                    console.print(f"[red][ERR] {url}[/] -> {reason}")
                progress.update(task, advance=1)
    return findings

# ---------------------------
# Presentation & Summary
# ---------------------------

def summarize_directory_results(results: List[dict]):
    table = Table(title="Hasil Scan Directory (Valid ditemukan di bawah)", show_lines=True)
    table.add_column("No", width=4)
    table.add_column("Path")
    table.add_column("URL")
    table.add_column("Status", width=8)
    table.add_column("Note")

    valid = []
    for i, r in enumerate(results, start=1):
        note = r.get("reason")
        status = r.get("status")
        table.add_row(str(i), r.get("path"), r.get("url"), str(status), str(note))
        if status and 200 <= status < 400:
            valid.append(r)

    console.print(table)
    console.rule("Hasil Valid (ringkasan)")
    if valid:
        vtable = Table(title="Valid Paths", show_lines=False)
        vtable.add_column("No", width=4)
        vtable.add_column("Path")
        vtable.add_column("URL")
        vtable.add_column("Status", width=8)
        for i, r in enumerate(valid, start=1):
            vtable.add_row(str(i), r.get("path"), r.get("url"), str(r.get("status")))
        console.print(vtable)
    else:
        console.print(Panel("Tidak ada hasil valid ditemukan.", style="green"))

def summarize_breach_results(findings: List[dict]):
    table = Table(title="Hasil Data Breach Scan (Detail)", show_lines=True)
    table.add_column("No", width=4)
    table.add_column("Site")
    table.add_column("Path")
    table.add_column("URL")
    table.add_column("Status", width=8)

    positives = []
    for i, f in enumerate(findings, start=1):
        table.add_row(str(i), f.get("site"), f.get("path"), f.get("url"), str(f.get("status")))
        if f.get("status") and 200 <= f.get("status") < 400:
            positives.append(f)

    console.print(table)
    console.rule("Hasil Valid (ringkasan)")
    if positives:
        v = Table(title="Potensi Kebocoran (status 2xx/3xx)")
        v.add_column("No", width=4)
        v.add_column("Site")
        v.add_column("Path")
        v.add_column("URL")
        v.add_column("Status", width=8)
        for i, p in enumerate(positives, start=1):
            v.add_row(str(i), p.get("site"), p.get("path"), p.get("url"), str(p.get("status")))
        console.print(v)
    else:
        console.print(Panel("Tidak ada indikasi kebocoran yang jelas (status 2xx/3xx).", style="green"))

# ---------------------------
# Main Menu
# ---------------------------

def main_menu():
    console.clear()
    console.print(Panel(Text(BANNER, justify="center"), style="bold blue"))

    console.print("[bold]Opsi:[/]")
    console.print("1. Scan Directoary")
    console.print("2. Data Breach")
    console.print("0. Keluar")

    choice = console.input("Pilih opsi (1/2/0): ")
    return choice.strip()

def run_scan_directory():
    console.print(Panel("[bold]Mode: Scan Directoary[/] - Ambil daftar dari directoary.txt"))
    paths = read_lines_strip(DIRECTORY_LIST_FILE)
    if not paths:
        console.print("[red]File directoary.txt kosong atau tidak ditemukan. Pastikan ada path di sana.")
        return
    target = console.input("Masukkan target (contoh: https://example.com): ")
    if not target:
        console.print("[red]Target wajib diisi.")
        return
    start = time.time()
    results = scan_paths_on_target(target, paths)
    end = time.time()
    console.print(f"Selesai dalam {end - start:.2f} detik.")
    summarize_directory_results(results)

def run_data_breach():
    console.print(Panel("[bold]Mode: Data Breach[/] - Ambil daftar dari databreach.txt"))
    paths = read_lines_strip(DATABREACH_LIST_FILE)
    if not paths:
        console.print("[red]File databreach.txt kosong atau tidak ditemukan. Pastikan ada path/pattern di sana.")
        return
    start = time.time()
    findings = scan_databreach_sites(DATA_BREACH_SITES, paths)
    end = time.time()
    console.print(f"Selesai dalam {end - start:.2f} detik.")
    summarize_breach_results(findings)

def main():
    while True:
        choice = main_menu()
        if choice == "1":
            run_scan_directory()
            console.input("Tekan ENTER untuk kembali ke menu utama...")
        elif choice == "2":
            run_data_breach()
            console.input("Tekan ENTER untuk kembali ke menu utama...")
        elif choice == "0":
            console.print("Keluar. Terima kasih.")
            break
        else:
            console.print("Pilihan tidak dikenali. Silakan pilih 1, 2, atau 0.")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        console.print("[yellow]Dihentikan oleh pengguna.[/]")
    except Exception as e:
        console.print(f"[bold red]Terjadi error:[/] {e}")
