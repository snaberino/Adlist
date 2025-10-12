import re
from urllib.parse import urlparse

from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
import io
import gzip
import sys

from typing import Tuple, Dict

import pathlib

# --- URL hardcodati ---
SOURCES = [
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
    "https://blocklistproject.github.io/Lists/tracking.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.xiaomi.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.vivo.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.roku.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.lgwebos.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.tiktok.extended.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.tiktok.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.samsung.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.winoffice.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.huawei.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.apple.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.amazon.txt",
    "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
    "https://hostfiles.frogeye.fr/firstparty-trackers-hosts.txt",
    "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/android-tracking.txt",
    "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt",
    "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/AmazonFireTV.txt",
    "https://www.github.developerdan.com/hosts/lists/ads-and-tracking-extended.txt",
    "https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Formats/GoodbyeAds-YouTube-AdBlock-Filter.txt",
    "https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Extension/GoodbyeAds-Samsung-AdBlock.txt",
    "https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Extension/GoodbyeAds-Xiaomi-Extension.txt",
    "https://raw.githubusercontent.com/jerryn70/GoodbyeAds/master/Hosts/GoodbyeAds.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt",
    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_4_Social/filter.txt",
    "https://easylist.to/easylist/easyprivacy.txt",
    "https://big.oisd.nl/"
]

# regex per validare un dominio
DOMAIN_REGEX = re.compile(r"^(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.IGNORECASE)

def normalize_line(line: str) -> str | None:
    """
    Prende una riga da una blocklist e restituisce il dominio normalizzato.
    Restituisce None se la riga non contiene un dominio valido.
    """
    raw = line.strip()
    if not raw:
        return None

    # commenti e eccezioni adblock
    if raw.startswith(("#", "!", "@@")):
        return None

    # gestisci formati hosts (0.0.0.0 domain)
    for prefix in ("0.0.0.0 ", "127.0.0.1 ", "::1 ", ":: "):
        if raw.startswith(prefix):
            parts = raw.split()
            if len(parts) >= 2:
                raw = parts[-1]
                break

    # gestisci formati Adblock (||domain^ o |https://domain^)
    if raw.startswith(("||", "|")):
        # rimuovi eventuali | iniziali
        raw = raw.lstrip("|")
        # tronca a eventuale delimitatore
        for c in ("^", "/", "?", "#"):
            if c in raw:
                raw = raw.split(c, 1)[0]
        # se include schema, estrai host
        if raw.startswith(("http://", "https://")):
            host = urlparse(raw).hostname
            raw = host if host else raw

    # rimuovi punti iniziali/finali e forzalo lowercase
    domain = raw.strip().lower().strip(".")
    # escludi localhost
    if domain in ("localhost", "broadcasthost", "localhost.localdomain"):
        return None

    # validazione dominio
    if DOMAIN_REGEX.match(domain):
        return domain
    return None

def _fetch_text(source: str, timeout: int = 45) -> str:
    """
    Restituisce il contenuto testuale della sorgente (URL http/https o path file).
    Gestisce automaticamente gzip su HTTP.
    """
    if source.startswith(("http://", "https://")):
        req = Request(source, headers={"User-Agent": "blocklist-merger/1.0", "Accept-Encoding": "gzip"})
        try:
            with urlopen(req, timeout=timeout) as resp:
                data = resp.read()
                # decompressione trasparente se Content-Encoding: gzip
                if resp.headers.get("Content-Encoding", "").lower() == "gzip":
                    with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
                        return gz.read().decode("utf-8", errors="ignore")
                # altrimenti prova a decodificare direttamente
                return data.decode("utf-8", errors="ignore")
        except HTTPError as e:
            raise RuntimeError(f"HTTP error {e.code} su {source}") from e
        except URLError as e:
            raise RuntimeError(f"Errore di rete su {source}: {e.reason}") from e
    else:
        # file locale
        with open(source, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()

def load_list(source: str) -> set[str]:
    """
    Carica una lista (da URL o file), normalizza ogni riga e
    restituisce un set di domini unici.
    """
    text = _fetch_text(source)
    domains: set[str] = set()
    skipped = 0

    for line in text.splitlines():
        d = normalize_line(line)
        if d:
            domains.add(d)
        else:
            skipped += 1

    # log minimale (puoi rimuoverlo o sostituirlo con logging)
    print(f"- Caricata: {source}\n  -> domini unici: {len(domains):,} | righe scartate: {skipped:,}", file=sys.stderr)
    return domains

def merge_one_source(acc: set[str], source: str) -> Tuple[set[str], Dict[str, int]]:
    """
    Unisce in modo incrementale i domini normalizzati di `source` nell'accumulatore `acc`.
    Ritorna l'acc aggiornato e alcune statistiche utili.
    """
    current = load_list(source)          # set normalizzato della sorgente
    before = len(acc)
    new_entries = current - acc          # ciò che non è già presente
    duplicates = len(current) - len(new_entries)

    acc |= current                       # unione effettiva

    stats = {
        "before": before,
        "added": len(new_entries),
        "duplicates": duplicates,
        "after": len(acc),
    }
    return acc, stats

# --- Salvataggio/Caricamento stato (solo domini) ---
def save_domains(path: str | pathlib.Path, domains: set[str]) -> None:
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        for d in sorted(domains):
            f.write(d + "\n")
    tmp.replace(p)

def load_domains(path: str | pathlib.Path) -> set[str]:
    p = pathlib.Path(path)
    if not p.exists():
        return set()
    out: set[str] = set()
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            d = line.strip().lower()
            if DOMAIN_REGEX.match(d):
                out.add(d)
    return out

# --- Scrittura output hosts ---
def write_hosts(path: str | pathlib.Path, domains: set[str], ip: str = "0.0.0.0") -> None:
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        for d in sorted(domains):
            f.write(f"{ip} {d}\n")
    tmp.replace(p)

# --- Orchestratore ---
def main():
    out_dir = pathlib.Path("output")
    out_domains = out_dir / "merged.domains"
    out_hosts = out_dir / "merged.hosts"
    ip = "0.0.0.0"

    acc = load_domains(out_domains)
    print(f"Stato iniziale: {len(acc):,} domini", file=sys.stderr)

    for src in SOURCES:
        acc, stats = merge_one_source(acc, src)
        print(f"• {src}: +{stats['added']:,} (dup: {stats['duplicates']:,}) → {stats['after']:,}", file=sys.stderr)
        save_domains(out_domains, acc)   # salva dopo ogni lista (come richiesto)

    write_hosts(out_hosts, acc, ip=ip)
    print(f"\nOK. Totale domini: {len(acc):,}\n- Stato: {out_domains}\n- Hosts: {out_hosts} (IP {ip})")

if __name__ == "__main__":
    main()