#!/usr/bin/env python3
"""audit_domaine.py : audit e-mail d'un domaine (SPF, DMARC, DKIM, MTA-STS).
Usage : uv run audit_domaine.py exemple.fr [--json]
Bibliothèque standard seulement. Les requêtes DNS passent par dns.google (DNS over HTTPS).
Lecture seule : aucune donnée n'est envoyée ailleurs que ces requêtes DNS publiques."""
import json, re, sys, urllib.parse, urllib.request

SELECTEURS = ["default","google","selector1","selector2","k1","k2","k3","s1","s2","mail","dkim",
 "smtp","mandrill","mte1","mte2","scph0","scph1","pic","protonmail","protonmail2","protonmail3",
 "zoho","zmail","cm","mxvault","everlytickey1","everlytickey2","dk","email","key1","key2",
 "sig1","m1","mailo","brevo","mailjet","sendgrid","amazonses","ovh","ionos"]

def doh(nom, typ="TXT"):
    url = "https://dns.google/resolve?" + urllib.parse.urlencode({"name": nom, "type": typ})
    for _ in range(3):
        try:
            return json.load(urllib.request.urlopen(url, timeout=20))
        except Exception:
            pass
    return None

def txt(nom):
    r = doh(nom)
    if not r or "Answer" not in r:
        return []
    return [a["data"].replace('" "', "").strip('"') for a in r["Answer"] if a.get("type") == 16]

def spf(d):
    for v in txt(d):
        if re.match(r"v=spf1(\s|$)", v, re.I):
            return v
    return None

def cout_spf(d, vus=None, prof=0):
    """Requêtes DNS comptées selon RFC 7208 §4.6.4 (limite : 10). Retourne (n, notes)."""
    vus = vus if vus is not None else set()
    rec = spf(d)
    if rec is None:
        return 0, ["pas de SPF sur " + d]
    n, notes = 0, []
    for m in rec.split()[1:]:
        m2 = m.lstrip("+-~?").lower()
        if re.match(r"(include:|redirect=)", m2):
            n += 1
            cible = m2.split(":", 1)[1] if m2.startswith("include") else m2.split("=", 1)[1]
            if cible in vus or prof > 8:
                notes.append("boucle ou profondeur : " + cible)
                continue
            vus.add(cible)
            c, nn = cout_spf(cible, vus, prof + 1)
            n += c
            notes += nn
        elif re.match(r"(a|mx|ptr|exists)(:|/|$)", m2):
            n += 1
            if m2.startswith("mx"):
                n += 0  # les noms MX (jusqu'à 10) ont leur propre limite de 10 recherches : non comptés ici
            if m2.startswith("ptr"):
                notes.append("mécanisme ptr : déconseillé")
    return n, notes

def dmarc(d):
    for v in txt("_dmarc." + d):
        if re.match(r"v=DMARC1", v, re.I):
            return v
    return None

def dkim(d):
    trouves = []
    for s in SELECTEURS:
        for v in txt(f"{s}._domainkey.{d}"):
            if "p=" in v or "v=DKIM1" in v:
                trouves.append(s)
                break
    return trouves

def audit(d):
    d = d.strip().lower().rstrip(".")
    res = {"domaine": d, "problemes": []}
    s = spf(d)
    res["spf"] = s
    if s is None:
        res["problemes"].append("SPF absent")
    else:
        n, notes = cout_spf(d)
        res["spf_requetes"] = n
        res["spf_notes"] = notes
        if n > 10:
            res["problemes"].append(f"SPF : {n} requêtes DNS, limite 10 (erreur permanente côté récepteur)")
        if re.search(r"\s\+all\b", s) or s.rstrip().endswith(" all"):
            res["problemes"].append("SPF : « all » sans qualificateur ou +all autorise tout le monde")
        if not re.search(r"[-~]all\b|redirect=", s):
            res["problemes"].append("SPF : pas de -all ni ~all final")
    dm = dmarc(d)
    res["dmarc"] = dm
    if dm is None:
        res["problemes"].append("DMARC absent")
    else:
        p = re.search(r"(?:^|;)\s*p=(\w+)", dm)
        res["dmarc_p"] = p.group(1).lower() if p else None
        if res["dmarc_p"] == "none":
            res["problemes"].append("DMARC en p=none : surveille mais ne bloque rien")
        if "rua=" not in dm:
            res["problemes"].append("DMARC sans rua : aucun rapport agrégé reçu")
    res["dkim_selecteurs"] = dkim(d)
    if not res["dkim_selecteurs"]:
        res["dkim_note"] = "aucun sélecteur courant trouvé parmi %d testés (cela ne prouve pas l'absence de DKIM)" % len(SELECTEURS)
    res["mta_sts"] = any(v.startswith("v=STSv1") for v in txt("_mta-sts." + d))
    return res

if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        sys.exit(__doc__)
    sortie = [audit(a) for a in args]
    if "--json" in sys.argv:
        print(json.dumps(sortie, ensure_ascii=False, indent=2))
    else:
        for r in sortie:
            print("==", r["domaine"])
            print("SPF   :", r["spf"], "| requêtes DNS :", r.get("spf_requetes", "-"))
            print("DMARC :", r["dmarc"])
            print("DKIM  :", ", ".join(r["dkim_selecteurs"]) or r.get("dkim_note"))
            print("MTA-STS :", "oui" if r["mta_sts"] else "non")
            for p in r["problemes"]:
                print(" !", p)
            if not r["problemes"]:
                print(" aucun problème détecté par ces contrôles")
