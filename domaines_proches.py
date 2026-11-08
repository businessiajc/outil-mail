"""Domaines proches d'une marque : génère des variantes plausibles (fautes de frappe, caractères
ressemblants, mots-pièges, autres extensions) et regarde par DNS public lesquelles existent.
LECTURE SEULE : ne visite aucun site, n'envoie rien. Un domaine qui existe n'est PAS forcément malveillant
(certains sont des protections défensives de la marque elle-même). Usage :
  uv run python domaines_proches.py exemple.fr [--max 300]
"""
import sys, json, urllib.request, urllib.parse, concurrent.futures as cf

HOMOGLYPHES = {"a": ["4", "à"], "e": ["3", "é"], "i": ["1", "l"], "l": ["1", "i"], "o": ["0"], "s": ["5", "z"], "m": ["rn"], "w": ["vv"], "u": ["v"], "c": ["k"]}
VOISINS = {"a": "qzs", "b": "vgn", "c": "xvd", "d": "sfe", "e": "zrd", "f": "dgr", "g": "fht", "h": "gjy", "i": "uok", "j": "hku", "k": "jli", "l": "kmo", "m": "nlk", "n": "bhm", "o": "ipl", "p": "ol", "q": "wsa", "r": "etf", "s": "adw", "t": "ryg", "u": "yij", "v": "cfb", "w": "qse", "x": "zsc", "y": "tuh", "z": "aqs"}
MOTS = ["login", "secure", "service", "client", "paiement", "support", "mon-compte", "espace"]
TLDS = ["com", "net", "org", "fr", "eu", "io", "co", "shop", "online", "site", "info", "xyz", "app", "support"]


def separer(d):
    nom, _, tld = d.partition(".")
    return nom, tld


def variantes(domaine):
    nom, tld = separer(domaine.lower())
    v = set()
    for i in range(len(nom)):
        v.add(nom[:i] + nom[i + 1:] + "." + tld)                      # omission
        v.add(nom[:i] + nom[i] * 2 + nom[i + 1:] + "." + tld)         # répétition
        if i < len(nom) - 1:
            v.add(nom[:i] + nom[i + 1] + nom[i] + nom[i + 2:] + "." + tld)  # inversion
        for h in HOMOGLYPHES.get(nom[i], []):
            v.add(nom[:i] + h + nom[i + 1:] + "." + tld)              # caractère ressemblant
        for n in VOISINS.get(nom[i], ""):
            v.add(nom[:i] + n + nom[i + 1:] + "." + tld)              # touche voisine
        if 0 < i < len(nom):
            v.add(nom[:i] + "-" + nom[i:] + "." + tld)                # tiret
    for t in TLDS:
        v.add(nom + "." + t)                                           # autre extension
    for m in MOTS:
        v.add(nom + "-" + m + "." + tld); v.add(m + "-" + nom + "." + tld)  # mot-piège
    v.discard(domaine.lower())
    return sorted(x for x in v if all(c.isalnum() or c in "-." for c in x) and not x.startswith("-") and "-." not in x)


def doh(nom, type_):
    url = "https://dns.google/resolve?" + urllib.parse.urlencode({"name": nom, "type": type_})
    for _ in range(2):
        try:
            d = json.load(urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "domaines-proches/1"}), timeout=12))
            return d
        except Exception:
            continue
    return None


def verifier(d):
    a = doh(d, "A")
    if a is None:
        return d, None
    existe = a.get("Status") == 0 and bool(a.get("Answer"))
    if not existe:
        ns = doh(d, "NS")
        existe = bool(ns and ns.get("Status") == 0 and ns.get("Answer"))   # enregistré sans site
    if not existe:
        return d, False
    mx = doh(d, "MX")
    return d, {"web": bool(a.get("Answer")), "mail": bool(mx and mx.get("Answer"))}


def balayer(domaine, maximum=300):
    vs = variantes(domaine)[:maximum]
    trouves, inconnus = {}, 0
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        for d, r in ex.map(verifier, vs):
            if r is None: inconnus += 1
            elif r: trouves[d] = r
    return {"domaine": domaine, "variantes_testees": len(vs), "enregistrees": trouves, "reponses_dns_manquantes": inconnus}


if __name__ == "__main__":
    dom = sys.argv[1]
    mx = int(sys.argv[sys.argv.index("--max") + 1]) if "--max" in sys.argv else 300
    r = balayer(dom, mx)
    print(f"{r['domaine']} : {r['variantes_testees']} variantes testées, {len(r['enregistrees'])} enregistrées, {r['reponses_dns_manquantes']} réponses DNS manquantes")
    for d, i in r["enregistrees"].items():
        print("  ", d, "| site" if i["web"] else "| sans site", "| mail possible" if i["mail"] else "")
    print("Un domaine proche enregistré n'est pas forcément malveillant : à qualifier avant tout signalement.")
