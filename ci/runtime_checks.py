#!/usr/bin/env python3
"""
Contrôles des stages PRODUCTION / OPERATIONS du pipeline (sans dépendance externe).
 
Chaque sous-commande lit les fichiers produits par l'outil, écrit un résumé lisible
dans reports/ et renvoie un code de sortie :
    0 = conforme   |   1 = seuil non atteint (le stage passe en UNSTABLE)
 
Usage (appelé par le Jenkinsfile) :
    python3 ci/runtime_checks.py kubescape      reports/kubescape.json   <seuil %>
    python3 ci/runtime_checks.py lynis          reports/lynis-report.dat <score min>
    python3 ci/runtime_checks.py falco          reports/falco.txt        <pod cible>
    python3 ci/runtime_checks.py trivy-operator reports                  <tag image> <trouvé 0|1>
    python3 ci/runtime_checks.py targets-up     reports/prometheus-targets.json
    python3 ci/runtime_checks.py prometheus     reports
"""
 
import json
import os
import re
import sys
 
REPORTS = os.environ.get("REPORTS_DIR", "reports")
FALCO_PRIORITIES = ["Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug"]
 
 
def load_json(p, default=None):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default
 
 
def write(name, text):
    with open(os.path.join(REPORTS, name), "w", encoding="utf-8") as f:
        f.write(text + "\n")
    print(text)
 
 
def save_json(name, data):
    with open(os.path.join(REPORTS, name), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
 
 
# ---------------------------------------------------------------------------
# KUBESCAPE : score de conformité NSA / MITRE
# ---------------------------------------------------------------------------
def sev_from_factor(f):
    try:
        f = float(f)
    except Exception:
        return "UNKNOWN"
    return "CRITICAL" if f >= 9 else "HIGH" if f >= 7 else "MEDIUM" if f >= 4 else "LOW"
 
 
def ctrl_status(c):
    st = c.get("status")
    if isinstance(st, dict):
        st = st.get("status")
    return (st or "").lower()
 
 
def kubescape(path, threshold):
    data = load_json(path)
    if not data:
        write("kubescape.txt", "Kubescape : rapport JSON absent ou illisible (scan non exécuté ?)")
        return 1
    sd = data.get("summaryDetails", {}) or {}
    score = sd.get("complianceScore", sd.get("score"))
    score = round(float(score), 1) if score is not None else None
    fws = [(fw.get("name", "?"), round(float(fw.get("complianceScore", fw.get("score", 0)) or 0), 1))
           for fw in sd.get("frameworks", []) or []]
    failed = []
    for cid, c in (sd.get("controls", {}) or {}).items():
        if ctrl_status(c) == "failed":
            rc = c.get("ResourceCounters", {}) or {}
            failed.append({"id": cid, "name": c.get("name", ""),
                           "severity": sev_from_factor(c.get("scoreFactor")),
                           "failedResources": rc.get("failedResources", 0)})
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    failed.sort(key=lambda x: (order.index(x["severity"]), -int(x["failedResources"] or 0)))
    counts = {s: sum(1 for f in failed if f["severity"] == s) for s in order}
    rc_all = sd.get("ResourceCounters", {}) or {}
 
    summary = {"score": score, "threshold": float(threshold), "frameworks": fws, "failedControls": failed,
               "counts": counts, "resources": rc_all}
    save_json("kubescape-summary.json", summary)
 
    lines = ["=" * 78, " KUBESCAPE - conformité Kubernetes (namespace applicatif)", "=" * 78,
             f" Score global       : {score} %   (seuil : {threshold} %)"]
    for n, s in fws:
        lines.append(f" Référentiel {n:<7}: {s} %")
    lines.append(f" Contrôles en échec : {len(failed)}  (" +
                 ", ".join(f"{k} {v}" for k, v in counts.items() if v) + ")")
    lines.append("-" * 78)
    for f in failed[:15]:
        lines.append(f" [{f['severity']:<8}] {f['id']:<8} {f['name'][:50]:<50} ({f['failedResources']} ressource(s))")
    lines.append("=" * 78)
    write("kubescape.txt", "\n".join(lines))
    if score is None or score < float(threshold):
        print(f"Score de conformité inférieur au seuil ({score} < {threshold}) -> stage UNSTABLE")
        return 1
    return 0
 
 
# ---------------------------------------------------------------------------
# LYNIS : Hardening Index du serveur Jenkins
# ---------------------------------------------------------------------------
def lynis(path, minimum):
    kv, warnings, suggestions = {}, [], []
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if "=" not in line or line.startswith("#"):
                    continue
                k, v = line.split("=", 1)
                if k == "warning[]":
                    warnings.append(v.split("|"))
                elif k == "suggestion[]":
                    suggestions.append(v.split("|"))
                else:
                    kv[k] = v
    except Exception:
        write("lynis-summary.txt", "Lynis : fichier de rapport absent (audit non exécuté ?)")
        return 1
    try:
        index = int(kv.get("hardening_index", "0"))
    except ValueError:
        index = 0
    summary = {"index": index, "minimum": int(minimum), "version": kv.get("lynis_version", ""),
               "tests": kv.get("lynis_tests_done", kv.get("tests_executed", "")),
               "os": kv.get("os_fullname", kv.get("os_name", "")),
               "warnings": [{"id": w[0], "text": w[1] if len(w) > 1 else ""} for w in warnings],
               "suggestions": [{"id": s[0], "text": s[1] if len(s) > 1 else ""} for s in suggestions]}
    save_json("lynis-summary.json", summary)
    lines = ["=" * 78, " LYNIS - durcissement du serveur Jenkins (WSL)", "=" * 78,
             f" Hardening Index : {index}/100   (minimum : {minimum})",
             f" Système         : {summary['os']}   ·   Lynis {summary['version']}",
             f" Avertissements  : {len(warnings)}   ·   Suggestions : {len(suggestions)}", "-" * 78]
    for w in summary["warnings"][:10]:
        lines.append(f" [WARNING]    {w['id']:<10} {w['text'][:60]}")
    for s in summary["suggestions"][:10]:
        lines.append(f" [SUGGESTION] {s['id']:<10} {s['text'][:60]}")
    lines.append("=" * 78)
    write("lynis-summary.txt", "\n".join(lines))
    if index < int(minimum):
        print(f"Hardening Index trop faible ({index} < {minimum}) -> stage UNSTABLE")
        return 1
    return 0
 
 
# ---------------------------------------------------------------------------
# FALCO : détection d'intrusion à l'exécution
# ---------------------------------------------------------------------------
PRIO_RE = re.compile(r"\b(" + "|".join(FALCO_PRIORITIES) + r")\b\s+(.*)")
 
 
def falco(path, target_pod=""):
    alerts = []
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                m = PRIO_RE.search(line)
                if not m or ":" not in line[:40]:
                    continue
                prio, rest = m.group(1), m.group(2).strip()
                if prio in ("Informational", "Debug"):
                    continue
                rule = rest.split(" (")[0].split(" | ")[0].strip()
                alerts.append({"priority": prio, "rule": rule[:90],
                               "target": bool(target_pod) and target_pod in line})
    except Exception:
        write("falco-summary.txt", "Falco : journal introuvable")
        return 1
    by_prio = {p: sum(1 for a in alerts if a["priority"] == p) for p in FALCO_PRIORITIES[:6]}
    rules = {}
    for a in alerts:
        rules[a["rule"]] = rules.get(a["rule"], 0) + 1
    on_target = sum(1 for a in alerts if a["target"])
    summary = {"total": len(alerts), "byPriority": by_prio, "onTargetPod": on_target,
               "targetPod": target_pod, "rules": sorted(rules.items(), key=lambda x: -x[1])}
    save_json("falco-summary.json", summary)
    lines = ["=" * 78, " FALCO - détection d'intrusion pendant le build", "=" * 78,
             f" Alertes détectées : {len(alerts)}   (dont {on_target} sur le pod {target_pod or '?'})",
             " Par priorité      : " + ", ".join(f"{k} {v}" for k, v in by_prio.items() if v), "-" * 78]
    for r, n in summary["rules"][:10]:
        lines.append(f" {n:>3} x {r}")
    lines.append("=" * 78)
    write("falco-summary.txt", "\n".join(lines))
    if not alerts:
        print("Aucune alerte Falco : l'attaque simulée n'a pas été détectée -> stage UNSTABLE")
        return 1
    return 0
 
 
# ---------------------------------------------------------------------------
# TRIVY OPERATOR : scan continu des workloads en cours d'exécution
# ---------------------------------------------------------------------------
def summ(item):
    s = (item.get("report", {}) or {}).get("summary", {}) or {}
    return {k: int(s.get(k + "Count", 0) or 0) for k in ("critical", "high", "medium", "low")}
 
 
def trivy_operator(folder, tag, found):
    vulns = load_json(os.path.join(folder, "trivy-operator-vulns.json"), {"items": []}) or {"items": []}
    conf = load_json(os.path.join(folder, "trivy-operator-config.json"), {"items": []}) or {"items": []}
    secr = load_json(os.path.join(folder, "trivy-operator-secrets.json"), {"items": []}) or {"items": []}
    images, app = [], None
    for it in vulns.get("items", []):
        art = (it.get("report", {}) or {}).get("artifact", {}) or {}
        lab = (it.get("metadata", {}) or {}).get("labels", {}) or {}
        row = {"workload": lab.get("trivy-operator.resource.name", it.get("metadata", {}).get("name", "?")),
               "container": lab.get("trivy-operator.container.name", ""),
               "image": f"{art.get('repository', '?')}:{art.get('tag', '')}", **summ(it)}
        images.append(row)
        if str(art.get("tag", "")) == str(tag):
            app = row
    images.sort(key=lambda r: (-r["critical"], -r["high"]))
    configs = []
    for it in conf.get("items", []):
        lab = (it.get("metadata", {}) or {}).get("labels", {}) or {}
        configs.append({"workload": f"{lab.get('trivy-operator.resource.kind', '')}/"
                                    f"{lab.get('trivy-operator.resource.name', it.get('metadata', {}).get('name', '?'))}",
                        **summ(it)})
    secrets = sum(len((it.get("report", {}) or {}).get("secrets", []) or []) for it in secr.get("items", []))
    tot = {k: sum(r[k] for r in images) for k in ("critical", "high", "medium", "low")}
    summary = {"images": images, "configs": configs, "secrets": secrets, "totals": tot,
               "appImage": app, "appTag": tag, "appReportFound": str(found) == "1"}
    save_json("trivy-operator-summary.json", summary)
    lines = ["=" * 78, " TRIVY OPERATOR - scan continu du namespace applicatif", "=" * 78,
             f" Images scannées : {len(images)}   ·   CVE : Critical {tot['critical']} · High {tot['high']}"
             f" · Medium {tot['medium']} · Low {tot['low']}",
             f" Secrets exposés : {secrets}   ·   Workloads audités (config) : {len(configs)}", "-" * 78]
    for r in images:
        lines.append(f" {r['image'][:45]:<45} C {r['critical']:>3}  H {r['high']:>3}  M {r['medium']:>4}  L {r['low']:>4}")
    lines.append("-" * 78)
    if app:
        lines.append(f" Image du build ({app['image']}) : Critical {app['critical']} · High {app['high']}")
    else:
        lines.append(f" Rapport de l'image du build (tag {tag}) pas encore disponible (scan en cours).")
    lines.append("=" * 78)
    write("trivy-operator-summary.txt", "\n".join(lines))
    if app and app["critical"] > 0:
        print("CVE CRITICAL dans l'image déployée -> stage UNSTABLE")
        return 1
    return 0
 
 
# ---------------------------------------------------------------------------
# PROMETHEUS : cibles supervisées + alertes actives
# ---------------------------------------------------------------------------
def targets(path):
    data = load_json(path, {}) or {}
    return [{"job": t.get("labels", {}).get("job", "?"), "health": t.get("health", "unknown"),
             "url": t.get("scrapeUrl", ""), "error": t.get("lastError", "")}
            for t in (data.get("data", {}) or {}).get("activeTargets", [])]
 
 
def targets_up(path):
    ts = targets(path)
    up = sum(1 for t in ts if t["health"] == "up")
    print(f"Cibles UP : {up}/{len(ts)}")
    return 0 if ts and up == len(ts) else 1
 
 
def prometheus(folder):
    ts = targets(os.path.join(folder, "prometheus-targets.json"))
    al = (load_json(os.path.join(folder, "prometheus-alerts.json"), {}) or {}).get("data", {}).get("alerts", [])
    rules = (load_json(os.path.join(folder, "prometheus-rules.json"), {}) or {}).get("data", {}).get("groups", [])
    graf = load_json(os.path.join(folder, "grafana-health.json"), {}) or {}
    firing = [{"name": a.get("labels", {}).get("alertname", "?"), "severity": a.get("labels", {}).get("severity", ""),
               "state": a.get("state", ""), "summary": (a.get("annotations", {}) or {}).get("summary", "")}
              for a in al if a.get("state") == "firing"]
    nrules = sum(len(g.get("rules", [])) for g in rules)
    up = sum(1 for t in ts if t["health"] == "up")
    summary = {"targets": ts, "up": up, "total": len(ts), "rules": nrules, "firing": firing,
               "grafana": graf.get("database", "") == "ok", "grafanaVersion": graf.get("version", "")}
    save_json("prometheus-summary.json", summary)
    lines = ["=" * 78, " SUPERVISION CONTINUE - Prometheus & Grafana", "=" * 78,
             f" Cibles supervisées : {up}/{len(ts)} UP   ·   Règles d'alerte chargées : {nrules}",
             f" Alertes actives    : {len(firing)}   ·   Grafana : "
             f"{'OK (v' + summary['grafanaVersion'] + ')' if summary['grafana'] else 'injoignable'}", "-" * 78]
    for t in ts:
        lines.append(f" [{t['health'].upper():<7}] {t['job']:<20} {t['error'][:45]}")
    for f in firing:
        lines.append(f" [ALERTE {f['severity'] or '?'}] {f['name']} - {f['summary'][:50]}")
    lines.append("=" * 78)
    write("prometheus-summary.txt", "\n".join(lines))
    if not ts or up < len(ts) or not summary["grafana"]:
        print("Supervision incomplète (cible DOWN ou Grafana injoignable) -> stage UNSTABLE")
        return 1
    return 0
 
 
def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    os.makedirs(REPORTS, exist_ok=True)
    cmd, args = argv[1], argv[2:]
    if cmd == "kubescape":
        return kubescape(args[0], args[1] if len(args) > 1 else "60")
    if cmd == "lynis":
        return lynis(args[0], args[1] if len(args) > 1 else "50")
    if cmd == "falco":
        return falco(args[0], args[1] if len(args) > 1 else "")
    if cmd == "trivy-operator":
        return trivy_operator(args[0], args[1] if len(args) > 1 else "", args[2] if len(args) > 2 else "0")
    if cmd == "targets-up":
        return targets_up(args[0])
    if cmd == "prometheus":
        return prometheus(args[0])
    print(f"Sous-commande inconnue : {cmd}")
    return 2
 
 
if __name__ == "__main__":
    sys.exit(main(sys.argv))
 
