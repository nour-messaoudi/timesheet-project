#!/usr/bin/env python3
"""
Génère le rapport DevSecOps du pipeline Jenkins (sans dépendance externe).
 
Entrées (dans reports/ et target/) :
  stages.txt, meta.txt, secret-scan.txt, sonar-measures.json,
  trivy-sca.json, trivy-iac.json, trivy-image.json, sbom-cyclonedx.json,
  zap-report.json, gauntlt.txt, target/surefire-reports/TEST-*.xml, target/site/jacoco/jacoco.xml,
  et les synthèses PRODUCTION / OPERATIONS écrites par ci/runtime_checks.py :
  kubescape-summary.json, lynis-summary.json, falco-summary.json,
  trivy-operator-summary.json, prometheus-summary.json
 
Sorties (dans reports/) :
  devsecops-report.html + devsecops-report.css  -> rapport visuel
  devsecops-summary.txt                        -> résumé texte (aussi affiché en console)
  summary-line.txt                             -> ligne courte pour la description du build
"""
 
import glob
import html
import json
import os
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
 
REPORTS = os.environ.get("REPORTS_DIR", "reports")
 
# ----------------------------------------------------------------------------
# Catalogue des stages (noms identiques à ceux du Jenkinsfile)
# ----------------------------------------------------------------------------
STAGES = [
    ("TOOL CHECK", "Shell", "Vérifie que tous les outils sont installés", "ci"),
    ("CHECKOUT FROM GITHUB", "Git", "Récupère le code source (branche master)", "ci"),
    ("SECRET SECURITY SCAN", "pre-commit", "Détecte les secrets (mots de passe, tokens) dans le code", "sec"),
    ("CLEAN PROJECT", "Maven", "Nettoie le dossier target/", "ci"),
    ("BUILD ARTIFACT", "Maven", "Compile et package le JAR", "ci"),
    ("UNIT & SECURITY TESTS", "JUnit 5 · Mockito · JaCoCo", "Exécute les tests et mesure la couverture", "sec"),
    ("SAST - SONARQUBE", "SonarQube", "Analyse statique du code source (SAST)", "sec"),
    ("QUALITY GATE", "SonarQube Quality Gate", "Bloque si la qualité/sécurité du nouveau code est insuffisante", "sec"),
    ("SCA - DEPENDENCIES SCAN", "Trivy fs", "CVE dans les dépendances Maven (SCA)", "sec"),
    ("IaC SECURITY SCAN", "Trivy config", "Mauvaises configurations Dockerfile / Kubernetes", "sec"),
    ("PUBLISH/ARCHIVE ARTIFACT", "Jenkins", "Archive le JAR (empreinte)", "ci"),
    ("BUILD DOCKER IMAGE", "Docker", "Construit l'image de l'application", "ci"),
    ("TRIVY IMAGE SECURITY SCAN", "Trivy image · CycloneDX", "CVE de l'image (OS + JAR) + SBOM — security gate", "sec"),
    ("PUSH TO DOCKERHUB", "Docker Hub", "Publie l'image validée", "ci"),
    ("DEPLOY", "kubectl · minikube", "Déploie sur Kubernetes (rollback auto si échec)", "ci"),
    ("HEALTH CHECK", "Actuator · Prometheus", "Vérifie que l'application et le monitoring répondent", "ci"),
    ("CONFIG SAFETY - KUBESCAPE", "Kubescape (NSA · MITRE)", "[PRODUCTION] Conformité de la configuration Kubernetes", "sec"),
    ("SERVER HARDENING - LYNIS", "Lynis", "[PRODUCTION] Audit de durcissement du serveur Jenkins", "sec"),
    ("DAST - OWASP ZAP", "OWASP ZAP baseline", "Teste l'application en cours d'exécution (DAST)", "sec"),
    ("SECURITY TESTS - GAUNTLT", "Gauntlt (curl · nmap)", "Tests d'attaque BDD sur l'application déployée", "sec"),
    ("HOST INTRUSION - FALCO", "Falco · Falcosidekick", "[PRODUCTION] Détection d'intrusion en temps réel (attaque simulée)", "sec"),
    ("CONTINUOUS SCANNING - TRIVY OPERATOR", "Trivy Operator", "[OPERATIONS] Scan continu des workloads en exécution", "sec"),
    ("CONTINUOUS MONITORING - PROMETHEUS", "Prometheus · Grafana", "[OPERATIONS] Supervision, règles d'alerte, tableaux de bord", "sec"),
    ("EMAIL NOTIFICATION", "Email Extension · Gmail SMTP", "Envoie le rapport par e-mail si le build est SUCCESS", "ci"),
]
 
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
 
# Stages non bloquants : un échec y est affiché UNSTABLE (catchError dans le Jenkinsfile)
NON_BLOCKING = {
    "DAST - OWASP ZAP", "SECURITY TESTS - GAUNTLT", "CONFIG SAFETY - KUBESCAPE", "SERVER HARDENING - LYNIS",
    "HOST INTRUSION - FALCO", "CONTINUOUS SCANNING - TRIVY OPERATOR", "CONTINUOUS MONITORING - PROMETHEUS",
}
 
 
# ----------------------------------------------------------------------------
# Utilitaires de lecture
# ----------------------------------------------------------------------------
def path(name):
    return os.path.join(REPORTS, name)
 
 
def load_json(name):
    try:
        with open(path(name), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None
 
 
def read_kv(name):
    data = {}
    try:
        with open(path(name), encoding="utf-8") as f:
            for line in f:
                if "=" in line:
                    k, v = line.rstrip("\n").split("=", 1)
                    data[k.strip()] = v.strip()
    except Exception:
        pass
    return data
 
 
def read_stages():
    res = {}
    try:
        with open(path("stages.txt"), encoding="utf-8") as f:
            for line in f:
                parts = line.rstrip("\n").split("|")
                if len(parts) >= 3:
                    res[parts[0]] = {"status": parts[1], "duration": int(parts[2] or 0) // 1000}
    except Exception:
        pass
    return res
 
 
def esc(v):
    return html.escape(str(v)) if v is not None else ""
 
 
def fmt_dur(sec):
    if sec is None:
        return "—"
    m, s = divmod(int(sec), 60)
    return f"{m} min {s:02d} s" if m else f"{s} s"
 
 
# ----------------------------------------------------------------------------
# Parsers par outil
# ----------------------------------------------------------------------------
def parse_secrets():
    hooks = []
    try:
        with open(path("secret-scan.txt"), encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                for st in ("Passed", "Failed", "Skipped"):
                    if line.endswith(st):
                        name = line[: -len(st)].rstrip(". ").strip()
                        hooks.append((name, st))
    except Exception:
        return None
    return hooks
 
 
def parse_tests():
    files = glob.glob("target/surefire-reports/TEST-*.xml")
    if not files:
        return None
    t = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0, "time": 0.0, "suites": []}
    for fp in files:
        try:
            r = ET.parse(fp).getroot()
        except Exception:
            continue
        n = int(r.get("tests", 0)); fa = int(r.get("failures", 0))
        er = int(r.get("errors", 0)); sk = int(r.get("skipped", 0))
        tm = float(r.get("time", 0) or 0)
        t["tests"] += n; t["failures"] += fa; t["errors"] += er; t["skipped"] += sk; t["time"] += tm
        t["suites"].append((r.get("name", os.path.basename(fp)).split(".")[-1], n, fa + er, sk, tm))
    return t
 
 
def parse_coverage():
    fp = "target/site/jacoco/jacoco.xml"
    if not os.path.exists(fp):
        return None
    try:
        root = ET.parse(fp).getroot()
    except Exception:
        return None
    cov = {}
    for c in root.findall("counter"):  # compteurs globaux (enfants directs de <report>)
        missed, covered = int(c.get("missed")), int(c.get("covered"))
        total = missed + covered
        cov[c.get("type")] = round(100.0 * covered / total, 1) if total else 0.0
    return cov
 
 
def parse_sonar():
    data = load_json("sonar-measures.json")
    if not data:
        return None
    m = {x["metric"]: x.get("value") for x in data.get("component", {}).get("measures", [])}
 
    def pick(*keys):
        for k in keys:
            if k in m and m[k] is not None:
                return m[k]
        return None
 
    return {
        "reliability": pick("software_quality_reliability_issues", "bugs"),
        "security": pick("software_quality_security_issues", "vulnerabilities"),
        "maintainability": pick("software_quality_maintainability_issues", "code_smells"),
        "hotspots": pick("security_hotspots"),
        "coverage": pick("coverage"),
        "duplication": pick("duplicated_lines_density"),
        "ncloc": pick("ncloc"),
    }
 
 
def parse_trivy_vulns(name):
    data = load_json(name)
    if data is None:
        return None
    out = {"counts": {s: 0 for s in SEV_ORDER}, "items": [], "targets": []}
    for r in data.get("Results", []) or []:
        vulns = r.get("Vulnerabilities") or []
        out["targets"].append((r.get("Target", "?"), r.get("Type", ""), len(vulns)))
        for v in vulns:
            sev = v.get("Severity", "UNKNOWN")
            out["counts"][sev] = out["counts"].get(sev, 0) + 1
            out["items"].append({
                "sev": sev, "id": v.get("VulnerabilityID", ""), "pkg": v.get("PkgName", ""),
                "installed": v.get("InstalledVersion", ""), "fixed": v.get("FixedVersion", "") or "—",
                "title": v.get("Title", "") or "", "target": r.get("Target", ""),
            })
    out["items"].sort(key=lambda x: SEV_ORDER.index(x["sev"]) if x["sev"] in SEV_ORDER else 9)
    out["total"] = len(out["items"])
    return out
 
 
def parse_trivy_iac():
    data = load_json("trivy-iac.json")
    if data is None:
        return None
    out = {"counts": {s: 0 for s in SEV_ORDER}, "files": [], "rules": {}, "total": 0}
    for r in data.get("Results", []) or []:
        fails = [m for m in (r.get("Misconfigurations") or []) if m.get("Status", "FAIL") == "FAIL"]
        summ = r.get("MisconfSummary") or {}
        out["files"].append((r.get("Target", "?"), summ.get("Successes", 0), len(fails)))
        for m in fails:
            sev = m.get("Severity", "UNKNOWN")
            out["counts"][sev] = out["counts"].get(sev, 0) + 1
            out["total"] += 1
            rid = m.get("ID") or m.get("AVDID") or "?"
            rule = out["rules"].setdefault(rid, {"sev": sev, "title": m.get("Title", ""),
                                                 "resolution": m.get("Resolution", ""), "files": set()})
            rule["files"].add(r.get("Target", "?"))
    return out
 
 
def parse_sbom():
    data = load_json("sbom-cyclonedx.json")
    if data is None:
        return None
    return len(data.get("components", []) or [])
 
 
def parse_gauntlt():
    try:
        with open(path("gauntlt.txt"), encoding="utf-8", errors="ignore") as f:
            txt = f.read()
    except Exception:
        return None
    import re
    out = {"scenarios": 0, "passed": 0, "failed": 0, "steps": 0, "list": [], "failing": []}
    m = re.search(r"(\d+) scenarios? \(([^)]*)\)", txt)
    if m:
        out["scenarios"] = int(m.group(1))
        p = re.search(r"(\d+) passed", m.group(2)); f = re.search(r"(\d+) failed", m.group(2))
        out["passed"] = int(p.group(1)) if p else 0
        out["failed"] = int(f.group(1)) if f else 0
    m = re.search(r"(\d+) steps? \(", txt)
    if m:
        out["steps"] = int(m.group(1))
    out["list"] = [l.split("Scenario:", 1)[1].split("#")[0].strip()
                   for l in txt.splitlines() if l.strip().startswith("Scenario:")]
    if "Failing Scenarios:" in txt:
        block = txt.split("Failing Scenarios:", 1)[1]
        for l in block.splitlines():
            if "# Scenario:" in l:
                out["failing"].append(l.split("# Scenario:", 1)[1].strip())
    return out
 
 
def parse_zap():
    data = load_json("zap-report.json")
    if data is None:
        return None
    names = {"3": "High", "2": "Medium", "1": "Low", "0": "Informational"}
    out = {"counts": {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}, "alerts": []}
    for site in data.get("site", []) or []:
        for a in site.get("alerts", []) or []:
            risk = names.get(str(a.get("riskcode", "0")), "Informational")
            out["counts"][risk] += 1
            uris = sorted({i.get("uri", "") for i in a.get("instances", []) or []})
            out["alerts"].append({
                "risk": risk, "name": a.get("alert") or a.get("name", ""),
                "id": a.get("pluginid", ""), "count": a.get("count", len(uris)),
                "solution": strip_tags(a.get("solution", "")), "uris": uris[:5],
            })
    order = ["High", "Medium", "Low", "Informational"]
    out["alerts"].sort(key=lambda x: order.index(x["risk"]))
    return out
 
 
def strip_tags(s):
    out, inside = [], False
    for ch in s or "":
        if ch == "<":
            inside = True
        elif ch == ">":
            inside = False
        elif not inside:
            out.append(ch)
    return "".join(out).strip()
 
 
def git_info():
    try:
        return subprocess.check_output(["git", "log", "-1", "--format=%h — %s (%an)"], text=True).strip()
    except Exception:
        return "—"
 
 
# ----------------------------------------------------------------------------
# Construction des résultats par stage
# ----------------------------------------------------------------------------
def sev_text(counts, keys=("CRITICAL", "HIGH")):
    return " · ".join(f"{k.capitalize()} {counts.get(k, 0)}" for k in keys)
 
 
def build():
    stages_rt = read_stages()
    meta = read_kv("meta.txt")
 
    secrets = parse_secrets()
    tests = parse_tests()
    cov = parse_coverage()
    sonar = parse_sonar()
    sca = parse_trivy_vulns("trivy-sca.json")
    iac = parse_trivy_iac()
    img = parse_trivy_vulns("trivy-image.json")
    sbom = parse_sbom()
    zap = parse_zap()
    gauntlt = parse_gauntlt()
    qg = meta.get("qualityGate", "N/A")
 
    key = {}
    level = {}  # ok | warn | ko | na  (verdict sécurité)
 
    if secrets is not None:
        failed = [h for h, s in secrets if s == "Failed"]
        key["SECRET SECURITY SCAN"] = f"{len(secrets)} contrôles · {len(failed)} en échec"
        level["SECRET SECURITY SCAN"] = "ko" if failed else "ok"
    if tests:
        ko = tests["failures"] + tests["errors"]
        txt = f"{tests['tests'] - ko - tests['skipped']}/{tests['tests']} tests OK"
        if cov and "LINE" in cov:
            txt += f" · couverture lignes {cov['LINE']} %"
        key["UNIT & SECURITY TESTS"] = txt
        level["UNIT & SECURITY TESTS"] = "ko" if ko else "ok"
    if sonar:
        key["SAST - SONARQUBE"] = (f"Fiabilité {sonar['reliability'] or 0} · Sécurité {sonar['security'] or 0}"
                                   f" · Hotspots {sonar['hotspots'] or 0} · Maintenabilité {sonar['maintainability'] or 0}")
        level["SAST - SONARQUBE"] = "warn" if str(sonar["security"] or "0") != "0" else "ok"
    key["QUALITY GATE"] = f"Statut : {qg}"
    level["QUALITY GATE"] = "ok" if qg == "OK" else ("na" if qg == "N/A" else "ko")
    if sca is not None:
        key["SCA - DEPENDENCIES SCAN"] = f"{sca['total']} CVE ({sev_text(sca['counts'])})"
        level["SCA - DEPENDENCIES SCAN"] = "warn" if sca["total"] else "ok"
    if iac is not None:
        key["IaC SECURITY SCAN"] = f"{iac['total']} mauvaises config. ({sev_text(iac['counts'])}) · {len(iac['rules'])} règles"
        level["IaC SECURITY SCAN"] = "warn" if iac["total"] else "ok"
    if img is not None:
        txt = f"{img['total']} CVE ({sev_text(img['counts'])})"
        if sbom is not None:
            txt += f" · SBOM {sbom} composants"
        key["TRIVY IMAGE SECURITY SCAN"] = txt
        level["TRIVY IMAGE SECURITY SCAN"] = "ko" if img["total"] else "ok"
    if zap is not None:
        c = zap["counts"]
        key["DAST - OWASP ZAP"] = f"High {c['High']} · Medium {c['Medium']} · Low {c['Low']} · Info {c['Informational']}"
        level["DAST - OWASP ZAP"] = "ko" if c["High"] else ("warn" if c["Medium"] or c["Low"] else "ok")
 
    image = os.environ.get("DOCKER_IMAGE", meta.get("image", ""))
    jar = sorted(glob.glob("target/*.jar"))
    jar_txt = f"{os.path.basename(jar[0])} ({os.path.getsize(jar[0]) // (1024 * 1024)} Mo)" if jar else "JAR"
    key.setdefault("TOOL CHECK", "Java 17, Maven, Docker, kubectl, Trivy, Git, pre-commit, Python, Kubescape, Lynis OK")
    key.setdefault("CHECKOUT FROM GITHUB", "commit " + git_info().split(" — ")[0])
    key.setdefault("CLEAN PROJECT", "target/ nettoyé")
    key.setdefault("BUILD ARTIFACT", jar_txt)
    key.setdefault("PUBLISH/ARCHIVE ARTIFACT", jar_txt + " archivé + empreinte")
    key.setdefault("BUILD DOCKER IMAGE", image)
    key.setdefault("PUSH TO DOCKERHUB", image)
    key.setdefault("DEPLOY", f"namespace {os.environ.get('K8S_NAMESPACE', '')}")
    key.setdefault("HEALTH CHECK", "actuator/health = UP · Prometheus healthy")
    key.setdefault("EMAIL NOTIFICATION", "Rapport envoyé par e-mail")
    if gauntlt is not None:
        key["SECURITY TESTS - GAUNTLT"] = (f"{gauntlt['passed']}/{gauntlt['scenarios']} scénarios OK"
                                           f" · {gauntlt['failed']} en échec · {gauntlt['steps']} steps")
        level["SECURITY TESTS - GAUNTLT"] = "ko" if gauntlt["failed"] or not gauntlt["scenarios"] else "ok"
 
    ks, ly, fa, to, pm = (load_json("kubescape-summary.json"), load_json("lynis-summary.json"),
                          load_json("falco-summary.json"), load_json("trivy-operator-summary.json"),
                          load_json("prometheus-summary.json"))
    if ks:
        fw = " · ".join(f"{n} {v} %" for n, v in ks.get("frameworks", []))
        key["CONFIG SAFETY - KUBESCAPE"] = (f"Score {ks.get('score')} % (seuil {ks.get('threshold'):g} %)"
                                            f" · {fw} · {len(ks.get('failedControls', []))} contrôles en échec")
        level["CONFIG SAFETY - KUBESCAPE"] = "ok" if (ks.get("score") or 0) >= ks.get("threshold", 60) else "warn"
    if ly:
        key["SERVER HARDENING - LYNIS"] = (f"Hardening Index {ly['index']}/100 · {len(ly['warnings'])} avertissement(s)"
                                           f" · {len(ly['suggestions'])} suggestion(s)")
        level["SERVER HARDENING - LYNIS"] = "ok" if ly["index"] >= ly.get("minimum", 50) else "warn"
    if fa:
        bp = ", ".join(f"{k} {v}" for k, v in fa.get("byPriority", {}).items() if v)
        key["HOST INTRUSION - FALCO"] = f"{fa['total']} alerte(s) détectée(s) ({bp or 'aucune'}) — attaque simulée"
        level["HOST INTRUSION - FALCO"] = "ok" if fa["total"] else "ko"
    if to:
        t2 = to["totals"]
        app = to.get("appImage")
        txt = f"{len(to['images'])} images · Critical {t2['critical']} · High {t2['high']}"
        txt += (f" · image du build : C{app['critical']}/H{app['high']}" if app else " · image du build : scan en cours")
        key["CONTINUOUS SCANNING - TRIVY OPERATOR"] = txt
        level["CONTINUOUS SCANNING - TRIVY OPERATOR"] = ("ko" if app and app["critical"] else
                                                         "warn" if t2["critical"] or t2["high"] else "ok")
    if pm:
        key["CONTINUOUS MONITORING - PROMETHEUS"] = (f"{pm['up']}/{pm['total']} cibles UP · {pm['rules']} règles"
                                                     f" · {len(pm['firing'])} alerte(s) active(s)"
                                                     f" · Grafana {'OK' if pm['grafana'] else 'KO'}")
        level["CONTINUOUS MONITORING - PROMETHEUS"] = ("ko" if pm["up"] < pm["total"] or not pm["grafana"]
                                                       else "warn" if pm["firing"] else "ok")
 
    rows = []
    for name, tool, role, cat in STAGES:
        rt = stages_rt.get(name)
        status = rt["status"] if rt else "SKIPPED"
        if name in NON_BLOCKING and status == "FAILED":
            status = "UNSTABLE"
        if status == "RUNNING":
            status = "EN COURS"
        rows.append({
            "name": name, "tool": tool, "role": role, "cat": cat, "status": status,
            "duration": rt["duration"] if rt else None,
            "key": key.get(name, "") if status != "SKIPPED" else "Non exécuté (stage précédent en échec)",
            "level": level.get(name, "na") if status != "SKIPPED" else "na",
        })
 
    return {
        "meta": meta, "rows": rows, "secrets": secrets, "tests": tests, "cov": cov, "sonar": sonar,
        "qg": qg, "sca": sca, "iac": iac, "img": img, "sbom": sbom, "zap": zap, "gauntlt": gauntlt, "image": image,
        "kubescape": ks, "lynis": ly, "falco": fa, "trivyop": to, "prom": pm,
    }
 
 
# ----------------------------------------------------------------------------
# Rendu HTML
# ----------------------------------------------------------------------------
CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#1d2330;--muted:#6b7280;--line:#e5e7eb;
--ok:#15803d;--okbg:#dcfce7;--warn:#b45309;--warnbg:#fef3c7;--ko:#b91c1c;--kobg:#fee2e2;
--na:#6b7280;--nabg:#f3f4f6;--accent:#1e40af}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:24px 16px 48px}
header{background:#0f172a;color:#fff;border-radius:12px;padding:20px 24px;margin-bottom:20px}
header h1{margin:0 0 6px;font-size:22px}
header .sub{color:#cbd5e1;font-size:13px}
header code{background:#1e293b;color:#e2e8f0}
header .verdict{display:inline-block;margin-top:10px;padding:4px 12px;border-radius:999px;font-weight:600;font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-bottom:20px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;border-top:4px solid var(--na)}
.kpi.ok{border-top-color:var(--ok)}.kpi.warn{border-top-color:var(--warn)}.kpi.ko{border-top-color:var(--ko)}
.kpi .lbl{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.kpi .val{font-size:22px;font-weight:700;margin:2px 0}
.kpi .det{color:var(--muted);font-size:12px}
section{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px 20px;margin-bottom:18px}
section h2{margin:0 0 4px;font-size:17px}
section .intro{color:var(--muted);margin:0 0 12px;font-size:13px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:var(--muted);font-weight:600;border-bottom:2px solid var(--line);padding:8px 6px}
td{border-bottom:1px solid var(--line);padding:8px 6px;vertical-align:top}
tr.sec td:first-child{border-left:3px solid var(--accent)}
.b{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700;white-space:nowrap}
.b.ok,.b.SUCCESS{background:var(--okbg);color:var(--ok)}
.b.warn,.b.UNSTABLE,.b.MEDIUM,.b.Medium{background:var(--warnbg);color:var(--warn)}
.b.ko,.b.FAILED,.b.CRITICAL,.b.HIGH,.b.High{background:var(--kobg);color:var(--ko)}
.b.na,.b.SKIPPED,.b.EN,.b.LOW,.b.Low,.b.Informational,.b.UNKNOWN{background:var(--nabg);color:var(--na)}
.muted{color:var(--muted)}
code{background:#f1f5f9;padding:1px 5px;border-radius:4px;font-size:12px}
.empty{padding:10px;background:var(--okbg);color:var(--ok);border-radius:8px;font-weight:600}
.links a{margin-right:14px}
footer{color:var(--muted);font-size:12px;text-align:center;margin-top:24px}
"""
 
VERDICT_LABEL = {"ok": "Conforme", "warn": "À surveiller", "ko": "Bloquant", "na": "N/A"}
 
 
def badge(text, cls=None):
    return f'<span class="b {esc(cls or text)}">{esc(text)}</span>'
 
 
def kpi(label, value, detail, level):
    return (f'<div class="kpi {level}"><div class="lbl">{esc(label)}</div>'
            f'<div class="val">{esc(value)}</div><div class="det">{esc(detail)}</div></div>')
 
 
def render_html(d):
    meta = d["meta"]
    result = meta.get("result", "UNKNOWN")
    vcls = {"SUCCESS": "ok", "UNSTABLE": "warn", "FAILURE": "ko"}.get(result, "na")
    now = datetime.now().strftime("%d/%m/%Y %H:%M")
 
    t, cov, s, sca, iac, img, zap = d["tests"], d["cov"], d["sonar"], d["sca"], d["iac"], d["img"], d["zap"]
 
    k = []
    if t:
        ko = t["failures"] + t["errors"]
        k.append(kpi("Tests unitaires", f"{t['tests'] - ko - t['skipped']}/{t['tests']}",
                     f"{ko} échec · {t['skipped']} ignoré", "ko" if ko else "ok"))
    if cov:
        k.append(kpi("Couverture (lignes)", f"{cov.get('LINE', 0)} %",
                     f"branches {cov.get('BRANCH', 0)} %", "ok" if cov.get("LINE", 0) >= 50 else "warn"))
    k.append(kpi("Quality Gate", d["qg"], "SonarQube (nouveau code)",
                 "ok" if d["qg"] == "OK" else ("na" if d["qg"] == "N/A" else "ko")))
    if d["secrets"] is not None:
        f = sum(1 for _, st in d["secrets"] if st == "Failed")
        k.append(kpi("Secrets", "0 fuite" if not f else f"{f} alerte(s)", "pre-commit", "ko" if f else "ok"))
    if sca is not None:
        k.append(kpi("SCA dépendances", f"{sca['total']} CVE", sev_text(sca["counts"]), "warn" if sca["total"] else "ok"))
    if img is not None:
        k.append(kpi("Image Docker", f"{img['total']} CVE", sev_text(img["counts"]), "ko" if img["total"] else "ok"))
    if iac is not None:
        k.append(kpi("IaC (K8s/Docker)", f"{iac['total']} findings", sev_text(iac["counts"]), "warn" if iac["total"] else "ok"))
    if zap is not None:
        c = zap["counts"]
        k.append(kpi("DAST (ZAP)", f"{c['High']} High", f"Medium {c['Medium']} · Low {c['Low']}",
                     "ko" if c["High"] else ("warn" if c["Medium"] or c["Low"] else "ok")))
 
    if d.get("kubescape"):
        ks = d["kubescape"]
        k.append(kpi("Kubescape", f"{ks.get('score')} %", f"conformité NSA/MITRE (seuil {ks.get('threshold'):g} %)",
                     "ok" if (ks.get("score") or 0) >= ks.get("threshold", 60) else "warn"))
    if d.get("lynis"):
        ly = d["lynis"]
        k.append(kpi("Lynis", f"{ly['index']}/100", "Hardening Index du serveur",
                     "ok" if ly["index"] >= ly.get("minimum", 50) else "warn"))
    if d.get("falco"):
        fa = d["falco"]
        k.append(kpi("Falco", f"{fa['total']} alertes", "attaque simulée détectée" if fa["total"] else "aucune détection",
                     "ok" if fa["total"] else "ko"))
    if d.get("trivyop"):
        t2 = d["trivyop"]["totals"]
        k.append(kpi("Trivy Operator", f"{t2['critical']} Critical", f"High {t2['high']} · cluster (images tierces incluses)",
                     "warn" if t2["critical"] or t2["high"] else "ok"))
    if d.get("prom"):
        pm = d["prom"]
        k.append(kpi("Supervision", f"{pm['up']}/{pm['total']} UP", f"{len(pm['firing'])} alerte(s) Prometheus active(s)",
                     "ko" if pm["up"] < pm["total"] else ("warn" if pm["firing"] else "ok")))
 
    # --- tableau des stages
    srows = []
    for i, r in enumerate(d["rows"], 1):
        srows.append(
            f'<tr class="{"sec" if r["cat"] == "sec" else ""}"><td>{i}</td><td><b>{esc(r["name"])}</b>'
            f'<div class="muted">{esc(r["role"])}</div></td><td>{esc(r["tool"])}</td>'
            f'<td>{badge(r["status"])}</td><td>{fmt_dur(r["duration"])}</td><td>{esc(r["key"])}</td>'
            f'<td>{badge(VERDICT_LABEL[r["level"]], r["level"]) if r["cat"] == "sec" else ""}</td></tr>')
 
    parts = [f"""<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rapport DevSecOps #{esc(os.environ.get('BUILD_NUMBER', ''))}</title>
<link rel="stylesheet" href="devsecops-report.css"></head><body><div class="wrap">
<header><h1>Rapport DevSecOps — {esc(os.environ.get('JOB_NAME', 'pipeline'))} #{esc(os.environ.get('BUILD_NUMBER', ''))}</h1>
<div class="sub">Commit : {esc(git_info())}<br>Image : <code>{esc(d['image'])}</code> · Namespace : {esc(os.environ.get('K8S_NAMESPACE', ''))} · Généré le {now}</div>
<span class="verdict b {vcls}">Résultat du build : {esc(result)}</span></header>
<div class="grid">{''.join(k)}</div>
<section><h2>1. Résumé par stage</h2>
<p class="intro">Les lignes marquées d'un liseré bleu sont les contrôles de sécurité. « Verdict » indique le niveau de risque détecté.</p>
<table><tr><th>#</th><th>Stage</th><th>Outil</th><th>Statut</th><th>Durée</th><th>Résultat clé</th><th>Verdict</th></tr>
{''.join(srows)}</table></section>"""]
 
    # --- secrets
    if d["secrets"] is not None:
        rows = "".join(f"<tr><td>{esc(h)}</td><td>{badge(st, 'ok' if st == 'Passed' else ('ko' if st == 'Failed' else 'na'))}</td></tr>"
                       for h, st in d["secrets"])
        parts.append(f"""<section><h2>2. Détection de secrets — pre-commit</h2>
<p class="intro">Recherche de mots de passe, clés et tokens commités par erreur. Bloquant.</p>
<table><tr><th>Contrôle</th><th>Résultat</th></tr>{rows}</table></section>""")
 
    # --- tests
    if t:
        rows = "".join(f"<tr><td>{esc(n)}</td><td>{a}</td><td>{f}</td><td>{sk}</td><td>{tm:.2f} s</td></tr>"
                       for n, a, f, sk, tm in t["suites"])
        cv = ""
        if cov:
            cv = " · ".join(f"{k2.capitalize()} {v} %" for k2, v in cov.items()
                            if k2 in ("LINE", "BRANCH", "METHOD", "CLASS"))
        parts.append(f"""<section><h2>3. Tests unitaires et couverture — JUnit / JaCoCo</h2>
<p class="intro">{t['tests']} tests en {t['time']:.1f} s. Couverture : {esc(cv or 'n/a')}</p>
<table><tr><th>Classe de test</th><th>Tests</th><th>Échecs</th><th>Ignorés</th><th>Durée</th></tr>{rows}</table></section>""")
 
    # --- sonar
    sm = s or {}
    link = f' — <a href="{esc(d["meta"].get("sonarUrl", ""))}/dashboard?id={esc(d["meta"].get("sonarKey", ""))}">ouvrir le dashboard</a>' \
        if d["meta"].get("sonarUrl") else ""
    parts.append(f"""<section><h2>4. SAST — SonarQube &amp; Quality Gate</h2>
<p class="intro">Analyse statique du code Java. Quality Gate : {badge(d['qg'], 'ok' if d['qg'] == 'OK' else 'ko')}{link}</p>
<table><tr><th>Fiabilité (bugs)</th><th>Sécurité (vulnérabilités)</th><th>Security Hotspots</th><th>Maintenabilité</th><th>Couverture</th><th>Duplication</th><th>Lignes de code</th></tr>
<tr><td>{esc(sm.get('reliability', 'n/a'))}</td><td>{esc(sm.get('security', 'n/a'))}</td><td>{esc(sm.get('hotspots', 'n/a'))}</td>
<td>{esc(sm.get('maintainability', 'n/a'))}</td><td>{esc(sm.get('coverage', 'n/a'))} %</td><td>{esc(sm.get('duplication', 'n/a'))} %</td><td>{esc(sm.get('ncloc', 'n/a'))}</td></tr></table></section>""")
 
    # --- trivy vulns
    def vuln_section(num, title, intro, data, extra=""):
        if data is None:
            return ""
        tg = "".join(f"<tr><td><code>{esc(a)}</code></td><td>{esc(b)}</td><td>{c}</td></tr>" for a, b, c in data["targets"])
        if data["items"]:
            it = "".join(
                f"<tr><td>{badge(v['sev'])}</td><td><b>{esc(v['id'])}</b></td><td>{esc(v['pkg'])}</td>"
                f"<td>{esc(v['installed'])}</td><td>{esc(v['fixed'])}</td><td>{esc(v['title'][:120])}</td></tr>"
                for v in data["items"])
            det = (f"<table><tr><th>Sévérité</th><th>CVE</th><th>Paquet</th><th>Installé</th><th>Corrigé dans</th>"
                   f"<th>Description</th></tr>{it}</table>")
        else:
            det = '<div class="empty">Aucune vulnérabilité HIGH/CRITICAL détectée.</div>'
        return (f"<section><h2>{num}. {title}</h2><p class='intro'>{intro} {extra}</p>"
                f"<table><tr><th>Cible analysée</th><th>Type</th><th>Vulnérabilités</th></tr>{tg}</table><br>{det}</section>")
 
    parts.append(vuln_section(5, "SCA — dépendances Maven (Trivy fs)",
                              "CVE HIGH/CRITICAL dans les bibliothèques déclarées dans pom.xml. Non bloquant (le gate est sur l'image).",
                              sca))
    parts.append(vuln_section(6, "Scan de l'image Docker (Trivy image) — Security Gate",
                              "CVE HIGH/CRITICAL corrigeables dans l'OS de base et le JAR. <b>Bloquant</b> : l'image n'est pas poussée si > 0.",
                              img, f"SBOM CycloneDX : {d['sbom']} composants." if d["sbom"] is not None else ""))
 
    # --- IaC
    if iac is not None:
        fr = "".join(f"<tr><td><code>{esc(f)}</code></td><td>{ok}</td><td>{ko}</td></tr>" for f, ok, ko in iac["files"])
        rr = "".join(
            f"<tr><td>{badge(r['sev'])}</td><td><b>{esc(rid)}</b></td><td>{esc(r['title'])}</td>"
            f"<td>{len(r['files'])} fichier(s)<div class='muted'>{esc(', '.join(sorted(r['files'])))}</div></td>"
            f"<td>{esc(r['resolution'])}</td></tr>"
            for rid, r in sorted(iac["rules"].items()))
        det = (f"<table><tr><th>Sévérité</th><th>Règle</th><th>Problème</th><th>Fichiers</th><th>Correction</th></tr>{rr}</table>"
               if rr else '<div class="empty">Aucune mauvaise configuration HIGH/CRITICAL.</div>')
        parts.append(f"""<section><h2>7. IaC — Dockerfile &amp; manifests Kubernetes (Trivy config)</h2>
<p class="intro">{iac['total']} mauvaises configurations HIGH/CRITICAL. Non bloquant.</p>
<table><tr><th>Fichier</th><th>Contrôles OK</th><th>Échecs</th></tr>{fr}</table><br>{det}</section>""")
 
    # --- ZAP
    if zap is not None:
        if zap["alerts"]:
            ar = "".join(
                f"<tr><td>{badge(a['risk'])}</td><td><b>{esc(a['name'])}</b> <span class='muted'>[{esc(a['id'])}]</span>"
                f"<div class='muted'>{'<br>'.join(esc(u) for u in a['uris'])}</div></td><td>{esc(a['count'])}</td>"
                f"<td>{esc(a['solution'][:220])}</td></tr>" for a in zap["alerts"])
            det = f"<table><tr><th>Risque</th><th>Alerte / URLs</th><th>Occurrences</th><th>Solution</th></tr>{ar}</table>"
        else:
            det = '<div class="empty">Aucune alerte.</div>'
        c = zap["counts"]
        parts.append(f"""<section><h2>8. DAST — OWASP ZAP baseline</h2>
<p class="intro">Scan passif de l'application déployée. High {c['High']} · Medium {c['Medium']} · Low {c['Low']} · Info {c['Informational']}. Non bloquant.
Rapport complet : <a href="zap-report.html">zap-report.html</a></p>{det}</section>""")
 
    # --- Gauntlt
    g = d.get("gauntlt")
    if g is not None:
        failing = set(g["failing"])
        gr = "".join(
            f"<tr><td>{esc(sc)}</td><td>{badge('Échec', 'ko') if sc in failing else badge('OK', 'ok')}</td></tr>"
            for sc in g["list"])
        parts.append(f"""<section><h2>9. Tests d'attaque — Gauntlt</h2>
<p class="intro">Attaques BDD (curl, nmap) sur l'application déployée : {g['passed']}/{g['scenarios']} scénarios OK,
{g['failed']} en échec, {g['steps']} steps. Non bloquant. Sortie complète : <a href="gauntlt.txt">gauntlt.txt</a></p>
<table><tr><th>Scénario</th><th>Résultat</th></tr>{gr}</table></section>""")
 
    # --- PRODUCTION / OPERATIONS
    ks = d.get("kubescape")
    if ks:
        fw = "".join(f"<tr><td>{esc(n)}</td><td>{esc(v)} %</td></tr>" for n, v in ks.get("frameworks", []))
        fc = "".join(f"<tr><td>{badge(c['severity'])}</td><td><b>{esc(c['id'])}</b></td><td>{esc(c['name'])}</td>"
                     f"<td>{esc(c['failedResources'])}</td></tr>" for c in ks.get("failedControls", [])[:20])
        det = (f"<table><tr><th>Sévérité</th><th>Contrôle</th><th>Description</th><th>Ressources en échec</th></tr>{fc}</table>"
               if fc else '<div class="empty">Tous les contrôles sont conformes.</div>')
        parts.append(f"""<section><h2>10. PRODUCTION — Configuration Safety Checks (Kubescape)</h2>
<p class="intro">Conformité des ressources du namespace aux référentiels NSA-CISA et MITRE ATT&amp;CK.
Score global {badge(str(ks.get('score')) + ' %', 'ok' if (ks.get('score') or 0) >= ks.get('threshold', 60) else 'warn')}
(seuil {esc(ks.get('threshold'))} %). Non bloquant.</p>
<table><tr><th>Référentiel</th><th>Score</th></tr>{fw}</table><br>{det}</section>""")
    ly = d.get("lynis")
    if ly:
        lr = "".join(f"<tr><td>{badge('Warning', 'ko')}</td><td><b>{esc(w['id'])}</b></td><td>{esc(w['text'])}</td></tr>"
                     for w in ly["warnings"][:15])
        lr += "".join(f"<tr><td>{badge('Suggestion', 'na')}</td><td><b>{esc(s2['id'])}</b></td><td>{esc(s2['text'])}</td></tr>"
                      for s2 in ly["suggestions"][:15])
        parts.append(f"""<section><h2>11. PRODUCTION — Server Hardening (Lynis)</h2>
<p class="intro">Audit du serveur qui exécute le pipeline ({esc(ly.get('os', ''))}).
Hardening Index {badge(str(ly['index']) + '/100', 'ok' if ly['index'] >= ly.get('minimum', 50) else 'warn')}
(minimum {esc(ly.get('minimum'))}). {len(ly['warnings'])} avertissement(s), {len(ly['suggestions'])} suggestion(s). Non bloquant.</p>
<table><tr><th>Type</th><th>Test</th><th>Détail</th></tr>{lr}</table></section>""")
    fa = d.get("falco")
    if fa:
        fr = "".join(f"<tr><td>{esc(n)}</td><td>{esc(r)}</td></tr>" for r, n in fa.get("rules", [])[:15])
        det = (f"<table><tr><th>Occurrences</th><th>Règle Falco déclenchée</th></tr>{fr}</table>"
               if fr else '<div class="empty" style="background:var(--kobg);color:var(--ko)">Aucune alerte : la détection ne fonctionne pas.</div>')
        parts.append(f"""<section><h2>12. PRODUCTION — Host Intrusion Detection (Falco)</h2>
<p class="intro">Le pipeline simule un comportement d'attaquant dans le pod <code>{esc(fa.get('targetPod', ''))}</code>
(lecture de fichiers d'authentification, recherche de clés privées) et vérifie que Falco le détecte en temps réel.
{fa['total']} alerte(s), dont {fa.get('onTargetPod', 0)} sur le pod ciblé. Non bloquant.</p>{det}</section>""")
    to = d.get("trivyop")
    if to:
        ir = "".join(f"<tr><td><code>{esc(r['image'])}</code></td><td>{esc(r['workload'])}</td><td>{r['critical']}</td>"
                     f"<td>{r['high']}</td><td>{r['medium']}</td><td>{r['low']}</td></tr>" for r in to["images"])
        app = to.get("appImage")
        apptxt = (f"Image du build <code>{esc(app['image'])}</code> : Critical {app['critical']} · High {app['high']}."
                  if app else "Le rapport de l'image du build n'était pas encore disponible (scan en cours).")
        parts.append(f"""<section><h2>13. OPERATIONS — Continuous Scanning (Trivy Operator)</h2>
<p class="intro">Scan permanent des images <b>réellement en exécution</b> dans le namespace, y compris les images tierces
(MySQL, Prometheus, Grafana) que le pipeline ne construit pas. {apptxt} Secrets exposés : {to['secrets']}. Non bloquant.</p>
<table><tr><th>Image</th><th>Workload</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr>{ir}</table></section>""")
    pm = d.get("prom")
    if pm:
        tr = "".join(f"<tr><td>{esc(t['job'])}</td><td>{badge(t['health'].upper(), 'ok' if t['health'] == 'up' else 'ko')}</td>"
                     f"<td class='muted'>{esc(t['error'])}</td></tr>" for t in pm["targets"])
        ar = "".join(f"<tr><td>{badge(a['severity'] or '?', 'ko' if a['severity'] == 'critical' else 'warn')}</td>"
                     f"<td><b>{esc(a['name'])}</b></td><td>{esc(a['summary'])}</td></tr>" for a in pm["firing"])
        al = (f"<table><tr><th>Sévérité</th><th>Alerte active</th><th>Résumé</th></tr>{ar}</table>"
              if ar else '<div class="empty">Aucune alerte Prometheus active.</div>')
        parts.append(f"""<section><h2>14. OPERATIONS — Continuous Monitoring (Prometheus &amp; Grafana)</h2>
<p class="intro">{pm['up']}/{pm['total']} cibles supervisées UP · {pm['rules']} règles d'alerte (disponibilité + sécurité) ·
Grafana {badge('OK', 'ok') if pm['grafana'] else badge('KO', 'ko')}. Non bloquant.</p>
<table><tr><th>Cible</th><th>État</th><th>Erreur</th></tr>{tr}</table><br>{al}</section>""")
 
    parts.append("""<section><h2>Rapports bruts</h2><p class="links">
<a href="trivy-sca.txt">trivy-sca.txt</a><a href="trivy-iac.txt">trivy-iac.txt</a>
<a href="trivy-image.txt">trivy-image.txt</a><a href="sbom-cyclonedx.json">sbom-cyclonedx.json</a>
<a href="zap-report.html">zap-report.html</a><a href="secret-scan.txt">secret-scan.txt</a>
<a href="gauntlt.txt">gauntlt.txt</a><a href="kubescape.txt">kubescape.txt</a><a href="lynis.txt">lynis.txt</a>
<a href="falco.txt">falco.txt</a><a href="trivy-operator-summary.txt">trivy-operator-summary.txt</a>
<a href="prometheus-summary.txt">prometheus-summary.txt</a></p></section>""")
    parts.append(f"<footer>Rapport généré automatiquement par ci/devsecops_report.py — {now}</footer></div></body></html>")
    return "\n".join(parts)
 
 
# ----------------------------------------------------------------------------
# Résumé texte (console Jenkins) + ligne courte
# ----------------------------------------------------------------------------
def render_text(d):
    lines = ["=" * 100, " RAPPORT DEVSECOPS — résumé par stage", "=" * 100,
             f" {'#':<3}{'STAGE':<38}{'STATUT':<11}{'DURÉE':<12}RÉSULTAT CLÉ", "-" * 100]
    for i, r in enumerate(d["rows"], 1):
        lines.append(f" {i:<3}{r['name'][:37]:<38}{r['status']:<11}{fmt_dur(r['duration']):<12}{r['key']}")
    lines.append("=" * 100)
    return "\n".join(lines)
 
 
def summary_line(d):
    p = [f"QG {d['qg']}"]
    if d["tests"]:
        t = d["tests"]
        p.append(f"Tests {t['tests'] - t['failures'] - t['errors'] - t['skipped']}/{t['tests']}")
    if d["cov"]:
        p.append(f"Cov {d['cov'].get('LINE', 0)}%")
    if d["sca"] is not None:
        p.append(f"SCA {d['sca']['total']}")
    if d["img"] is not None:
        p.append(f"Image {d['img']['total']}")
    if d["iac"] is not None:
        p.append(f"IaC {d['iac']['total']}")
    if d["zap"] is not None:
        c = d["zap"]["counts"]
        p.append(f"ZAP H{c['High']}/M{c['Medium']}/L{c['Low']}")
    if d.get("gauntlt") is not None:
        g = d["gauntlt"]
        p.append(f"Gauntlt {g['passed']}/{g['scenarios']}")
    if d.get("kubescape"):
        p.append(f"Kubescape {d['kubescape'].get('score')}%")
    if d.get("lynis"):
        p.append(f"Lynis {d['lynis']['index']}")
    if d.get("falco"):
        p.append(f"Falco {d['falco']['total']}")
    if d.get("trivyop"):
        t2 = d["trivyop"]["totals"]
        p.append(f"TrivyOp C{t2['critical']}/H{t2['high']}")
    if d.get("prom"):
        p.append(f"Prom {d['prom']['up']}/{d['prom']['total']}")
    return " | ".join(p)
 
 
def main():
    os.makedirs(REPORTS, exist_ok=True)
    d = build()
    with open(path("devsecops-report.css"), "w", encoding="utf-8") as f:
        f.write(CSS)
    page = render_html(d)
    with open(path("devsecops-report.html"), "w", encoding="utf-8") as f:
        f.write(page)
    # Version autonome (CSS intégré) : corps de l'e-mail + pièce jointe
    standalone = page.replace('<link rel="stylesheet" href="devsecops-report.css">', "<style>" + CSS + "</style>")
    with open(path("devsecops-report-email.html"), "w", encoding="utf-8") as f:
        f.write(standalone)
    txt = render_text(d)
    with open(path("devsecops-summary.txt"), "w", encoding="utf-8") as f:
        f.write(txt + "\n")
    with open(path("summary-line.txt"), "w", encoding="utf-8") as f:
        f.write(summary_line(d) + "\n")
    print(txt)
    print("Rapport HTML : " + path("devsecops-report.html"))
 
 
if __name__ == "__main__":
    main()
 


