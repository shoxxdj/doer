#!/usr/bin/env python3
"""
Module d'analyse de sécurité des en-têtes HTTP
Analyse les en-têtes retournés par une URL, détecte les fuites d'informations,
les défauts de configuration et les manques de sécurité.
"""

import sys
import re
import requests
import urllib3
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse

# Désactive les avertissements SSL pour les tests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ─────────────────────────────────────────────
# Dataclasses
# ─────────────────────────────────────────────

@dataclass
class HeaderFinding:
    """Représente un résultat d'analyse pour un en-tête"""
    header: str
    value: Optional[str]
    category: str          # 'leak', 'missing', 'misconfigured', 'ok'
    severity: str          # 'critical', 'high', 'medium', 'low', 'info'
    message: str
    recommendation: str = ""


@dataclass
class HttpHeadersAnalysis:
    """Résultat complet de l'analyse des en-têtes HTTP"""
    url: str
    status_code: Optional[int] = None
    raw_headers: Dict[str, str] = field(default_factory=dict)
    findings: List[HeaderFinding] = field(default_factory=list)
    leaks: List[HeaderFinding] = field(default_factory=list)
    missing_security: List[HeaderFinding] = field(default_factory=list)
    misconfigurations: List[HeaderFinding] = field(default_factory=list)
    condition: Optional[str] = None
    score: int = 100
    summary: str = ""
    warnings: List[str] = field(default_factory=list)


# ─────────────────────────────────────────────
# Analyseur principal
# ─────────────────────────────────────────────

class HttpHeadersAnalyzer:
    """Analyseur de sécurité des en-têtes HTTP"""

    # En-têtes de sécurité obligatoires et leur analyse
    REQUIRED_SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'severity': 'high',
            'recommendation': (
                "Ajouter : Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n"
                "  Force les navigateurs à utiliser HTTPS exclusivement."
            ),
        },
        'Content-Security-Policy': {
            'severity': 'high',
            'recommendation': (
                "Définir une CSP stricte, ex: Content-Security-Policy: default-src 'self'\n"
                "  Réduit drastiquement le risque de XSS et d'injection de contenu."
            ),
        },
        'X-Content-Type-Options': {
            'severity': 'medium',
            'recommendation': (
                "Ajouter : X-Content-Type-Options: nosniff\n"
                "  Empêche le navigateur de deviner le type MIME."
            ),
        },
        'X-Frame-Options': {
            'severity': 'medium',
            'recommendation': (
                "Ajouter : X-Frame-Options: DENY  (ou SAMEORIGIN)\n"
                "  Protège contre le clickjacking. Peut être remplacé par frame-ancestors dans la CSP."
            ),
        },
        'Referrer-Policy': {
            'severity': 'low',
            'recommendation': (
                "Ajouter : Referrer-Policy: strict-origin-when-cross-origin\n"
                "  Contrôle les informations transmises via l'en-tête Referer."
            ),
        },
        'Permissions-Policy': {
            'severity': 'low',
            'recommendation': (
                "Ajouter : Permissions-Policy: geolocation=(), microphone=(), camera=()\n"
                "  Limite l'accès aux API sensibles du navigateur."
            ),
        },
        'Cross-Origin-Opener-Policy': {
            'severity': 'low',
            'recommendation': (
                "Ajouter : Cross-Origin-Opener-Policy: same-origin\n"
                "  Isole le contexte de navigation pour prévenir les attaques Spectre."
            ),
        },
        'Cross-Origin-Resource-Policy': {
            'severity': 'low',
            'recommendation': (
                "Ajouter : Cross-Origin-Resource-Policy: same-origin\n"
                "  Empêche d'autres origines d'intégrer vos ressources."
            ),
        },
    }

    # En-têtes pouvant révéler des informations techniques sensibles
    LEAK_HEADERS = {
        'Server': {
            'severity': 'medium',
            'pattern': None,  # Toute valeur est une fuite potentielle
            'message': "Révèle le logiciel serveur et potentiellement sa version.",
            'recommendation': "Supprimer ou neutraliser cet en-tête (ex: \"Server: Apache\" → vide ou \"Server: -).",
        },
        'X-Powered-By': {
            'severity': 'medium',
            'pattern': None,
            'message': "Révèle le framework ou le langage utilisé côté serveur.",
            'recommendation': "Supprimer X-Powered-By (désactivable dans la config PHP, Express, etc.).",
        },
        'X-AspNet-Version': {
            'severity': 'medium',
            'pattern': None,
            'message': "Révèle la version d'ASP.NET utilisée.",
            'recommendation': "Supprimer en ajoutant <httpRuntime enableVersionHeader=\"false\"/> dans web.config.",
        },
        'X-AspNetMvc-Version': {
            'severity': 'medium',
            'pattern': None,
            'message': "Révèle la version d'ASP.NET MVC.",
            'recommendation': "Supprimer via MvcHandler.DisableMvcResponseHeader = true;",
        },
        'X-Generator': {
            'severity': 'low',
            'pattern': None,
            'message': "Révèle le générateur de contenu (CMS, framework...).",
            'recommendation': "Supprimer ou neutraliser cet en-tête dans la configuration du CMS.",
        },
        'X-Drupal-Cache': {
            'severity': 'low',
            'pattern': None,
            'message': "Révèle l'utilisation de Drupal.",
            'recommendation': "Supprimer ou masquer les en-têtes spécifiques à Drupal.",
        },
        'X-Varnish': {
            'severity': 'low',
            'pattern': None,
            'message': "Révèle l'utilisation de Varnish Cache et expose des identifiants internes.",
            'recommendation': "Supprimer ou remplacer par un en-tête neutre.",
        },
        'Via': {
            'severity': 'low',
            'pattern': None,
            'message': "Révèle les proxies ou CDN intermédiaires utilisés.",
            'recommendation': "Supprimer ou neutraliser selon la politique de confidentialité.",
        },
        'X-Cache': {
            'severity': 'info',
            'pattern': None,
            'message': "Révèle l'infrastructure de cache.",
            'recommendation': "Évaluer si cet en-tête doit être exposé publiquement.",
        },
        'X-Backend-Server': {
            'severity': 'high',
            'pattern': None,
            'message': "Révèle le nom ou l'adresse du serveur backend — fuite d'infrastructure critique.",
            'recommendation': "Supprimer immédiatement cet en-tête dans la configuration du load balancer / proxy.",
        },
        'X-Real-IP': {
            'severity': 'medium',
            'pattern': None,
            'message': "Peut révéler l'adresse IP réelle d'un client ou d'un serveur interne.",
            'recommendation': "Supprimer en contexte de réponse public.",
        },
        'X-Forwarded-For': {
            'severity': 'info',
            'pattern': None,
            'message': "Révèle les adresses IP de la chaîne de proxies.",
            'recommendation': "Vérifier que cet en-tête n'expose pas des IPs internes.",
        },
        'X-Debug-Token': {
            'severity': 'high',
            'pattern': None,
            'message': "Révèle un token de debug Symfony — mode debug probablement actif.",
            'recommendation': "Désactiver le mode debug en production.",
        },
        'X-Debug-Token-Link': {
            'severity': 'high',
            'pattern': None,
            'message': "Expose un lien vers la barre de debug Symfony — mode debug actif en production.",
            'recommendation': "Désactiver APP_DEBUG=false et supprimer le profiler en production.",
        },
        'X-Application-Context': {
            'severity': 'medium',
            'pattern': None,
            'message': "Révèle le contexte applicatif (Spring Boot par exemple).",
            'recommendation': "Supprimer cet en-tête en production.",
        },
    }

    # Patterns de version dans les en-têtes (renforce la gravité)
    VERSION_PATTERN = re.compile(
        r'\b(\d+\.\d+[\.\d]*)\b|'       # 1.2.3
        r'(v\d+[\.\d]*)\b|'             # v1.2
        r'(PHP/[\d\.]+)|'               # PHP/7.4
        r'(Apache/[\d\.]+)|'            # Apache/2.4
        r'(nginx/[\d\.]+)|'             # nginx/1.18
        r'(OpenSSL/[\S]+)',             # OpenSSL/1.1.1
        re.IGNORECASE
    )

    # Analyse de la valeur HSTS
    HSTS_MIN_AGE = 15552000  # 6 mois en secondes

    def __init__(self, url: str, timeout: int = 10, verify_ssl: bool = False,
                 follow_redirects: bool = False):
        self.url = url
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.analysis = HttpHeadersAnalysis(url=url)

        if not self.url.startswith(('http://', 'https://')):
            self.url = f'https://{self.url}'

    # ─── Collecte des en-têtes ───────────────────

    def fetch_headers(self) -> bool:
        """Effectue la requête HTTP et collecte les en-têtes."""
        try:
            response = requests.get(
                self.url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=self.follow_redirects,
                headers={'User-Agent': 'Mozilla/5.0 (SecurityScanner/1.0)'}
            )
            self.analysis.status_code = response.status_code
            # Normalise les clés en Title-Case pour comparaisons insensibles à la casse
            self.analysis.raw_headers = {k: v for k, v in response.headers.items()}
            return True

        except requests.exceptions.SSLError as e:
            self.analysis.warnings.append(f"Erreur SSL : {e}. Relancez avec --no-verify-ssl.")
        except requests.exceptions.Timeout:
            self.analysis.warnings.append("Timeout : le serveur n'a pas répondu dans le délai imparti.")
        except requests.exceptions.ConnectionError as e:
            self.analysis.warnings.append(f"Erreur de connexion : {e}")
        except Exception as e:
            self.analysis.warnings.append(f"Erreur inattendue : {e}")
        return False

    # ─── Helpers ─────────────────────────────────

    def _get_header(self, name: str) -> Optional[str]:
        """Récupère un en-tête de façon insensible à la casse."""
        for k, v in self.analysis.raw_headers.items():
            if k.lower() == name.lower():
                return v
        return None

    def _header_present(self, name: str) -> bool:
        return self._get_header(name) is not None

    def _contains_version(self, value: str) -> bool:
        return bool(self.VERSION_PATTERN.search(value))

    # ─── Analyses thématiques ─────────────────────

    def check_information_leaks(self) -> None:
        """Détecte les en-têtes qui fuient des informations techniques."""
        for header_name, meta in self.LEAK_HEADERS.items():
            value = self._get_header(header_name)
            if value is None:
                continue

            severity = meta['severity']
            message = meta['message']

            # Si la valeur contient un numéro de version, on aggrave
            if self._contains_version(value):
                severity = _escalate_severity(severity)
                message += f" De plus, une version précise est exposée : « {value} »."

            finding = HeaderFinding(
                header=header_name,
                value=value,
                category='leak',
                severity=severity,
                message=message,
                recommendation=meta['recommendation'],
            )
            self.analysis.findings.append(finding)
            self.analysis.leaks.append(finding)

    def check_missing_security_headers(self) -> None:
        """Vérifie l'absence des en-têtes de sécurité essentiels."""
        for header_name, meta in self.REQUIRED_SECURITY_HEADERS.items():
            if not self._header_present(header_name):
                finding = HeaderFinding(
                    header=header_name,
                    value=None,
                    category='missing',
                    severity=meta['severity'],
                    message=f"En-tête de sécurité absent : {header_name}.",
                    recommendation=meta['recommendation'],
                )
                self.analysis.findings.append(finding)
                self.analysis.missing_security.append(finding)

    def check_misconfigurations(self) -> None:
        """Analyse la valeur des en-têtes de sécurité présents pour détecter les erreurs."""

        # ── HSTS ──────────────────────────────────────────────────────────
        hsts = self._get_header('Strict-Transport-Security')
        if hsts:
            issues = []
            # max-age
            m = re.search(r'max-age\s*=\s*(\d+)', hsts, re.IGNORECASE)
            if m:
                age = int(m.group(1))
                if age < self.HSTS_MIN_AGE:
                    issues.append(
                        f"max-age trop court ({age}s < {self.HSTS_MIN_AGE}s recommandé)."
                    )
                if age == 0:
                    issues.append("max-age=0 désactive effectivement HSTS !")
            else:
                issues.append("Directive max-age manquante.")
            if 'includesubdomains' not in hsts.lower():
                issues.append("includeSubDomains absent — les sous-domaines ne sont pas protégés.")
            if issues:
                self._add_misconfig(
                    'Strict-Transport-Security', hsts, 'medium',
                    "Configuration HSTS insuffisante : " + " | ".join(issues),
                    "Utiliser : Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
                )

        # ── CSP ───────────────────────────────────────────────────────────
        csp = self._get_header('Content-Security-Policy')
        if csp:
            issues = []
            csp_lower = csp.lower()
            if 'unsafe-inline' in csp_lower:
                issues.append("'unsafe-inline' autorisé — neutralise la protection XSS.")
            if 'unsafe-eval' in csp_lower:
                issues.append("'unsafe-eval' autorisé — permet l'exécution de code dynamique.")
            if "default-src *" in csp_lower or "script-src *" in csp_lower:
                issues.append("Wildcard '*' dans default-src ou script-src — CSP inefficace.")
            if 'default-src' not in csp_lower and 'script-src' not in csp_lower:
                issues.append("Aucune directive default-src ou script-src définie.")
            if issues:
                self._add_misconfig(
                    'Content-Security-Policy', csp, 'high',
                    "CSP présente mais contient des faiblesses : " + " | ".join(issues),
                    "Supprimer 'unsafe-inline'/'unsafe-eval', utiliser des nonces ou hashes."
                )

        # ── X-Frame-Options ───────────────────────────────────────────────
        xfo = self._get_header('X-Frame-Options')
        if xfo:
            xfo_upper = xfo.strip().upper()
            if xfo_upper not in ('DENY', 'SAMEORIGIN'):
                self._add_misconfig(
                    'X-Frame-Options', xfo, 'medium',
                    f"Valeur non standard : « {xfo} ». Seules DENY et SAMEORIGIN sont reconnues.",
                    "Utiliser X-Frame-Options: DENY ou SAMEORIGIN."
                )
            if 'ALLOW-FROM' in xfo_upper:
                self._add_misconfig(
                    'X-Frame-Options', xfo, 'low',
                    "ALLOW-FROM est obsolète et ignoré par la plupart des navigateurs modernes.",
                    "Remplacer par frame-ancestors dans la Content-Security-Policy."
                )

        # ── X-Content-Type-Options ────────────────────────────────────────
        xcto = self._get_header('X-Content-Type-Options')
        if xcto and xcto.strip().lower() != 'nosniff':
            self._add_misconfig(
                'X-Content-Type-Options', xcto, 'low',
                f"Valeur inattendue « {xcto} ». Seule la valeur « nosniff » est valide.",
                "Utiliser exactement : X-Content-Type-Options: nosniff"
            )

        # ── Cookie flags ─────────────────────────────────────────────────
        for header_name in ('Set-Cookie',):
            value = self._get_header(header_name)
            if value:
                issues = []
                val_lower = value.lower()
                if 'secure' not in val_lower:
                    issues.append("flag Secure absent — cookie transmissible en HTTP clair.")
                if 'httponly' not in val_lower:
                    issues.append("flag HttpOnly absent — cookie accessible via JavaScript (risque XSS).")
                if 'samesite' not in val_lower:
                    issues.append("flag SameSite absent — risque CSRF.")
                elif 'samesite=none' in val_lower and 'secure' not in val_lower:
                    issues.append("SameSite=None sans Secure est invalide.")
                if issues:
                    self._add_misconfig(
                        'Set-Cookie', value, 'high',
                        "Cookie mal configuré : " + " | ".join(issues),
                        "Ajouter les flags : Set-Cookie: ...; Secure; HttpOnly; SameSite=Strict"
                    )

        # ── Cache-Control sur réponses sensibles ─────────────────────────
        cc = self._get_header('Cache-Control')
        if cc:
            cc_lower = cc.lower()
            if 'no-store' not in cc_lower and 'private' not in cc_lower:
                self._add_misconfig(
                    'Cache-Control', cc,
                    'low',
                    "La politique de cache ne prévient pas explicitement la mise en cache de données sensibles.",
                    "Pour les pages authentifiées : Cache-Control: no-store, no-cache, must-revalidate"
                )

        # ── Access-Control-Allow-Origin ───────────────────────────────────
        acao = self._get_header('Access-Control-Allow-Origin')
        if acao and acao.strip() == '*':
            self._add_misconfig(
                'Access-Control-Allow-Origin', acao, 'medium',
                "CORS ouvert à toutes les origines (*) — toute origine peut lire les réponses.",
                "Restreindre à l'origine légitime : Access-Control-Allow-Origin: https://votredomaine.com"
            )

        # ── Access-Control-Allow-Credentials + wildcard ───────────────────
        acac = self._get_header('Access-Control-Allow-Credentials')
        if acac and acac.strip().lower() == 'true' and acao == '*':
            self._add_misconfig(
                'Access-Control-Allow-Credentials', acac, 'critical',
                "CORS : Access-Control-Allow-Credentials: true avec Allow-Origin: * est invalide "
                "et peut exposer des données authentifiées.",
                "Ne jamais combiner credentials:true avec wildcard. Spécifier une origine précise."
            )

        # ── HTTP sur HTTPS attendu ────────────────────────────────────────
        parsed = urlparse(self.url)
        if parsed.scheme == 'https':
            hsts_val = self._get_header('Strict-Transport-Security')
            if not hsts_val:
                self._add_misconfig(
                    'Strict-Transport-Security', None, 'high',
                    "Le site est servi en HTTPS mais ne renvoie pas d'en-tête HSTS.",
                    "Ajouter : Strict-Transport-Security: max-age=31536000; includeSubDomains"
                )

        # ── Deprecation / Legacy headers ─────────────────────────────────
        xss_protection = self._get_header('X-XSS-Protection')
        if xss_protection:
            val = xss_protection.strip()
            if val not in ('0',):
                self._add_misconfig(
                    'X-XSS-Protection', xss_protection, 'low',
                    "X-XSS-Protection est obsolète. Une valeur non nulle peut créer des "
                    "vulnérabilités dans certains navigateurs.",
                    "Remplacer par une CSP robuste. Définir X-XSS-Protection: 0 pour désactiver."
                )

    def _add_misconfig(self, header: str, value: Optional[str], severity: str,
                       message: str, recommendation: str) -> None:
        finding = HeaderFinding(
            header=header,
            value=value,
            category='misconfigured',
            severity=severity,
            message=message,
            recommendation=recommendation,
        )
        self.analysis.findings.append(finding)
        self.analysis.misconfigurations.append(finding)

    # ─── Score & condition ───────────────────────

    SEVERITY_DEDUCTIONS = {
        'critical': 25,
        'high': 15,
        'medium': 8,
        'low': 3,
        'info': 0,
    }

    def compute_score(self) -> int:
        """Calcule un score de sécurité de 0 à 100."""
        score = 100
        for f in self.analysis.findings:
            score -= self.SEVERITY_DEDUCTIONS.get(f.severity, 0)
        self.analysis.score = max(0, score)
        return self.analysis.score

    def evaluate_condition(self) -> str:
        """Évalue la condition globale basée sur le score."""
        score = self.analysis.score
        if score >= 85:
            self.analysis.condition = 'secure'
        elif score >= 65:
            self.analysis.condition = 'moderate'
        elif score >= 40:
            self.analysis.condition = 'warning'
        else:
            self.analysis.condition = 'critical'
        return self.analysis.condition

    # ─── Résumé textuel ──────────────────────────

    SEVERITY_ICONS = {
        'critical': '🔴',
        'high':     '🟠',
        'medium':   '🟡',
        'low':      '🔵',
        'info':     '⚪',
    }

    CONDITION_ICONS = {
        'secure':   '✅',
        'moderate': '🟡',
        'warning':  '⚠️ ',
        'critical': '🚨',
    }

    def generate_summary(self) -> str:
        lines = []
        sep = "─" * 60

        lines.append("╔══════════════════════════════════════════════════════════╗")
        lines.append("║       Analyse de sécurité des en-têtes HTTP              ║")
        lines.append("╚══════════════════════════════════════════════════════════╝")
        lines.append(f"URL analysée  : {self.url}")
        lines.append(f"Code HTTP     : {self.analysis.status_code or 'N/A'}")
        lines.append(f"Score         : {self.analysis.score}/100")
        cond_icon = self.CONDITION_ICONS.get(self.analysis.condition or '', '')
        lines.append(f"Condition     : {cond_icon} {(self.analysis.condition or 'inconnue').upper()}")
        lines.append(sep)

        # En-têtes bruts
        lines.append("\n📋 EN-TÊTES REÇUS :")
        for k, v in sorted(self.analysis.raw_headers.items()):
            lines.append(f"  {k}: {v}")

        # Fuites
        lines.append(f"\n{sep}")
        lines.append(f"🕵️  FUITES D'INFORMATIONS ({len(self.analysis.leaks)}) :")
        if self.analysis.leaks:
            for f in self.analysis.leaks:
                icon = self.SEVERITY_ICONS.get(f.severity, '•')
                lines.append(f"  {icon} [{f.severity.upper()}] {f.header}: {f.value}")
                lines.append(f"     → {f.message}")
                lines.append(f"     ✏  {f.recommendation}")
        else:
            lines.append("  ✅ Aucune fuite détectée.")

        # En-têtes de sécurité manquants
        lines.append(f"\n{sep}")
        lines.append(f"🔒 EN-TÊTES DE SÉCURITÉ MANQUANTS ({len(self.analysis.missing_security)}) :")
        if self.analysis.missing_security:
            for f in self.analysis.missing_security:
                icon = self.SEVERITY_ICONS.get(f.severity, '•')
                lines.append(f"  {icon} [{f.severity.upper()}] {f.header}")
                lines.append(f"     → {f.message}")
                lines.append(f"     ✏  {f.recommendation}")
        else:
            lines.append("  ✅ Tous les en-têtes de sécurité essentiels sont présents.")

        # Mauvaises configurations
        lines.append(f"\n{sep}")
        lines.append(f"⚙️  MAUVAISES CONFIGURATIONS ({len(self.analysis.misconfigurations)}) :")
        if self.analysis.misconfigurations:
            for f in self.analysis.misconfigurations:
                icon = self.SEVERITY_ICONS.get(f.severity, '•')
                val_str = f": {f.value}" if f.value else ""
                lines.append(f"  {icon} [{f.severity.upper()}] {f.header}{val_str}")
                lines.append(f"     → {f.message}")
                lines.append(f"     ✏  {f.recommendation}")
        else:
            lines.append("  ✅ Aucune mauvaise configuration détectée.")

        # Avertissements techniques
        if self.analysis.warnings:
            lines.append(f"\n{sep}")
            lines.append("⚠️  AVERTISSEMENTS TECHNIQUES :")
            for w in self.analysis.warnings:
                lines.append(f"  - {w}")

        # Comptage par sévérité
        lines.append(f"\n{sep}")
        lines.append("📊 RÉCAPITULATIF PAR SÉVÉRITÉ :")
        counts = _count_by_severity(self.analysis.findings)
        for sev in ('critical', 'high', 'medium', 'low', 'info'):
            icon = self.SEVERITY_ICONS[sev]
            lines.append(f"  {icon} {sev.upper():10} : {counts.get(sev, 0)}")

        lines.append(sep)

        self.analysis.summary = '\n'.join(lines)
        return self.analysis.summary

    # ─── Orchestration ───────────────────────────

    def analyze(self) -> bool:
        """Effectue l'analyse complète."""
        if not self.fetch_headers():
            return False

        self.check_information_leaks()
        self.check_missing_security_headers()
        self.check_misconfigurations()
        self.compute_score()
        self.evaluate_condition()
        self.generate_summary()
        return True

    def to_dict(self) -> Dict:
        """Retourne l'analyse sous forme de dictionnaire sérialisable."""
        return {
            'url': self.url,
            'status_code': self.analysis.status_code,
            'score': self.analysis.score,
            'condition': self.analysis.condition,
            'raw_headers': self.analysis.raw_headers,
            'findings': [
                {
                    'header': f.header,
                    'value': f.value,
                    'category': f.category,
                    'severity': f.severity,
                    'message': f.message,
                    'recommendation': f.recommendation,
                }
                for f in self.analysis.findings
            ],
            'leaks_count': len(self.analysis.leaks),
            'missing_security_count': len(self.analysis.missing_security),
            'misconfigurations_count': len(self.analysis.misconfigurations),
            'summary': self.analysis.summary,
            'warnings': self.analysis.warnings,
        }


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

_SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical']


def _escalate_severity(severity: str) -> str:
    """Augmente la sévérité d'un cran."""
    idx = _SEVERITY_ORDER.index(severity) if severity in _SEVERITY_ORDER else 0
    return _SEVERITY_ORDER[min(idx + 1, len(_SEVERITY_ORDER) - 1)]


def _count_by_severity(findings: List[HeaderFinding]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


# ─────────────────────────────────────────────
# API publique
# ─────────────────────────────────────────────

def analyze_http_headers(url: str, timeout: int = 10, verify_ssl: bool = False,
                         follow_redirects: bool = False) -> Optional[Dict]:
    """
    Analyse de sécurité des en-têtes HTTP d'une URL.

    Args:
        url: URL à analyser
        timeout: Délai maximum en secondes
        verify_ssl: Vérifier les certificats SSL
        follow_redirects: Suivre les redirections

    Returns:
        Dictionnaire avec les résultats, ou None en cas d'erreur fatale
    """
    try:
        analyzer = HttpHeadersAnalyzer(url, timeout, verify_ssl, follow_redirects)
        success = analyzer.analyze()
        if not success:
            return None
        return analyzer.to_dict()
    except Exception as e:
        print(f"Erreur lors de l'analyse : {e}", file=sys.stderr)
        return None


# ─────────────────────────────────────────────
# Entrée CLI
# ─────────────────────────────────────────────

def main():
    import argparse
    import json

    parser = argparse.ArgumentParser(
        description="Analyse de sécurité des en-têtes HTTP retournés par une URL.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  %(prog)s https://example.com
  %(prog)s https://example.com --json
  %(prog)s https://example.com --timeout 5 --no-verify-ssl
  %(prog)s https://example.com --follow-redirects
        """,
    )

    parser.add_argument('url', help="URL à analyser")
    parser.add_argument('--timeout', type=int, default=10,
                        help="Timeout des requêtes en secondes (défaut : 10)")
    parser.add_argument('--no-verify-ssl', action='store_true',
                        help="Désactiver la vérification des certificats SSL")
    parser.add_argument('--follow-redirects', action='store_true',
                        help="Suivre les redirections HTTP")
    parser.add_argument('--json', action='store_true',
                        help="Sortie au format JSON")

    args = parser.parse_args()

    result = analyze_http_headers(
        url=args.url,
        timeout=args.timeout,
        verify_ssl=not args.no_verify_ssl,
        follow_redirects=args.follow_redirects,
    )

    if not result:
        print("Échec de l'analyse des en-têtes HTTP.", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(result['summary'])
        print()
        print("=" * 60)
        print(f"Score de sécurité : {result['score']}/100  |  Condition : {result['condition'].upper()}")
        print(f"Fuites : {result['leaks_count']}  |  Manquants : {result['missing_security_count']}  |  Mauvaises configs : {result['misconfigurations_count']}")
        print("=" * 60)


if __name__ == '__main__':
    main()