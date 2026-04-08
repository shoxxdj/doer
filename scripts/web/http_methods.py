#!/usr/bin/env python3
"""
Module d'analyse des méthodes HTTP autorisées
Teste toutes les méthodes HTTP et catégorise les risques
"""

import sys
import requests
import urllib3
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

# Désactive les avertissements SSL pour les tests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class HttpMethod:
    """Représente une méthode HTTP testée"""
    name: str
    allowed: bool
    status_code: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    dangerous: bool = False
    description: str = ""


@dataclass
class HttpMethodsAnalysis:
    """Résultat de l'analyse des méthodes HTTP"""
    url: str
    methods: List[HttpMethod] = field(default_factory=list)
    dangerous_allowed: List[str] = field(default_factory=list)
    safe_allowed: List[str] = field(default_factory=list)
    condition: Optional[str] = None
    summary: str = ""
    warnings: List[str] = field(default_factory=list)


class HttpMethodsAnalyzer:
    """Analyseur de méthodes HTTP"""
    
    # Méthodes HTTP standards à tester
    METHODS = [
        'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 
        'HEAD', 'OPTIONS', 'TRACE', 'CONNECT',
        'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE',
        'LOCK', 'UNLOCK', 'VERSION-CONTROL', 'REPORT',
        'CHECKOUT', 'CHECKIN', 'UNCHECKOUT', 'MKWORKSPACE',
        'UPDATE', 'LABEL', 'MERGE', 'BASELINE-CONTROL',
        'MKACTIVITY', 'ORDERPATCH', 'ACL', 'SEARCH'
    ]
    
    # Méthodes considérées comme dangereuses
    DANGEROUS_METHODS = {
        'PUT': 'Permet de télécharger des fichiers sur le serveur',
        'DELETE': 'Permet de supprimer des ressources',
        'TRACE': 'Peut révéler des informations sensibles (attaque XST)',
        'CONNECT': 'Peut être utilisé pour du tunneling',
        'PROPFIND': 'Peut révéler la structure du serveur (WebDAV)',
        'PROPPATCH': 'Peut modifier des propriétés (WebDAV)',
        'MKCOL': 'Peut créer des collections/dossiers (WebDAV)',
        'COPY': 'Peut copier des ressources (WebDAV)',
        'MOVE': 'Peut déplacer des ressources (WebDAV)',
        'LOCK': 'Peut verrouiller des ressources (WebDAV)',
        'UNLOCK': 'Peut déverrouiller des ressources (WebDAV)',
        'PATCH': 'Permet de modifier partiellement des ressources',
        'VERSION-CONTROL': 'Méthode de versioning (WebDAV)',
        'CHECKOUT': 'Méthode de versioning (WebDAV)',
        'CHECKIN': 'Méthode de versioning (WebDAV)',
        'UNCHECKOUT': 'Méthode de versioning (WebDAV)',
        'MKWORKSPACE': 'Peut créer des espaces de travail (WebDAV)',
        'MKACTIVITY': 'Méthode de versioning (WebDAV)',
        'BASELINE-CONTROL': 'Méthode de versioning (WebDAV)',
        'MERGE': 'Méthode de versioning (WebDAV)',
    }
    
    # Méthodes considérées comme sûres
    SAFE_METHODS = {
        'GET': 'Récupère des ressources (lecture seule)',
        'HEAD': 'Récupère les en-têtes (lecture seule)',
        'OPTIONS': 'Découvre les méthodes supportées',
        'POST': 'Soumet des données (usage standard)',
    }
    
    def __init__(self, url: str, timeout: int = 10, verify_ssl: bool = False):
        """
        Initialise l'analyseur
        
        Args:
            url: URL à tester
            timeout: Timeout pour les requêtes (secondes)
            verify_ssl: Vérifier les certificats SSL
        """
        self.url = url
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.analysis = HttpMethodsAnalysis(url=url)
        
        # Normalise l'URL
        if not self.url.startswith(('http://', 'https://')):
            self.url = f'http://{self.url}'
    
    def test_method(self, method: str) -> HttpMethod:
        """
        Teste une méthode HTTP spécifique
        
        Args:
            method: Nom de la méthode HTTP
            
        Returns:
            HttpMethod avec les résultats du test
        """
        http_method = HttpMethod(
            name=method,
            allowed=False,
            dangerous=method in self.DANGEROUS_METHODS,
            description=self.DANGEROUS_METHODS.get(method, self.SAFE_METHODS.get(method, ''))
        )
        
        try:
            # Effectue la requête avec la méthode spécifiée
            response = requests.request(
                method=method,
                url=self.url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False
            )
            
            http_method.status_code = response.status_code
            http_method.response_headers = dict(response.headers)
            
            # Détermine si la méthode est autorisée
            # Codes 2xx, 3xx, 401, 403 indiquent que la méthode est reconnue
            # 405 (Method Not Allowed) indique que la méthode n'est pas supportée
            # 501 (Not Implemented) indique que la méthode n'est pas implémentée
            if response.status_code in [405, 501]:
                http_method.allowed = False
            elif response.status_code < 500:
                http_method.allowed = True
            else:
                # Code 5xx autre que 501 -> on considère que c'est accepté mais erreur serveur
                http_method.allowed = True
                
        except requests.exceptions.Timeout:
            self.analysis.warnings.append(f"Timeout lors du test de {method}")
        except requests.exceptions.SSLError:
            self.analysis.warnings.append(f"Erreur SSL lors du test de {method}")
        except requests.exceptions.ConnectionError:
            self.analysis.warnings.append(f"Erreur de connexion lors du test de {method}")
        except Exception as e:
            self.analysis.warnings.append(f"Erreur lors du test de {method}: {str(e)}")
        
        return http_method
    
    def test_with_options(self) -> Set[str]:
        """
        Utilise la méthode OPTIONS pour découvrir les méthodes supportées
        
        Returns:
            Set des méthodes découvertes via OPTIONS
        """
        discovered = set()
        
        try:
            response = requests.options(
                self.url,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            # Cherche dans l'en-tête Allow
            allow_header = response.headers.get('Allow', '')
            if allow_header:
                discovered = set(m.strip().upper() for m in allow_header.split(','))
                
        except Exception as e:
            self.analysis.warnings.append(f"Erreur lors de la requête OPTIONS: {str(e)}")
        
        return discovered
    
    def analyze(self) -> None:
        """Effectue l'analyse complète des méthodes HTTP"""
        
        # Teste d'abord avec OPTIONS pour optimiser
        discovered_methods = self.test_with_options()
        
        if discovered_methods:
            self.analysis.warnings.append(
                f"Méthodes découvertes via OPTIONS: {', '.join(sorted(discovered_methods))}"
            )
        
        # Teste toutes les méthodes
        for method in self.METHODS:
            http_method = self.test_method(method)
            self.analysis.methods.append(http_method)
            
            if http_method.allowed:
                if http_method.dangerous:
                    self.analysis.dangerous_allowed.append(method)
                else:
                    self.analysis.safe_allowed.append(method)
        
        # Évalue la condition de sécurité
        self.evaluate_condition()
        
        # Génère le résumé
        self.generate_summary()
    
    def evaluate_condition(self) -> str:
        """
        Évalue la condition de sécurité basée sur les méthodes autorisées
        
        Returns:
            Condition de sécurité
        """
        dangerous_count = len(self.analysis.dangerous_allowed)
        safe_count = len(self.analysis.safe_allowed)
        
        if dangerous_count == 0:
            if safe_count <= 3:
                # Seulement GET, HEAD, POST ou OPTIONS
                self.analysis.condition = 'secure'
            else:
                self.analysis.condition = 'moderate'
        elif dangerous_count <= 2:
            self.analysis.condition = 'warning'
        else:
            self.analysis.condition = 'critical'
        
        return self.analysis.condition
    
    def generate_summary(self) -> str:
        """Génère un résumé textuel de l'analyse"""
        lines = []
        
        lines.append(f"=== Analyse des méthodes HTTP ===")
        lines.append(f"URL testée: {self.url}")
        lines.append(f"Condition de sécurité: {self.analysis.condition or 'non évaluée'}")
        lines.append(f"")
        
        # Méthodes autorisées sûres
        if self.analysis.safe_allowed:
            lines.append(f"✓ Méthodes sûres autorisées ({len(self.analysis.safe_allowed)}):")
            for method in sorted(self.analysis.safe_allowed):
                desc = self.SAFE_METHODS.get(method, '')
                lines.append(f"  - {method}: {desc}")
        else:
            lines.append(f"✓ Aucune méthode sûre autorisée")
        
        lines.append(f"")
        
        # Méthodes dangereuses autorisées
        if self.analysis.dangerous_allowed:
            lines.append(f"⚠ Méthodes dangereuses autorisées ({len(self.analysis.dangerous_allowed)}):")
            for method in sorted(self.analysis.dangerous_allowed):
                desc = self.DANGEROUS_METHODS.get(method, '')
                lines.append(f"  - {method}: {desc}")
        else:
            lines.append(f"✓ Aucune méthode dangereuse autorisée")
        
        # Avertissements
        if self.analysis.warnings:
            lines.append(f"\n⚠ Avertissements:")
            for warning in self.analysis.warnings:
                lines.append(f"  - {warning}")
        
        # Détails complets
        lines.append(f"\n=== Détails complets ===")
        for method_obj in sorted(self.analysis.methods, key=lambda x: x.name):
            status = "✓ AUTORISÉE" if method_obj.allowed else "✗ Bloquée"
            danger = " [DANGEREUSE]" if method_obj.dangerous else ""
            code = f" (HTTP {method_obj.status_code})" if method_obj.status_code else ""
            lines.append(f"{method_obj.name:20} {status}{danger}{code}")
        
        self.analysis.summary = '\n'.join(lines)
        return self.analysis.summary
    
    def to_dict(self) -> Dict:
        """Retourne l'analyse sous forme de dictionnaire"""
        return {
            'url': self.url,
            'condition': self.analysis.condition,
            'safe_allowed': sorted(self.analysis.safe_allowed),
            'dangerous_allowed': sorted(self.analysis.dangerous_allowed),
            'methods': [
                {
                    'name': m.name,
                    'allowed': m.allowed,
                    'dangerous': m.dangerous,
                    'status_code': m.status_code,
                    'description': m.description
                }
                for m in self.analysis.methods
            ],
            'summary': self.analysis.summary,
            'warnings': self.analysis.warnings
        }


def analyze_http_methods(url: str, timeout: int = 10, verify_ssl: bool = False) -> Optional[Dict]:
    """
    Fonction principale d'analyse des méthodes HTTP
    
    Args:
        url: URL à tester
        timeout: Timeout pour les requêtes
        verify_ssl: Vérifier les certificats SSL
    
    Returns:
        Dictionnaire avec les résultats de l'analyse ou None en cas d'erreur
    """
    try:
        analyzer = HttpMethodsAnalyzer(url, timeout, verify_ssl)
        analyzer.analyze()
        return analyzer.to_dict()
    except Exception as e:
        print(f"Erreur lors de l'analyse: {e}", file=sys.stderr)
        return None


def main():
    """Utilisation en ligne de commande"""
    import argparse
    import json
    
    parser = argparse.ArgumentParser(
        description='Analyse les méthodes HTTP autorisées par une URL',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Exemples:
  %(prog)s https://example.com
  %(prog)s https://example.com --json
  %(prog)s https://example.com --timeout 5 --verify-ssl
        '''
    )
    
    parser.add_argument('url', help='URL à tester')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout en secondes (défaut: 10)')
    parser.add_argument('--verify-ssl', action='store_true', help='Vérifier les certificats SSL')
    parser.add_argument('--json', action='store_true', help='Sortie au format JSON')
    
    args = parser.parse_args()
    
    # Analyse
    result = analyze_http_methods(args.url, args.timeout, args.verify_ssl)
    
    if not result:
        print("Erreur lors de l'analyse des méthodes HTTP")
        sys.exit(1)
    
    if args.json:
        # Affiche en JSON
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        # Affiche le résumé textuel
        print(result['summary'])
        
        # Affiche aussi le JSON si demandé
        print("\n" + "="*60)
        print("Résumé de sécurité:")
        print("="*60)
        print(f"Condition: {result['condition']}")
        print(f"Méthodes sûres: {', '.join(result['safe_allowed']) if result['safe_allowed'] else 'aucune'}")
        print(f"Méthodes dangereuses: {', '.join(result['dangerous_allowed']) if result['dangerous_allowed'] else 'aucune'}")


if __name__ == '__main__':
    main()
