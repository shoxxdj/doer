#!/usr/bin/env python3
"""
Module d'analyse des résultats Nmap
Peut être utilisé de manière autonome ou importé
"""

import sys
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Port:
    """Représente un port scanné"""
    number: str
    protocol: str
    state: str
    service: str = ""
    version: str = ""
    product: str = ""


@dataclass
class Host:
    """Représente un hôte scanné"""
    ip: str
    hostname: str = ""
    status: str = ""
    ports: List[Port] = field(default_factory=list)


@dataclass
class NmapAnalysis:
    """Résultat de l'analyse Nmap"""
    hosts: List[Host] = field(default_factory=list)
    total_open_ports: int = 0
    result: Optional[str] = None
    summary: str = ""
    warnings: List[str] = field(default_factory=list)


class NmapAnalyzer:
    """Analyseur de résultats Nmap"""
    
    # Définition des ports et services web connus
    WEB_PORTS = {'80', '443', '8080', '8443', '8000', '8888'}
    WEB_SERVICES = {'http', 'https', 'http-proxy', 'https-alt', 'http-alt', 'ssl/http'}
    
    # Ports critiques à surveiller
    CRITICAL_PORTS = {
        '21': 'FTP',
        '22': 'SSH',
        '23': 'Telnet',
        '25': 'SMTP',
        '53': 'DNS',
        '135': 'RPC',
        '139': 'NetBIOS',
        '445': 'SMB',
        '3306': 'MySQL',
        '3389': 'RDP',
        '5432': 'PostgreSQL',
        '5900': 'VNC',
        '27017': 'MongoDB'
    }
    
    def __init__(self):
        self.analysis = NmapAnalysis()
    
    def parse_xml(self, xml_content: str) -> bool:
        """
        Parse le contenu XML de nmap
        Retourne True si succès, False sinon
        """
        try:
            root = ET.fromstring(xml_content)
            
            # Parse chaque hôte
            for host_elem in root.findall('.//host'):
                host = self._parse_host(host_elem)
                if host:
                    self.analysis.hosts.append(host)
                    self.analysis.total_open_ports += len(host.ports)
            
            return True
        except ET.ParseError as e:
            self.analysis.warnings.append(f"Erreur de parsing XML: {e}")
            return False
        except Exception as e:
            self.analysis.warnings.append(f"Erreur lors de l'analyse: {e}")
            return False
    
    def _parse_host(self, host_elem) -> Optional[Host]:
        """Parse un élément host du XML"""
        try:
            # Récupère l'adresse IP
            address_elem = host_elem.find('.//address[@addrtype="ipv4"]')
            if address_elem is None:
                address_elem = host_elem.find('.//address')
            
            if address_elem is None:
                return None
            
            ip = address_elem.get('addr', '')
            
            # Récupère le hostname si disponible
            hostname = ""
            hostname_elem = host_elem.find('.//hostname')
            if hostname_elem is not None:
                hostname = hostname_elem.get('name', '')
            
            # Récupère le statut
            status_elem = host_elem.find('.//status')
            status = status_elem.get('state', 'unknown') if status_elem is not None else 'unknown'
            
            # Parse les ports
            ports = []
            for port_elem in host_elem.findall('.//port'):
                port = self._parse_port(port_elem)
                if port and port.state == 'open':
                    ports.append(port)
            
            return Host(
                ip=ip,
                hostname=hostname,
                status=status,
                ports=ports
            )
        except Exception as e:
            self.analysis.warnings.append(f"Erreur parsing hôte: {e}")
            return None
    
    def _parse_port(self, port_elem) -> Optional[Port]:
        """Parse un élément port du XML"""
        try:
            port_id = port_elem.get('portid', '')
            protocol = port_elem.get('protocol', 'tcp')
            
            # État du port
            state_elem = port_elem.find('state')
            state = state_elem.get('state', 'unknown') if state_elem is not None else 'unknown'
            
            # Informations sur le service
            service_elem = port_elem.find('service')
            service = ""
            version = ""
            product = ""
            
            if service_elem is not None:
                service = service_elem.get('name', '')
                version = service_elem.get('version', '')
                product = service_elem.get('product', '')
            
            return Port(
                number=port_id,
                protocol=protocol,
                state=state,
                service=service,
                version=version,
                product=product
            )
        except Exception as e:
            self.analysis.warnings.append(f"Erreur parsing port: {e}")
            return None
    
    def parse_text(self, text_content: str) -> bool:
        """
        Parse le contenu texte de nmap (format simple)
        Retourne True si succès, False sinon
        """
        try:
            current_host = None
            
            for line in text_content.split('\n'):
                line = line.strip()
                
                # Détection d'un nouvel hôte
                if 'Nmap scan report for' in line:
                    if current_host:
                        self.analysis.hosts.append(current_host)
                    
                    # Extraction IP
                    parts = line.split()
                    ip = parts[-1].strip('()')
                    current_host = Host(ip=ip)
                
                # Détection d'un port ouvert
                elif current_host and '/tcp' in line and 'open' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        port_info = parts[0].split('/')
                        port_number = port_info[0]
                        state = parts[1]
                        service = parts[2] if len(parts) > 2 else ''
                        
                        port = Port(
                            number=port_number,
                            protocol='tcp',
                            state=state,
                            service=service
                        )
                        current_host.ports.append(port)
                        self.analysis.total_open_ports += 1
            
            # Ajoute le dernier hôte
            if current_host:
                self.analysis.hosts.append(current_host)
            
            return True
        except Exception as e:
            self.analysis.warnings.append(f"Erreur parsing texte: {e}")
            return False
    
    def evaluate_result(self) -> str:
        """
        Évalue la result basée sur les résultats
        Retourne 'web_only', 'many_ports_open', 'critical_exposure', ou None
        """
        if self.analysis.total_open_ports == 0:
            self.analysis.result = None
            return None
        
        all_ports = []
        critical_found = []
        
        for host in self.analysis.hosts:
            for port in host.ports:
                all_ports.append((port.number, port.service.lower()))
                
                # Vérifie les ports critiques
                if port.number in self.CRITICAL_PORTS:
                    critical_found.append((port.number, self.CRITICAL_PORTS[port.number]))
        
        # Si des ports critiques sont exposés
        if critical_found:
            self.analysis.result = 'critical_exposure'
            self.analysis.warnings.append(
                f"Ports critiques exposés: {', '.join([f'{p} ({n})' for p, n in critical_found])}"
            )
            return 'critical_exposure'
        
        # Vérifie si seulement des ports web
        is_web_only = all(
            port_num in self.WEB_PORTS or service in self.WEB_SERVICES
            for port_num, service in all_ports
        )
        
        if is_web_only:
            self.analysis.result = 'web_only'
            return 'web_only'
        
        # Beaucoup de ports ouverts
        if self.analysis.total_open_ports > 10:
            self.analysis.result = 'many_ports_open'
            return 'many_ports_open'
        
        # Cas par défaut
        self.analysis.result = 'standard'
        return 'standard'
    
    def generate_summary(self) -> str:
        """Génère un résumé textuel de l'analyse"""
        lines = []
        
        lines.append(f"=== Analyse Nmap ===")
        lines.append(f"Nombre d'hôtes: {len(self.analysis.hosts)}")
        lines.append(f"Total ports ouverts: {self.analysis.total_open_ports}")
        lines.append(f"result: {self.analysis.result or 'aucune'}")
        
        if self.analysis.warnings:
            lines.append(f"\n⚠ Avertissements:")
            for warning in self.analysis.warnings:
                lines.append(f"  - {warning}")
        
        lines.append(f"\n=== Détails par hôte ===")
        for host in self.analysis.hosts:
            lines.append(f"\nHôte: {host.ip}")
            if host.hostname:
                lines.append(f"  Hostname: {host.hostname}")
            lines.append(f"  Statut: {host.status}")
            lines.append(f"  Ports ouverts: {len(host.ports)}")
            
            if host.ports:
                lines.append("  Détails:")
                for port in host.ports:
                    service_info = f"{port.service}"
                    if port.version:
                        service_info += f" {port.version}"
                    if port.product:
                        service_info += f" ({port.product})"
                    
                    lines.append(f"    - {port.number}/{port.protocol}: {service_info}")
        
        self.analysis.summary = '\n'.join(lines)
        return self.analysis.summary
    
    def to_dict(self) -> Dict:
        """Retourne l'analyse sous forme de dictionnaire"""
        return {
            'result': self.analysis.result,
            'total_open_ports': self.analysis.total_open_ports,
            'hosts': [
                {
                    'ip': host.ip,
                    'hostname': host.hostname,
                    'status': host.status,
                    'ports': [
                        {
                            'number': port.number,
                            'protocol': port.protocol,
                            'state': port.state,
                            'service': port.service,
                            'version': port.version,
                            'product': port.product
                        }
                        for port in host.ports
                    ]
                }
                for host in self.analysis.hosts
            ],
            'summary': self.analysis.summary,
            'warnings': self.analysis.warnings
        }


def analyze_nmap_results(content: str) -> Optional[Dict]:
    """
    Fonction principale d'analyse des résultats Nmap
    
    Args:
        content: Contenu XML ou texte des résultats nmap
    
    Returns:
        Dictionnaire avec les résultats de l'analyse ou None en cas d'erreur
    """
    analyzer = NmapAnalyzer()
    
    # Détermine le format et parse
    if content.strip().startswith('<?xml'):
        if not analyzer.parse_xml(content):
            return None
    else:
        if not analyzer.parse_text(content):
            return None
    
    # Évalue la result
    analyzer.evaluate_result()
    
    # Génère le résumé
    analyzer.generate_summary()
    
    return analyzer.to_dict()


def main():
    """Utilisation en ligne de commande"""
    if len(sys.argv) < 2:
        print("Usage: python analyze_nmap.py <fichier_nmap.xml|txt>")
        print("\nAnalyse un fichier de résultats nmap et affiche un résumé")
        sys.exit(1)
    
    file_path = Path(sys.argv[1])
    
    if not file_path.exists():
        print(f"Erreur: Fichier '{file_path}' introuvable")
        sys.exit(1)
    
    # Lit le fichier
    try:
        content = file_path.read_text(encoding='utf-8')
    except Exception as e:
        print(f"Erreur lors de la lecture du fichier: {e}")
        sys.exit(1)
    
    # Analyse
    result = analyze_nmap_results(content)
    
    if not result:
        print("Erreur lors de l'analyse des résultats")
        sys.exit(1)
    
    # Affiche le résumé
    print(result)
    
    if '--full' in sys.argv:
        print(result['summary'])

    # Affiche la result sous forme JSON si demandé
    if '--json' in sys.argv:
        import json
        print("\n" + "="*60)
        print("JSON:")
        print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()