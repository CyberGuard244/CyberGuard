import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.work', '.pw'}
BRAND_KEYWORDS = [
    'paypal', 'google', 'facebook', 'amazon', 'apple', 'microsoft',
    'netflix', 'instagram', 'twitter', 'bank', 'secure', 'account',
    'login', 'verify', 'update', 'confirm', 'mbway', 'multibanco',
    'millennium', 'cgd', 'santander', 'novobanco'
]


class URLAnalyzer:
    def analyze(self, url):
        indicators = []

        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ''
        except Exception:
            return [{'type': 'erro', 'description': 'URL inválido ou malformado', 'severity': 'alto'}]

        if not hostname:
            return [{'type': 'erro', 'description': 'Não foi possível extrair o domínio do URL', 'severity': 'alto'}]

        # Sem HTTPS
        if parsed.scheme == 'http':
            indicators.append({
                'type': 'sem_https',
                'description': 'O URL não usa HTTPS — a ligação não é encriptada',
                'severity': 'medio'
            })

        # IP como host
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
            indicators.append({
                'type': 'ip_como_host',
                'description': f'Usa um endereço IP ({hostname}) diretamente, em vez de um domínio',
                'severity': 'alto'
            })

        # TLD suspeito
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                indicators.append({
                    'type': 'tld_suspeito',
                    'description': f'Extensão de domínio "{tld}" é frequentemente usada em sites de spam',
                    'severity': 'medio'
                })
                break

        # Imitação de marca
        for brand in BRAND_KEYWORDS:
            if brand in hostname:
                parts = hostname.split('.')
                if brand not in parts:
                    indicators.append({
                        'type': 'imitacao_marca',
                        'description': f'O domínio pode estar a imitar a marca "{brand}"',
                        'severity': 'alto'
                    })
                    break

        # URL muito longo
        if len(url) > 100:
            indicators.append({
                'type': 'url_longo',
                'description': f'URL muito longo ({len(url)} caracteres) — pode tentar ocultar o destino real',
                'severity': 'baixo'
            })

        # Símbolo @ no URL
        if '@' in url:
            indicators.append({
                'type': 'arroba_no_url',
                'description': 'O URL contém "@" — o browser pode ignorar tudo antes deste símbolo',
                'severity': 'alto'
            })

        # Muitos subdomínios
        parts = hostname.split('.')
        if len(parts) > 4:
            indicators.append({
                'type': 'muitos_subdominios',
                'description': f'URL com {len(parts) - 2} subdomínios — padrão incomum',
                'severity': 'medio'
            })

        # Muitos hífens
        if hostname.count('-') >= 3:
            indicators.append({
                'type': 'muitos_hifens',
                'description': 'Domínio com muitos hífens — padrão comum em URLs de phishing',
                'severity': 'medio'
            })

        return indicators

    def calculate_risk(self, indicators):
        if not indicators:
            return 'baixo'
        severities = [i.get('severity', 'baixo') for i in indicators]
        if 'alto' in severities:
            return 'alto'
        if severities.count('medio') >= 2:
            return 'medio'
        if 'medio' in severities:
            return 'medio'
        return 'baixo'
