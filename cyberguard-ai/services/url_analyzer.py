import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = ['.xyz', '.top', '.click', '.loan', '.work', '.gq', '.ml', '.cf', '.ga', '.tk']

BRAND_KEYWORDS = [
    'paypal', 'apple', 'microsoft', 'google', 'amazon', 'netflix',
    'facebook', 'instagram', 'banco', 'cgd', 'bpi', 'millennium', 'santander'
]


def analyze_url(url: str) -> dict:
    """Analisa um URL e devolve indicadores de risco."""
    indicators = []

    try:
        normalised = url if url.startswith(('http://', 'https://')) else 'http://' + url
        parsed = urlparse(normalised)
    except Exception:
        return {
            'risk_level': 'unknown',
            'indicators': ['Não foi possível analisar o URL — formato inválido'],
            'summary': 'URL com formato inválido.',
            'parsed': {}
        }

    _check_https(parsed, indicators)
    _check_ip_host(parsed, indicators)
    _check_suspicious_tld(parsed, indicators)
    _check_brand_impersonation(parsed, indicators)
    _check_url_length(url, indicators)
    _check_special_chars(parsed, indicators)
    _check_many_subdomains(parsed, indicators)

    risk_level = _calculate_risk(indicators)

    return {
        'risk_level': risk_level,
        'indicators': indicators,
        'summary': f'{len(indicators)} indicador(es) encontrado(s).',
        'parsed': {
            'scheme': parsed.scheme,
            'domain': parsed.netloc,
            'path': parsed.path
        }
    }


def _check_https(parsed, indicators):
    if parsed.scheme == 'http':
        indicators.append('Ligação não encriptada (HTTP em vez de HTTPS)')


def _check_ip_host(parsed, indicators):
    host = parsed.netloc.split(':')[0]
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
        indicators.append('O endereço usa um IP em vez de um nome de domínio')


def _check_suspicious_tld(parsed, indicators):
    host = parsed.netloc.lower()
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            indicators.append(f'Extensão de domínio associada a abusos: {tld}')
            break


def _check_brand_impersonation(parsed, indicators):
    host = parsed.netloc.lower()
    for brand in BRAND_KEYWORDS:
        in_host = brand in host
        is_official = host == f'{brand}.com' or host.endswith(f'.{brand}.com')
        if in_host and not is_official:
            indicators.append(f'O domínio pode estar a imitar a marca "{brand}"')


def _check_url_length(url, indicators):
    if len(url) > 100:
        indicators.append(f'URL muito longo ({len(url)} caracteres) — pode esconder o destino real')


def _check_special_chars(parsed, indicators):
    if '@' in parsed.netloc:
        indicators.append('Símbolo "@" no domínio — técnica comum de phishing')


def _check_many_subdomains(parsed, indicators):
    host = parsed.netloc.split(':')[0]
    if host.count('.') > 3:
        indicators.append('Número elevado de subdomínios — pode tentar imitar um site legítimo')


def _calculate_risk(indicators: list) -> str:
    count = len(indicators)
    if count == 0:
        return 'low'
    elif count <= 2:
        return 'medium'
    else:
        return 'high'
