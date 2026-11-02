import re

URGENCY_PATTERNS = [
    r'urgente', r'imediatamente', r'agora mesmo',
    r'nas pr[oó]ximas \d+ horas',
    r'a sua conta (ser[aá]|foi) (suspensa|bloqueada)',
    r'a[çc][aã]o necess[aá]ria', r'prazo'
]

CREDENTIAL_PATTERNS = [
    r'(introduza|confirme|verifique|atualize) (a sua )?(password|palavra.passe|pin|c[oó]digo)',
    r'(clique|aceda) (aqui|no link) para (verificar|confirmar|atualizar)',
    r'dados (banc[aá]rios|de acesso|de login|pessoais)',
    r'n[uú]mero (do cart[aã]o|de conta|contribuinte)'
]

LINK_SHORTENERS = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'rebrand.ly']
GENERIC_GREETINGS = ['caro cliente', 'prezado utilizador', 'dear customer', 'valued customer', 'caro utilizador']


def analyze_message(text: str) -> dict:
    """Analisa uma mensagem em busca de sinais de phishing e engenharia social."""
    indicators = []

    _check_urgency(text, indicators)
    _check_credential_request(text, indicators)
    _check_suspicious_links(text, indicators)
    _check_generic_greeting(text, indicators)

    risk_level = _calculate_risk(indicators)

    return {
        'risk_level': risk_level,
        'indicators': indicators,
        'summary': f'{len(indicators)} indicador(es) encontrado(s).'
    }


def _check_urgency(text, indicators):
    lower = text.lower()
    for pattern in URGENCY_PATTERNS:
        if re.search(pattern, lower):
            indicators.append('Linguagem de urgência — técnica comum para pressionar a vítima a agir sem pensar')
            break


def _check_credential_request(text, indicators):
    lower = text.lower()
    for pattern in CREDENTIAL_PATTERNS:
        if re.search(pattern, lower):
            indicators.append('Pedido de credenciais ou dados pessoais/bancários')
            break


def _check_suspicious_links(text, indicators):
    url_pattern = re.compile(r'https?://[^\s]+')
    urls = url_pattern.findall(text)

    for url in urls:
        if any(s in url for s in LINK_SHORTENERS):
            indicators.append('Link encurtado encontrado — o destino real está escondido')
            break
        if re.search(r'https?://\d{1,3}(\.\d{1,3}){3}', url):
            indicators.append('Link com endereço IP em vez de domínio')
            break


def _check_generic_greeting(text, indicators):
    lower = text.lower()
    for greeting in GENERIC_GREETINGS:
        if greeting in lower:
            indicators.append('Saudação genérica — mensagens legítimas geralmente usam o teu nome')
            break


def _calculate_risk(indicators: list) -> str:
    count = len(indicators)
    if count == 0:
        return 'low'
    elif count <= 1:
        return 'medium'
    else:
        return 'high'
