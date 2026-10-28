import re

URGENCY_PHRASES = [
    'urgente', 'imediatamente', 'agir agora', 'expira em', 'prazo', 'última oportunidade',
    'conta suspensa', 'acesso bloqueado', 'verifique agora', 'clique aqui agora',
    'urgent', 'immediately', 'act now', 'expires', 'suspended', 'verify now',
    'ação imediata', 'responda já', 'nas próximas horas', 'hoje mesmo'
]

CREDENTIAL_REQUESTS = [
    'password', 'palavra-passe', 'pin', 'código de acesso', 'número de cartão',
    'dados bancários', 'credenciais', 'username', 'utilizador', 'nif',
    'número de contribuinte', 'número de segurança social', 'iban', 'código mbway',
    'código de confirmação', 'código de verificação'
]

THREAT_PHRASES = [
    'conta será encerrada', 'acesso será revogado', 'multa', 'processo judicial',
    'autoridades', 'bloqueado permanentemente', 'suspenso', 'cancelado',
    'consequências legais', 'reportado', 'denunciado'
]

REWARD_PHRASES = [
    'parabéns', 'ganhou', 'prémio', 'grátis', 'gratuito', 'oferta especial',
    'selecionado', 'congratulations', 'winner', 'prize', 'free', 'bónus',
    'sorteio', 'vencedor', 'recompensa'
]

URL_PATTERN = re.compile(r'https?://\S+|www\.\S+', re.IGNORECASE)


class MessageAnalyzer:
    def analyze(self, text):
        indicators = []
        text_lower = text.lower()

        # Linguagem urgente
        found_urgency = [p for p in URGENCY_PHRASES if p in text_lower]
        if found_urgency:
            indicators.append({
                'type': 'linguagem_urgente',
                'description': f'Linguagem de urgência: "{found_urgency[0]}"',
                'severity': 'medio'
            })

        # Pedido de credenciais
        found_credentials = [p for p in CREDENTIAL_REQUESTS if p in text_lower]
        if found_credentials:
            indicators.append({
                'type': 'pedido_credenciais',
                'description': f'Solicita informação sensível: {", ".join(found_credentials[:2])}',
                'severity': 'alto'
            })

        # Ameaças
        found_threats = [p for p in THREAT_PHRASES if p in text_lower]
        if found_threats:
            indicators.append({
                'type': 'ameaca',
                'description': f'Contém ameaças: "{found_threats[0]}"',
                'severity': 'alto'
            })

        # Promessas de recompensa
        found_rewards = [p for p in REWARD_PHRASES if p in text_lower]
        if found_rewards:
            indicators.append({
                'type': 'promessa_recompensa',
                'description': f'Promete recompensas ou prémios: "{found_rewards[0]}"',
                'severity': 'medio'
            })

        # Links na mensagem
        urls = URL_PATTERN.findall(text)
        if urls:
            indicators.append({
                'type': 'links_na_mensagem',
                'description': f'Contém {len(urls)} link(s) — verifique cada um antes de clicar',
                'severity': 'baixo'
            })

        # Imitação de entidades
        impersonation_brands = [
            'banco', 'paypal', 'amazon', 'google', 'microsoft', 'apple',
            'at.', 'finanças', 'segurança social', 'at portal', 'cgd',
            'millennium bcp', 'novo banco', 'santander', 'mbway'
        ]
        found_brands = [b for b in impersonation_brands if b in text_lower]
        if found_brands:
            indicators.append({
                'type': 'possivel_imitacao',
                'description': f'Menciona entidades conhecidas ({found_brands[0]}) — pode ser falsificação',
                'severity': 'medio'
            })

        # Maiúsculas excessivas
        words = text.split()
        caps_words = [w for w in words if w.isupper() and len(w) > 2]
        if len(caps_words) > 3:
            indicators.append({
                'type': 'maiusculas_excessivas',
                'description': 'Uso excessivo de maiúsculas — técnica para criar urgência falsa',
                'severity': 'baixo'
            })

        return indicators

    def calculate_risk(self, indicators):
        if not indicators:
            return 'baixo'
        severities = [i.get('severity', 'baixo') for i in indicators]
        if 'alto' in severities:
            return 'alto'
        if severities.count('medio') >= 2:
            return 'alto'
        if 'medio' in severities:
            return 'medio'
        return 'baixo'
