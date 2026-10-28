import os
import json
import anthropic


class ClaudeService:
    def __init__(self):
        self.client = None
        api_key = os.environ.get('CLAUDE_API_KEY')
        if api_key:
            self.client = anthropic.Anthropic(api_key=api_key)

    def _no_api_response(self, summary):
        return {
            'summary': summary,
            'explanation': 'Configure a variável CLAUDE_API_KEY no ficheiro .env para ativar as explicações com IA.',
            'recommendations': ['Consulta o ficheiro .env.example para instruções de configuração.'],
            'disclaimer': 'Resultados baseados apenas na análise local, sem IA.'
        }

    def _call_api(self, prompt):
        if not self.client:
            return self._no_api_response('IA não disponível — chave API não configurada.')

        try:
            message = self.client.messages.create(
                model='claude-opus-4-5',
                max_tokens=1024,
                messages=[{'role': 'user', 'content': prompt}]
            )
            text = message.content[0].text
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {
                    'summary': text[:150],
                    'explanation': text,
                    'recommendations': [],
                    'disclaimer': 'Os resultados são indicativos e podem conter falsos positivos ou negativos.'
                }
        except Exception as e:
            return {
                'summary': 'Erro ao contactar a IA.',
                'explanation': f'Não foi possível obter explicação: {str(e)}',
                'recommendations': [],
                'disclaimer': 'Resultados baseados apenas na análise local.'
            }

    def explain_url(self, url, indicators, risk_level):
        if not indicators:
            return {
                'summary': 'Nenhum indicador suspeito encontrado na estrutura do URL.',
                'explanation': (
                    'A análise estrutural não encontrou padrões suspeitos neste URL. '
                    'Isto não garante que seja seguro — o conteúdo da página não foi verificado. '
                    'Mantém sempre precaução com links recebidos de fontes desconhecidas.'
                ),
                'recommendations': [
                    'Verifica sempre a origem do link antes de clicar',
                    'Confirma com o remetente se recebeste o link de forma inesperada',
                    'Usa um antivírus atualizado ao navegar'
                ],
                'disclaimer': 'Esta análise baseia-se apenas na estrutura do URL, não no conteúdo da página.'
            }

        indicators_text = '\n'.join(
            [f"- {i['description']} (gravidade: {i['severity']})" for i in indicators]
        )

        prompt = f"""És um especialista em cibersegurança a ajudar estudantes do 10.º ano em Portugal.

Analisa este URL: {url}

Indicadores encontrados pela análise técnica:
{indicators_text}

Nível de risco determinado: {risk_level}

Responde EXCLUSIVAMENTE em JSON válido com esta estrutura:
{{
  "summary": "Resumo em 1 frase do risco principal",
  "explanation": "Explicação clara em português de Portugal (3-4 frases). Distingue factos observados de suspeitas. Usa linguagem adequada para jovens de 15-16 anos.",
  "recommendations": ["Recomendação 1", "Recomendação 2", "Recomendação 3"],
  "disclaimer": "Os resultados são indicativos. Esta ferramenta pode gerar falsos positivos e falsos negativos."
}}

Não inventes indicadores para além dos fornecidos. Não afirmes que o URL é seguro."""

        return self._call_api(prompt)

    def explain_message(self, message, indicators, risk_level):
        if not indicators:
            return {
                'summary': 'Nenhum sinal de phishing encontrado nesta mensagem.',
                'explanation': (
                    'A análise não identificou padrões típicos de phishing ou engenharia social. '
                    'Mantém sempre precaução com mensagens inesperadas, mesmo sem alertas visíveis.'
                ),
                'recommendations': [
                    'Verifica sempre a identidade real do remetente',
                    'Não cliques em links inesperados',
                    'Contacta diretamente a entidade se tiveres dúvidas'
                ],
                'disclaimer': 'Esta análise é indicativa e pode conter erros.'
            }

        indicators_text = '\n'.join(
            [f"- {i['description']} (gravidade: {i['severity']})" for i in indicators]
        )
        preview = message[:300] + '...' if len(message) > 300 else message

        prompt = f"""És um especialista em cibersegurança a ajudar estudantes do 10.º ano em Portugal.

Analisaste esta mensagem (prévia): "{preview}"

Indicadores encontrados:
{indicators_text}

Nível de risco: {risk_level}

Responde EXCLUSIVAMENTE em JSON válido:
{{
  "summary": "Resumo em 1 frase do risco principal",
  "explanation": "Explicação em português de Portugal (3-4 frases). Distingue o que foi observado do que é suspeita. Linguagem para jovens de 15-16 anos.",
  "recommendations": ["Recomendação 1", "Recomendação 2", "Recomendação 3"],
  "disclaimer": "Os resultados são indicativos. Falsos positivos são possíveis."
}}

Não inventes informação para além dos indicadores fornecidos."""

        return self._call_api(prompt)

    def explain_file(self, filename, indicators, risk_level):
        indicators_text = (
            '\n'.join([f"- {i['description']} (gravidade: {i['severity']})" for i in indicators])
            if indicators else 'Nenhum indicador suspeito encontrado.'
        )

        prompt = f"""És um especialista em cibersegurança a ajudar estudantes do 10.º ano em Portugal.

Analisaste o ficheiro: {filename}
Nível de risco: {risk_level}

Indicadores encontrados:
{indicators_text}

IMPORTANTE: Esta análise é superficial (metadados e bytes). O ficheiro não foi executado.

Responde EXCLUSIVAMENTE em JSON válido:
{{
  "summary": "Resumo em 1 frase",
  "explanation": "Explicação em português de Portugal (3-4 frases). Sê honesto sobre as limitações desta análise. Linguagem para jovens de 15-16 anos.",
  "recommendations": ["Recomendação 1", "Recomendação 2", "Recomendação 3"],
  "disclaimer": "Esta análise é superficial e NÃO substitui um antivírus. O ficheiro não foi executado nem aberto."
}}"""

        return self._call_api(prompt)
