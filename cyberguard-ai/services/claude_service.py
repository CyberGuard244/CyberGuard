import os
import anthropic


def get_ai_explanation(analysis_type: str, indicators: list, content: str) -> str:
    """
    Envia os indicadores à Claude API e pede uma explicação em português de Portugal.
    Devolve: string com a explicação, ou mensagem de erro.
    """
    api_key = os.environ.get('CLAUDE_API_KEY')
    if not api_key:
        return 'Chave da API não configurada. Verifica o ficheiro .env.'

    model = os.environ.get('CLAUDE_MODEL', 'claude-haiku-5-5')
    client = anthropic.Anthropic(api_key=api_key)
    prompt = _build_prompt(analysis_type, indicators, content)

    try:
        message = client.messages.create(
            model=model,
            max_tokens=600,
            messages=[{'role': 'user', 'content': prompt}]
        )
        return message.content[0].text
    except anthropic.AuthenticationError:
        return 'Chave da API inválida. Verifica a variável CLAUDE_API_KEY no ficheiro .env.'
    except anthropic.RateLimitError:
        return 'Limite de pedidos à API atingido. Tenta novamente mais tarde.'
    except anthropic.APIError as e:
        return f'Erro ao contactar a IA: {str(e)}'


def _build_prompt(analysis_type: str, indicators: list, content: str) -> str:
    if indicators:
        indicators_text = '\n'.join(f'- {ind}' for ind in indicators)
    else:
        indicators_text = 'Nenhum indicador suspeito encontrado.'

    return f"""És um assistente de cibersegurança a ajudar estudantes do 10.º ano em Portugal.

Tipo de análise: {analysis_type}
Conteúdo analisado: {content[:200]}

Indicadores encontrados pela ferramenta:
{indicators_text}

Responde em português de Portugal. Sê claro e simples.

A tua resposta deve ter exatamente 3 parágrafos curtos:
1. O que significam estes indicadores (ou a sua ausência)
2. O que o utilizador deve fazer a seguir
3. Um aviso de que esta análise é indicativa e pode ter falsos positivos ou negativos

IMPORTANTE: Não inventes indicadores. Baseia-te apenas nos que foram listados acima."""
