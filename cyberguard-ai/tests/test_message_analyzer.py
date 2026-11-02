import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from services.message_analyzer import analyze_message


def test_urgencia_detetada():
    msg = 'URGENTE: A sua conta será suspensa. Aceda imediatamente.'
    result = analyze_message(msg)
    assert any('urgência' in i.lower() for i in result['indicators'])

def test_pedido_credenciais():
    msg = 'Confirme a sua password clicando no link abaixo.'
    result = analyze_message(msg)
    assert any('credencial' in i.lower() or 'password' in i.lower() for i in result['indicators'])

def test_saudacao_generica():
    msg = 'Caro cliente, o seu pacote está retido. Pague a taxa agora.'
    result = analyze_message(msg)
    assert any('genérica' in i.lower() for i in result['indicators'])

def test_link_encurtado():
    msg = 'Clica aqui para verificares: bit.ly/abc123'
    result = analyze_message(msg)
    assert any('encurtado' in i.lower() for i in result['indicators'])

def test_mensagem_limpa():
    msg = 'Olá João, o teu pedido foi processado. Obrigado pela compra!'
    result = analyze_message(msg)
    assert result['risk_level'] == 'low'

def test_risco_alto():
    msg = 'URGENTE caro cliente: confirme a sua password agora. Clique: bit.ly/x9'
    result = analyze_message(msg)
    assert result['risk_level'] == 'high'


if __name__ == '__main__':
    testes = [
        test_urgencia_detetada, test_pedido_credenciais, test_saudacao_generica,
        test_link_encurtado, test_mensagem_limpa, test_risco_alto
    ]
    ok = fail = 0
    for t in testes:
        try:
            t(); print(f'  ✓  {t.__name__}'); ok += 1
        except Exception as e:
            print(f'  ✗  {t.__name__}: {e}'); fail += 1
    print(f'\n{ok} passou · {fail} falhou')
