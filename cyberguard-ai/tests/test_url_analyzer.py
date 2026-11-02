import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from services.url_analyzer import analyze_url, _calculate_risk


def test_http_detectado():
    result = analyze_url('http://exemplo.com')
    assert any('HTTP' in i for i in result['indicators']), 'Devia detetar HTTP'

def test_https_sem_indicadores():
    result = analyze_url('https://google.com')
    assert result['risk_level'] == 'low'

def test_ip_no_host():
    result = analyze_url('http://192.168.1.1/login')
    assert any('IP' in i for i in result['indicators'])

def test_tld_suspeito():
    result = analyze_url('https://banco-seguro.xyz/login')
    assert any('extensão' in i.lower() for i in result['indicators'])

def test_imitacao_de_marca():
    result = analyze_url('https://paypal-secure.com/verify')
    assert any('marca' in i.lower() for i in result['indicators'])

def test_arroba_no_dominio():
    result = analyze_url('http://utilizador@banco.com')
    assert any('@' in i for i in result['indicators'])

def test_url_longo():
    result = analyze_url('https://example.com/' + 'a' * 150)
    assert any('longo' in i.lower() for i in result['indicators'])

def test_calcular_risco():
    assert _calculate_risk([]) == 'low'
    assert _calculate_risk(['x']) == 'medium'
    assert _calculate_risk(['x', 'y', 'z']) == 'high'


# ── Executar sem pytest ───────────────────────────
if __name__ == '__main__':
    testes = [
        test_http_detectado, test_https_sem_indicadores, test_ip_no_host,
        test_tld_suspeito, test_imitacao_de_marca, test_arroba_no_dominio,
        test_url_longo, test_calcular_risco
    ]
    ok = fail = 0
    for t in testes:
        try:
            t(); print(f'  ✓  {t.__name__}'); ok += 1
        except Exception as e:
            print(f'  ✗  {t.__name__}: {e}'); fail += 1
    print(f'\n{ok} passou · {fail} falhou')
