import unittest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from services.message_analyzer import MessageAnalyzer


class TestMessageAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = MessageAnalyzer()

    # ── Linguagem urgente ──────────────────────────────────────────────────
    def test_urgency_detected(self):
        msg = 'A tua conta está suspensa. Verifica agora ou perdes o acesso.'
        indicators = self.analyzer.analyze(msg)
        types = [i['type'] for i in indicators]
        self.assertIn('linguagem_urgente', types)

    def test_normal_message_no_urgency(self):
        msg = 'Olá, como estás? Tudo bem por aí?'
        indicators = self.analyzer.analyze(msg)
        types = [i['type'] for i in indicators]
        self.assertNotIn('linguagem_urgente', types)

    # ── Pedido de credenciais ──────────────────────────────────────────────
    def test_credential_request(self):
        msg = 'Por favor confirma o teu username e password para prosseguir.'
        indicators = self.analyzer.analyze(msg)
        types = [i['type'] for i in indicators]
        self.assertIn('pedido_credenciais', types)

    # ── Ameaças ────────────────────────────────────────────────────────────
    def test_threat_detected(self):
        msg = 'A tua conta será encerrada se não agires nas próximas 24 horas.'
        indicators = self.analyzer.analyze(msg)
        types = [i['type'] for i in indicators]
        self.assertIn('ameaca', types)

    # ── Promessas ─────────────────────────────────────────────────────────
    def test_reward_detected(self):
        msg = 'Parabéns! Foste selecionado para receber um prémio especial grátis!'
        indicators = self.analyzer.analyze(msg)
        types = [i['type'] for i in indicators]
        self.assertIn('promessa_recompensa', types)

    # ── Links ─────────────────────────────────────────────────────────────
    def test_links_detected(self):
        msg = 'Clica aqui para verificar: https://evil.example.com/verify'
        indicators = self.analyzer.analyze(msg)
        types = [i['type'] for i in indicators]
        self.assertIn('links_na_mensagem', types)

    def test_no_links_in_clean_message(self):
        msg = 'Boa tarde, o teu encomenda foi enviada.'
        indicators = self.analyzer.analyze(msg)
        types = [i['type'] for i in indicators]
        self.assertNotIn('links_na_mensagem', types)

    # ── Nível de risco ─────────────────────────────────────────────────────
    def test_high_risk_phishing(self):
        msg = 'URGENTE: A tua conta será encerrada. Confirma a tua password e IBAN agora!'
        indicators = self.analyzer.analyze(msg)
        risk = self.analyzer.calculate_risk(indicators)
        self.assertEqual(risk, 'alto')

    def test_low_risk_clean(self):
        msg = 'Até amanhã, boa noite!'
        indicators = self.analyzer.analyze(msg)
        risk = self.analyzer.calculate_risk(indicators)
        self.assertEqual(risk, 'baixo')


if __name__ == '__main__':
    unittest.main(verbosity=2)
