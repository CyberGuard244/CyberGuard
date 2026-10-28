import unittest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from services.url_analyzer import URLAnalyzer


class TestURLAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = URLAnalyzer()

    # ── Sem HTTPS ──────────────────────────────────────────────────────────
    def test_http_flagged(self):
        indicators = self.analyzer.analyze('http://exemplo.com')
        types = [i['type'] for i in indicators]
        self.assertIn('sem_https', types)

    def test_https_no_flag(self):
        indicators = self.analyzer.analyze('https://google.com')
        types = [i['type'] for i in indicators]
        self.assertNotIn('sem_https', types)

    # ── IP como host ───────────────────────────────────────────────────────
    def test_ip_host_flagged(self):
        indicators = self.analyzer.analyze('http://192.168.1.1/login')
        types = [i['type'] for i in indicators]
        self.assertIn('ip_como_host', types)

    def test_domain_host_not_flagged(self):
        indicators = self.analyzer.analyze('https://exemplo.pt/login')
        types = [i['type'] for i in indicators]
        self.assertNotIn('ip_como_host', types)

    # ── TLD suspeito ───────────────────────────────────────────────────────
    def test_suspicious_tld(self):
        indicators = self.analyzer.analyze('https://promo.tk')
        types = [i['type'] for i in indicators]
        self.assertIn('tld_suspeito', types)

    # ── Símbolo @ ──────────────────────────────────────────────────────────
    def test_at_symbol_flagged(self):
        indicators = self.analyzer.analyze('http://google.com@evil.com/login')
        types = [i['type'] for i in indicators]
        self.assertIn('arroba_no_url', types)

    # ── Nível de risco ─────────────────────────────────────────────────────
    def test_high_risk_ip(self):
        indicators = self.analyzer.analyze('http://192.168.1.1/paypal-secure')
        risk = self.analyzer.calculate_risk(indicators)
        self.assertEqual(risk, 'alto')

    def test_low_risk_clean(self):
        indicators = self.analyzer.analyze('https://exemplo.pt')
        risk = self.analyzer.calculate_risk(indicators)
        self.assertIn(risk, ['baixo', 'medio'])

    # ── URL longo ──────────────────────────────────────────────────────────
    def test_long_url(self):
        long_url = 'https://exemplo.com/' + 'a' * 120
        indicators = self.analyzer.analyze(long_url)
        types = [i['type'] for i in indicators]
        self.assertIn('url_longo', types)


if __name__ == '__main__':
    unittest.main(verbosity=2)
