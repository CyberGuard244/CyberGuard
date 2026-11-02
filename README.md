# CyberGuard AI

Plataforma de segurança digital que analisa URLs, mensagens e ficheiros em busca de ameaças, usando a API do VirusTotal e análise heurística local.

## Funcionalidades

- **Análise de URLs** — verifica links suspeitos via VirusTotal (72+ motores)
- **Análise de Mensagens** — deteta phishing, urgência falsa e links encurtados
- **Análise de Ficheiros** — upload e scan com hash SHA-256 + VirusTotal
- **Histórico** — registo local dos últimos scans (localStorage)
- **Fallback heurístico** — análise offline quando a API não está acessível

## Stack

| Camada | Tecnologia |
|--------|-----------|
| Frontend | HTML + CSS + JS (single-file) |
| API externa | VirusTotal v3 |
| Backend (opcional) | Python / Flask |

## Estrutura

```
/
├── index.html          # App frontend completa
├── cyberguard-ai/
│   ├── app.py          # Servidor Flask
│   ├── requirements.txt
│   ├── services/
│   │   ├── url_analyzer.py
│   │   ├── message_analyzer.py
│   │   ├── file_analyzer.py
│   │   └── claude_service.py
│   └── tests/
│       ├── test_url_analyzer.py
│       └── test_message_analyzer.py
```

## Correr localmente

### Frontend (só abrir o browser)
```bash
# Basta abrir o index.html no browser
open index.html
```

### Backend Flask (opcional)
```bash
cd cyberguard-ai
pip install -r requirements.txt
python app.py
```

## Design

Estética editorial escura: fundo `#050505`, acento laranja-vermelho `#FF4500`, tipografia Playfair Display + Inter, overlay de ruído, animações de reveal.
