import os
from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv

load_dotenv()

from database.db import Database
from services.url_analyzer import URLAnalyzer
from services.message_analyzer import MessageAnalyzer
from services.file_analyzer import FileAnalyzer
from services.claude_service import ClaudeService

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB

db = Database()
claude = ClaudeService()
url_analyzer = URLAnalyzer()
message_analyzer = MessageAnalyzer()
file_analyzer = FileAnalyzer()


# ── Páginas ──────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    stats = db.get_stats()
    recent = db.get_recent(5)
    return render_template('index.html', stats=stats, recent=recent)


@app.route('/url')
def url_page():
    return render_template('url_analysis.html')


@app.route('/message')
def message_page():
    return render_template('message_analysis.html')


@app.route('/file')
def file_page():
    return render_template('file_analysis.html')


@app.route('/history')
def history_page():
    analyses = db.get_all()
    return render_template('history.html', analyses=analyses)


# ── API ───────────────────────────────────────────────────────────────────────

@app.route('/api/analyze/url', methods=['POST'])
def analyze_url():
    data = request.get_json()
    if not data or not data.get('url', '').strip():
        return jsonify({'error': 'URL em falta ou vazio'}), 400

    url = data['url'].strip()
    if len(url) > 2048:
        return jsonify({'error': 'URL demasiado longo'}), 400

    indicators = url_analyzer.analyze(url)
    risk_level = url_analyzer.calculate_risk(indicators)
    explanation = claude.explain_url(url, indicators, risk_level)

    analysis_id = db.save(
        analysis_type='url',
        target=url,
        indicators=indicators,
        risk_level=risk_level,
        summary=explanation.get('summary', '')
    )

    return jsonify({
        'id': analysis_id,
        'url': url,
        'indicators': indicators,
        'risk_level': risk_level,
        'explanation': explanation
    })


@app.route('/api/analyze/message', methods=['POST'])
def analyze_message():
    data = request.get_json()
    if not data or not data.get('message', '').strip():
        return jsonify({'error': 'Mensagem em falta ou vazia'}), 400

    message = data['message'].strip()
    if len(message) > 10000:
        return jsonify({'error': 'Mensagem demasiado longa (máximo 10 000 caracteres)'}), 400

    indicators = message_analyzer.analyze(message)
    risk_level = message_analyzer.calculate_risk(indicators)
    explanation = claude.explain_message(message, indicators, risk_level)

    preview = message[:100] + '...' if len(message) > 100 else message
    analysis_id = db.save(
        analysis_type='mensagem',
        target=preview,
        indicators=indicators,
        risk_level=risk_level,
        summary=explanation.get('summary', '')
    )

    return jsonify({
        'id': analysis_id,
        'indicators': indicators,
        'risk_level': risk_level,
        'explanation': explanation
    })


@app.route('/api/analyze/file', methods=['POST'])
def analyze_file():
    if 'file' not in request.files:
        return jsonify({'error': 'Ficheiro em falta'}), 400

    f = request.files['file']
    if not f.filename:
        return jsonify({'error': 'Nenhum ficheiro selecionado'}), 400

    file_data = f.read()
    result = file_analyzer.analyze(f.filename, file_data)

    if 'error' in result:
        return jsonify(result), 400

    explanation = claude.explain_file(f.filename, result['indicators'], result['risk_level'])

    analysis_id = db.save(
        analysis_type='ficheiro',
        target=f.filename,
        indicators=result['indicators'],
        risk_level=result['risk_level'],
        summary=explanation.get('summary', '')
    )

    return jsonify({
        'id': analysis_id,
        'filename': f.filename,
        'size': result['size'],
        'sha256': result['sha256'],
        'indicators': result['indicators'],
        'risk_level': result['risk_level'],
        'explanation': explanation,
        'limitation': result['limitation']
    })


@app.route('/api/history', methods=['GET'])
def get_history():
    return jsonify(db.get_all())


@app.route('/api/history', methods=['DELETE'])
def clear_history():
    db.clear()
    return jsonify({'message': 'Histórico apagado com sucesso'})


# ── Arranque ──────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    db.init()
    app.run(debug=os.environ.get('FLASK_DEBUG', '1') == '1', port=5000)
