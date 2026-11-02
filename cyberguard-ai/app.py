import os
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
from werkzeug.utils import secure_filename

load_dotenv()

from database.db import init_db, save_analysis, get_all_analyses, clear_all_analyses
from services.url_analyzer import analyze_url
from services.message_analyzer import analyze_message
from services.file_analyzer import analyze_file, validate_upload
from services.claude_service import get_ai_explanation

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_UPLOAD_SIZE', 1048576))

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')

# Inicializar a base de dados ao arrancar
with app.app_context():
    init_db()


# ─── Páginas ───────────────────────────────────────────────────────────────

@app.route('/')
def index():
    analyses = get_all_analyses(limit=5)
    return render_template('index.html', recent_analyses=analyses)

@app.route('/url-analysis')
def url_analysis():
    return render_template('url_analysis.html')

@app.route('/message-analysis')
def message_analysis():
    return render_template('message_analysis.html')

@app.route('/file-analysis')
def file_analysis():
    return render_template('file_analysis.html')

@app.route('/history')
def history():
    analyses = get_all_analyses(limit=100)
    return render_template('history.html', analyses=analyses)


# ─── API ───────────────────────────────────────────────────────────────────

@app.route('/api/analyze/url', methods=['POST'])
def api_analyze_url():
    data = request.get_json(silent=True)
    if not data or 'url' not in data:
        return jsonify({'error': 'URL não fornecido'}), 400

    url = data['url'].strip()
    if not url:
        return jsonify({'error': 'URL não pode estar vazio'}), 400
    if len(url) > 2000:
        return jsonify({'error': 'URL demasiado longo'}), 400

    result = analyze_url(url)
    explanation = get_ai_explanation('URL', result['indicators'], url)
    result['ai_explanation'] = explanation

    save_analysis(
        analysis_type='url',
        content=url,
        risk_level=result['risk_level'],
        indicators=result['indicators'],
        ai_explanation=explanation
    )
    return jsonify(result), 200


@app.route('/api/analyze/message', methods=['POST'])
def api_analyze_message():
    data = request.get_json(silent=True)
    if not data or 'message' not in data:
        return jsonify({'error': 'Mensagem não fornecida'}), 400

    text = data['message'].strip()
    if not text:
        return jsonify({'error': 'Mensagem não pode estar vazia'}), 400
    if len(text) > 10000:
        return jsonify({'error': 'Mensagem demasiado longa (máximo 10 000 caracteres)'}), 400

    result = analyze_message(text)
    explanation = get_ai_explanation('mensagem', result['indicators'], text[:500])
    result['ai_explanation'] = explanation

    save_analysis(
        analysis_type='message',
        content=text[:500],
        risk_level=result['risk_level'],
        indicators=result['indicators'],
        ai_explanation=explanation
    )
    return jsonify(result), 200


@app.route('/api/analyze/file', methods=['POST'])
def api_analyze_file():
    if 'file' not in request.files:
        return jsonify({'error': 'Nenhum ficheiro enviado'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Nenhum ficheiro selecionado'}), 400

    filename = secure_filename(file.filename)
    file_bytes = file.read()
    file_size = len(file_bytes)
    file.seek(0)

    valid, message = validate_upload(filename, file_size)
    if not valid:
        return jsonify({'error': message}), 400

    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    temp_path = os.path.join(UPLOAD_FOLDER, filename)

    try:
        file.save(temp_path)
        result = analyze_file(temp_path, filename)
        explanation = get_ai_explanation('ficheiro', result['indicators'], filename)
        result['ai_explanation'] = explanation

        save_analysis(
            analysis_type='file',
            content=filename,
            risk_level=result['risk_level'],
            indicators=result['indicators'],
            ai_explanation=explanation
        )
        return jsonify(result), 200
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


@app.route('/api/history', methods=['GET'])
def api_history():
    analyses = get_all_analyses(limit=100)
    return jsonify({'history': analyses}), 200


@app.route('/api/history', methods=['DELETE'])
def api_clear_history():
    clear_all_analyses()
    return jsonify({'message': 'Histórico apagado com sucesso'}), 200


# ─── Erros ─────────────────────────────────────────────────────────────────

@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'Ficheiro demasiado grande'}), 413

@app.errorhandler(404)
def not_found(e):
    return render_template('index.html', recent_analyses=[]), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Erro interno do servidor'}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
