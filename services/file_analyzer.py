import os
import hashlib

ALLOWED_EXTENSIONS = {
    '.txt', '.pdf', '.doc', '.docx', '.xls', '.xlsx',
    '.png', '.jpg', '.jpeg', '.gif', '.zip', '.csv'
}
DANGEROUS_EXTENSIONS = {
    '.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar',
    '.sh', '.dll', '.scr', '.com', '.pif', '.msi', '.reg',
    '.hta', '.wsf', '.lnk', '.vbe', '.jse'
}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB

MAGIC_BYTES = {
    b'\x4d\x5a': 'Executável Windows (PE)',
    b'\x7f\x45\x4c\x46': 'Executável Linux (ELF)',
    b'\xca\xfe\xba\xbe': 'Ficheiro Java Class',
    b'\x50\x4b\x03\x04': 'Arquivo ZIP',
    b'\x25\x50\x44\x46': 'Documento PDF',
    b'\xff\xd8\xff': 'Imagem JPEG',
    b'\x89\x50\x4e\x47': 'Imagem PNG',
    b'\x47\x49\x46\x38': 'Imagem GIF',
}


class FileAnalyzer:
    def analyze(self, filename, file_data):
        # Validação do nome
        if not filename or '/' in filename or '\\' in filename or '..' in filename:
            return {'error': 'Nome de ficheiro inválido'}

        size = len(file_data)
        if size > MAX_FILE_SIZE:
            return {'error': f'Ficheiro demasiado grande (máximo {MAX_FILE_SIZE // 1024 // 1024} MB)'}

        if size == 0:
            return {'error': 'Ficheiro vazio'}

        indicators = []
        _, ext = os.path.splitext(filename.lower())

        # Extensão perigosa
        if ext in DANGEROUS_EXTENSIONS:
            indicators.append({
                'type': 'extensao_perigosa',
                'description': f'A extensão "{ext}" é frequentemente usada em malware',
                'severity': 'alto'
            })

        # Extensão desconhecida
        elif ext not in ALLOWED_EXTENSIONS:
            indicators.append({
                'type': 'extensao_nao_suportada',
                'description': f'Extensão "{ext}" não é suportada por esta análise',
                'severity': 'medio'
            })

        # Tipo real pelo magic bytes
        real_type = self._detect_type(file_data)
        if real_type:
            indicators.append({
                'type': 'tipo_detectado',
                'description': f'Tipo identificado pelos bytes do ficheiro: {real_type}',
                'severity': 'baixo'
            })
            # Disfarce de executável
            if 'Executável' in real_type or 'ELF' in real_type or 'Java' in real_type:
                if ext not in DANGEROUS_EXTENSIONS:
                    indicators.append({
                        'type': 'disfarce_executavel',
                        'description': f'O conteúdo parece um executável, mas a extensão é "{ext}" — possível disfarce',
                        'severity': 'alto'
                    })

        # Dupla extensão
        parts = filename.split('.')
        if len(parts) > 2:
            indicators.append({
                'type': 'dupla_extensao',
                'description': f'Ficheiro com múltiplas extensões ("{filename}") — técnica comum para disfarçar malware',
                'severity': 'medio'
            })

        sha256 = hashlib.sha256(file_data).hexdigest()
        risk_level = self._calculate_risk(indicators)

        return {
            'filename': filename,
            'size': size,
            'sha256': sha256,
            'extension': ext,
            'indicators': indicators,
            'risk_level': risk_level,
            'limitation': (
                'AVISO: Esta análise é superficial (metadados e estrutura de bytes). '
                'Não substitui um antivírus real. O ficheiro não foi executado nem aberto.'
            )
        }

    def _detect_type(self, data):
        for magic, name in MAGIC_BYTES.items():
            if data[:len(magic)] == magic:
                return name
        return None

    def _calculate_risk(self, indicators):
        if not indicators:
            return 'baixo'
        severities = [i.get('severity', 'baixo') for i in indicators]
        if 'alto' in severities:
            return 'alto'
        if 'medio' in severities:
            return 'medio'
        return 'baixo'
