#!/usr/bin/env python3
"""
Sanitization App v1.0
"""
import os, re, uuid, shutil, tempfile, logging, subprocess, argparse, sys
from datetime import datetime, timedelta
from threading import Semaphore, Thread
from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory, send_file, session, render_template_string
from logging.handlers import RotatingFileHandler
from concurrent.futures import ThreadPoolExecutor
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# --- Config ---
MAX_UPLOAD_MB = 100         # Maximum upload file size in MB
MAX_THREADS   = 15          # Maximum concurrent processing threads
MAX_RULES     = 20          # Maximum regex rules allowed in session
MAX_RULE_LEN  = 100         # Maximum length of a single regex rule
MAX_FILES     = 5           # Maximum files allowed per upload
PURGE_DAYS    = 1           # Retention days for uploads/logs/outputs/UUIDs
REPL_CHAR     = 'XXX'       # Replacement string for sanitization (also used for filename chars)
ARCHIVE_EXTS = {
    '.zip','.rar','.7z','.tar','.tgz','.tar.gz',
    '.bz2','.tar.bz2','.gz','.xz','.lz','.zst'
}

# --- Log Rotation and Directories Setup ---
BASE   = Path(__file__).parent.resolve()
UPLOAD = BASE / 'uploads'
OUTPUT = BASE / 'outputs'
LOGS   = BASE / 'logs'
TEMP   = BASE / 'temp'
for d in (UPLOAD, OUTPUT, LOGS, TEMP):
    d.mkdir(exist_ok=True)

log_handler = RotatingFileHandler(
    LOGS / 'processing.log',
    maxBytes=5*1024*1024,  # 5MB per log file
    backupCount=3          # keep 3 rotated logs
)
logging.basicConfig(
    handlers=[log_handler],
    level=logging.INFO,
    format="%(asctime)s %(levelname)s:%(message)s"
)

def ensure_selfsigned_certs():
    """Ensure development self-signed certificates are present."""
    CRT_DIR = BASE / 'certs'
    CRT_DIR.mkdir(exist_ok=True)
    crt = CRT_DIR / 'cert.pem'
    key = CRT_DIR / 'key.pem'

    if crt.exists() and key.exists():
        return

    logging.info("Generating dev self-signed cert/key using cryptography.")

    try:
        key_obj = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"SanitizationAppDevCert"),
        ])

        cert = x509.CertificateBuilder()\
            .subject_name(subject)\
            .issuer_name(issuer)\
            .public_key(key_obj.public_key())\
            .serial_number(x509.random_serial_number())\
            .not_valid_before(datetime.utcnow())\
            .not_valid_after(datetime.utcnow() + timedelta(days=3650))\
            .sign(key_obj, hashes.SHA256())

        with open(key, "wb") as f:
            f.write(key_obj.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open(crt, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    except Exception as e:
        logging.error("Could not generate cert.pem/key.pem: %s", e)
        print("Could not generate cert.pem/key.pem:", e, file=sys.stderr)
        sys.exit(1)

def load_bad_patterns():
    """Load default patterns from bad_words.txt, skipping comments/empty lines."""
    patterns = []
    for line in (BASE/'bad_words.txt').read_text('utf-8').splitlines():
        clean = line.split('#',1)[0].strip()
        if clean:
            patterns.append(clean)
    return patterns

def purge_old():
    """Purge old uploads, logs, outputs, and expired sessions."""
    cutoff = datetime.now() - timedelta(days=PURGE_DAYS)
    for folder in (LOGS, OUTPUT, UPLOAD):
        for f in folder.iterdir():
            if f.is_file() and datetime.fromtimestamp(f.stat().st_mtime) < cutoff:
                try:
                    f.unlink()
                except:
                    pass
    purge_ids = [
        k for k, v in SESSIONS.items()
        if 'time' in v and v['time'] < cutoff
    ]
    for k in purge_ids:
        SESSIONS.pop(k, None)

def is_text(fp: Path) -> bool:
    """Determine if a file is a text file (by attempting UTF-8 decode)."""
    try:
        fp.read_text('utf-8')
        return True
    except:
        return False

def sanitize_content(text, rules):
    """Sanitize content by replacing non-ASCII and bad patterns. Returns new text and number of replacements."""
    repl_total = 0
    text, n = re.subn(r"[^\x20-\x7E\n\r]", REPL_CHAR, text)
    repl_total += n
    pats = rules if rules is not None else BAD_PATTERNS
    for pat in pats:
        text, n = re.subn(pat, REPL_CHAR, text, flags=re.IGNORECASE)
        repl_total += n
    return text, repl_total

def sanitize_filename_windows(name):
    """
    Replace Windows-forbidden filename chars and all non-ASCII characters.
    """
    # This regex covers:
    # - Invalid chars on Windows
    # - All characters not in printable ASCII
    sanitized = re.sub(r'[<>:"/\\|?*\x00-\x1F]|[^\x20-\x7E]', REPL_CHAR, name)
    sanitized = sanitized.rstrip(' .')
    sanitized = re.sub(f'(?:{re.escape(REPL_CHAR)})+', REPL_CHAR, sanitized)
    if not sanitized or sanitized in ('.', '..'):
        sanitized = 'file.txt'
    num_replacements = len(re.findall(r'[<>:"/\\|?*\x00-\x1F]|[^\x20-\x7E]', name))
    return sanitized, num_replacements

def is_junk_mac_file(path):
    """Check if path is a macOS junk file/folder."""
    s = str(path)
    return (
        '/__MACOSX' in s or '\\__MACOSX' in s or
        s.endswith('.DS_Store') or s.endswith('/.DS_Store') or s.endswith('\\.DS_Store')
    )

def safe_rename_in_dir(path, used_names):
    """
    Rename file or directory to sanitized version, avoiding collisions in its directory.
    Returns: (Path to new file, sanitized name, number of filename replacements)
    """
    dir_path = path.parent
    safe, fname_repl = sanitize_filename_windows(path.name)
    candidate = dir_path / safe
    orig_safe = safe
    counter = 1
    # Find a non-conflicting target filename
    while (candidate.exists() and candidate != path) or safe in used_names:
        stem, ext = os.path.splitext(orig_safe)
        safe = f"{stem}_{counter}{ext}"
        candidate = dir_path / safe
        counter += 1
    # Only rename if candidate is different
    if candidate != path:
        try:
            path.rename(candidate)
            logging.info(f"Renamed: {path.name} → {candidate.name}")
        except FileNotFoundError:
            logging.warning(f"Could not rename (not found): {path}")
            return path, path.name, 0
        except Exception as e:
            logging.error(f"Rename failed: {path} -> {candidate} ({e})")
            return path, path.name, 0
    used_names.add(safe)
    return candidate, safe, fname_repl
def extract_archive(upload_path, tempdir):
    """Extract an archive to a temporary directory using 7z."""
    subprocess.run(
        f"7z x '{upload_path}' -o'{tempdir}' -y",
        shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

def sanitize_tree(root):
    """
    Recursively sanitize all files and directory names in a directory tree,
    including nested archives.
    Returns total number of filename replacements.
    """
    filename_replacements = 0

    for dirpath, dirnames, filenames in os.walk(root, topdown=False):
        path = Path(dirpath)
        used_names = set()
        # --- Handle files ---
        for fname in filenames:
            f = path / fname
            if is_junk_mac_file(f):
                try: f.unlink()
                except: pass
                continue
            # --- If nested archive, extract and recurse ---
            if f.suffix.lower() in ARCHIVE_EXTS:
                extract_archive(f, f.parent)
                try: f.unlink()
                except: pass
                filename_replacements += sanitize_tree(f.parent)  # use actual target
                continue
            # --- Regular file: sanitize name ---
            _, _, frepl = safe_rename_in_dir(f, used_names)
            filename_replacements += frepl
        # --- Handle directories (bottom-up) ---
        for dname in dirnames:
            d = path / dname
            if is_junk_mac_file(d):
                try: shutil.rmtree(d)
                except: pass
                continue
            _, _, drepl = safe_rename_in_dir(d, used_names)
            filename_replacements += drepl
    return filename_replacements

def repack(tmpdir: Path, out_base: Path, ext: str) -> Path:
    """Repack the directory as a new archive based on extension."""
    e = ext.lower()
    if e == '.bz2':
        files = [p for p in tmpdir.iterdir() if p.is_file()]
        if len(files) == 1:
            out = out_base.with_suffix('.bz2')
            subprocess.run(f"bzip2 -c '{files[0]}' > '{out}'", shell=True, check=True)
            return out
        fmt = 'bztar'
    elif e in ('.tar.bz2', '.tbz2'): fmt = 'bztar'
    elif e in ('.tar.gz', '.tgz', '.gz'): fmt = 'gztar'
    elif e == '.tar': fmt = 'tar'
    else: fmt = 'zip'
    archive = shutil.make_archive(str(out_base), fmt, root_dir=tmpdir)
    return Path(archive)

# --- Flask & Processing App ---

app = Flask(__name__)
app.secret_key = uuid.uuid4().hex[:8]
app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD_MB * 1024 * 1024

SESSIONS = {}
sem = Semaphore(MAX_THREADS)

BAD_PATTERNS = load_bad_patterns()

def process_file(job_id, upload_paths, names, original_names, ip, rules):
    """
    Process each uploaded file/archive:
    - Only aggregate one stat per user-uploaded file (not for each file in an archive).
    - Counts filename replacements and content replacements.
    - Duration is for the whole file/archive.
    """
    sem.acquire()
    try:
        SESSIONS[job_id]['status'] = 'Processing'
        tmp = Path(tempfile.mkdtemp(dir=TEMP))

        sanitized_names = []
        per_upload_stats = []
        output_paths = []
        total_global_replacements = 0
        total_global_duration = 0.0

        for idx, up in enumerate(upload_paths):
            orig = original_names[idx]
            # Sanitize original filename with Windows-safe logic, avoid collision
            safe, fname_repl = sanitize_filename_windows(orig)
            candidate = tmp / safe
            counter = 1
            orig_safe = safe
            while candidate.exists():
                stem, ext = os.path.splitext(orig_safe)
                safe = f"{stem}_{counter}{ext}"
                candidate = tmp / safe
                counter += 1

            ext = up.suffix.lower()
            replacements = fname_repl
            start = datetime.now()
            if ext in ARCHIVE_EXTS:
                extract_archive(up, tmp)
                # Recursively sanitize everything in extracted tree (including nested)
                replacements += sanitize_tree(tmp)
                # Now sanitize file contents after filename sanitization
                for dirpath, dirnames, filenames in os.walk(tmp):
                    for fname in filenames:
                        fpath = Path(dirpath) / fname
                        if is_text(fpath):
                            with open(fpath, 'r+', encoding='utf-8', errors='ignore') as f:
                                text = f.read()
                                text, n = sanitize_content(text, rules)
                                f.seek(0)
                                f.write(text)
                                f.truncate()
                                replacements += n
                out_base = OUTPUT / f"sanit_{job_id}_{safe}"
                out = repack(tmp, out_base, Path(safe).suffix)
            else:
                shutil.copy(up, candidate)
                # Sanitize file content
                if is_text(candidate):
                    with open(candidate, 'r+', encoding='utf-8', errors='ignore') as f:
                        text = f.read()
                        text, n = sanitize_content(text, rules)
                        f.seek(0)
                        f.write(text)
                        f.truncate()
                        replacements += n
                out = OUTPUT / safe
                shutil.copy2(candidate, out)
            duration = (datetime.now() - start).total_seconds()
            sanitized_names.append(safe)
            per_upload_stats.append({'file': safe, 'replacements': replacements, 'duration': round(duration, 5)})
            output_paths.append(str(out))
            total_global_replacements += replacements
            total_global_duration += duration

        allow_download = any(stat['replacements'] > 0 for stat in per_upload_stats)

        session_update = {
            'status':'Done',
            'file_stats': per_upload_stats,
            'total_replacements': total_global_replacements,
            'duration': total_global_duration,
            'output_path': output_paths[0] if output_paths else "",
            'time': datetime.now()
        }
        if allow_download:
            session_update['download'] = f"/download/{job_id}?token={SESSIONS[job_id]['token']}"
        else:
            session_update['download'] = None

        SESSIONS[job_id].update(session_update)

        log_file = LOGS / f"{job_id}.log"
        with open(log_file, 'w') as lf:
            lf.write(",".join([
                job_id,
                ";".join(sanitized_names),
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                ip,
                f"{total_global_duration:.2f}",
                str(total_global_replacements)
            ]) + "\n")

        shutil.rmtree(tmp, ignore_errors=True)
        for up in upload_paths:
            up.unlink(missing_ok=True)
    finally:
        sem.release()

@app.errorhandler(413)
def handle_413(e):
    return jsonify(error=f'File too large (max {MAX_UPLOAD_MB}MB)'), 413

@app.route('/')
def index():
    session.pop('custom_rules', None)
    html = (BASE / 'templates' / 'index.html').read_text('utf-8')
    return render_template_string(html, max_mb=MAX_UPLOAD_MB, max_files=MAX_FILES)

@app.route('/logo.png', strict_slashes=False)
def logo():
    """Serve the logo image."""
    return send_file(BASE/'templates'/'logo.png', mimetype='image/png')

@app.route('/upload', methods=['POST'])
def upload():
    """Handle upload request, save files and start processing thread."""
    purge_old()
    files = request.files.getlist('file')
    if not files or len(files) > MAX_FILES:
        return jsonify(error=f"Select 1–{MAX_FILES} files"), 400

    job_id = uuid.uuid4().hex[:8]
    SESSIONS[job_id] = {
        'status': 'Queued',
        'token': uuid.uuid4().hex,  # 32-char secure token
        'time': datetime.now()
    }

    upaths, names, original_names = [], [], []
    for f in files:
        fn = f.filename
        up = UPLOAD/f"{job_id}_{fn}"
        f.save(up)
        upaths.append(up)
        names.append(fn)
        original_names.append(f.filename)

    cr = session.get('custom_rules')
    if not cr:
        cr = None

    Thread(
        target=process_file,
        args=(job_id, upaths, names, original_names, request.remote_addr, cr),
        daemon=True
    ).start()

    return jsonify(job_id=job_id)

@app.route('/status/<job_id>')
def status(job_id):
    """Return the current status for the given job."""
    info = SESSIONS.get(job_id)
    if info:
        resp = {
            'job_id': job_id,
            'status': info['status'],
            'progress': info.get('progress')
        }
        if info['status'] == 'Done':
            resp.update({
                'download': info['download'],
                'file_stats': info['file_stats'],
                'duration': info['duration'],
                'total_replacements': info['total_replacements']
            })
        return jsonify(resp)

    lf = LOGS / f"{job_id}.log"
    if not lf.exists():
        return jsonify(error='Invalid Job ID'), 404
    parts = lf.read_text('utf-8').strip().split(',')
    _, names_semi, ts, ip, dur, repl = parts
    return jsonify({
        'job_id': job_id,
        'status': 'Done',
        'download': f"/download/{job_id}",
        'duration': float(dur),
        'total_replacements': int(repl),
        'file_stats': []
    })

@app.route('/download/<job_id>')
def download(job_id):
    token = request.args.get("token", "")
    info = SESSIONS.get(job_id)
    if not info or info.get("token") != token or info.get("status") != "Done":
        return ('Forbidden', 403)

    out = Path(info['output_path'])
    if not out.exists():
        return ('Not Found', 404)

    # Download the first output file in OUTPUT dir
    download_name = out.name
    if info['file_stats'] and len(info['file_stats']) == 1:
        download_name = info['file_stats'][0]['file']

    return send_from_directory(
        out.parent, out.name, as_attachment=True, download_name=download_name
    )

@app.route('/set_rules', methods=['POST'])
def set_rules():
    """Set custom regex rules for this session (validate and store in session)."""
    rules = request.json.get('rules', [])
    if len(rules) > MAX_RULES or any(len(r) > MAX_RULE_LEN for r in rules):
        return jsonify(error='Too many/long patterns'), 400

    if not rules:
        session.pop('custom_rules', None)
    else:
        try:
            for r in rules:
                re.compile(r)
        except re.error as e:
            return jsonify(error=f"Invalid regex: {e}"), 400

        session['custom_rules'] = rules
    session.modified = True
    return jsonify(status='Rules set')

@app.route('/bad_words')
def bad_words():
    """Serve the default list of patterns/rules."""
    lines = (BASE/'bad_words.txt').read_text('utf-8').splitlines()
    return jsonify(lines=[l for l in lines if l.strip()])

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--serve', action='store_true', help='Run HTTPS server')
    parser.add_argument('file', nargs='?', help='CLI input file')
    parser.add_argument('--rules', nargs='*', help='Inline regex rules')
    parser.add_argument('--rules-file', help='Load regex rules from file')
    args = parser.parse_args()

    ensure_selfsigned_certs()

    if args.serve:
        app.run(
            host='0.0.0.0', port=8443,
            ssl_context=(str(BASE/'certs'/'cert.pem'), str(BASE/'certs'/'key.pem')),
            threaded=True
        )
    elif args.file:
        purge_old()
        f = Path(args.file)
        if not f.is_file():
            print("Error: file not found", file=sys.stderr)
            sys.exit(1)

        job_id = uuid.uuid4().hex[:8]
        SESSIONS[job_id] = {
            'status': 'Queued',
            'token': uuid.uuid4().hex,  # 32-char secure token
            'time': datetime.now()
        }
        up = UPLOAD/f"{job_id}_{f.name}"
        shutil.copy(f, up)

        safe, nrep = sanitize_filename_windows(f.name)
        rules = None
        if args.rules_file:
            rules = [
                l.split('#',1)[0].strip()
                for l in Path(args.rules_file).read_text('utf-8').splitlines()
                if l.strip()
            ]
        elif args.rules:
            rules = args.rules

        process_file(job_id, [up], [safe], [f.name], 'CLI', rules)
        info = SESSIONS[job_id]
        print("Job ID:", job_id)
        print(f"Duration: {info.get('duration', 0):.2f}s")
        print(f"Total Replacements: {info.get('total_replacements', 0)}")
        if info.get('total_replacements', 0) > 0:
            print(f"Output file: {info.get('output_path', 'N/A')}")
        else:
            print("No replacements found. No output file generated.")
    else:
        parser.print_help()
