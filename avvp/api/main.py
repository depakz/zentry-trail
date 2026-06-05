from fastapi import FastAPI, File, UploadFile, Form
from fastapi.responses import JSONResponse
from avvp.services.evidence_store.store import EvidenceStore
from avvp.services.evidence_store.signer import EvidenceSigner
from avvp.services.reporter.reporter import Reporter
from avvp.services.payload_library.catalog import library_index
import shutil
import os

app = FastAPI(title='avvp-api')

# use local store by default
STORE = EvidenceStore()
SIGNER = EvidenceSigner()
STORE.attach_signer(SIGNER)
REPORTER = Reporter()

@app.get('/health')
async def health():
    return {'status':'ok'}

@app.post('/evidence/upload')
async def upload_evidence(name: str = Form(...), file: UploadFile = File(...)):
    data = await file.read()
    res = STORE.save_evidence(data, {'name': name, 'object_name': name})
    return JSONResponse(res)

@app.get('/payloads')
async def list_payloads():
    base = os.path.join(os.path.dirname(__file__), '..', 'payload-library', 'templates')
    base = os.path.abspath(base)
    if not os.path.exists(base):
        return {'templates': [], 'categories': [], 'count': 0}
    index = library_index(base)
    templates = []
    for category in index['categories']:
        for filename in category['files']:
            templates.append({'category': category['name'], 'file': filename, 'path': os.path.join(category['name'], filename)})
    return {'templates': templates, 'categories': index['categories'], 'count': index['count']}

@app.post('/report/generate')
async def generate_report(findings: dict):
    # findings expected to be a dict or list under 'findings'
    f = findings.get('findings') if isinstance(findings, dict) else findings
    if f is None:
        return JSONResponse({'error':'no findings provided'}, status_code=400)
    sarif = REPORTER.write_sarif(f)
    html = REPORTER.write_html(f)
    return {'sarif': sarif, 'html': html}
