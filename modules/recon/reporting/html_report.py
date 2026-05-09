from pathlib import Path
from jinja2 import Environment, FileSystemLoader

def write(session, out_dir="reports") -> str:
    Path(out_dir).mkdir(exist_ok=True)
    env = Environment(loader=FileSystemLoader("reporting/templates"))
    tpl = env.get_template("report.html.j2")
    html = tpl.render(s=session)
    p = Path(out_dir) / f"{session.target.replace('.','_')}.html"
    p.write_text(html)
    return str(p)
