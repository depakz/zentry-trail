import os
import ast
import sys
from pathlib import Path

def get_std_libs():
    return {
        "abc", "argparse", "array", "ast", "asyncio", "base64", "binascii", "bisect", "builtins",
        "calendar", "cmath", "cmd", "code", "codecs", "collections", "colorsys", "compileall",
        "concurrent", "configparser", "contextlib", "contextvars", "copy", "copyreg", "crypt",
        "csv", "ctypes", "datetime", "dbm", "decimal", "difflib", "dis", "distutils", "doctest",
        "email", "encodings", "ensurepip", "enum", "errno", "faulthandler", "filecmp", "fileinput",
        "fnmatch", "fractions", "ftplib", "functools", "gc", "getopt", "getpass", "gettext",
        "glob", "graphlib", "grp", "gzip", "hashlib", "hmac", "html", "http", "imaplib", "imghdr",
        "imp", "importlib", "inspect", "io", "ipaddress", "itertools", "json", "keyword", "lib2to3",
        "linecache", "locale", "logging", "lzma", "mailbox", "mailcap", "marshal", "math",
        "mimetypes", "mmap", "modulefinder", "multiprocessing", "netrc", "nis", "nntplib", "ntpath",
        "numbers", "operator", "optparse", "os", "ossaudiodev", "pathlib", "pdb", "pickle", "pipes",
        "pkgutil", "platform", "plistlib", "poplib", "posix", "posixpath", "pprint", "profile",
        "pstats", "pty", "pwd", "py_compile", "pyclbr", "pydoc", "queue", "quopri", "random", "re",
        "readline", "reprlib", "resource", "rlcompleter", "runpy", "sched", "select", "selectors",
        "shelve", "shutil", "signal", "site", "smtpd", "smtplib", "sndhdr", "socket", "socketserver",
        "spwd", "sqlite3", "ssl", "stat", "statistics", "string", "stringprep", "struct", "subprocess",
        "sunau", "symtable", "sys", "sysconfig", "syslog", "tabnanny", "tarfile", "telnetlib", "tempfile",
        "termios", "test", "textwrap", "threading", "time", "timeit", "tkinter", "token", "tokenize",
        "trace", "traceback", "tracemalloc", "tty", "types", "typing", "unicodedata", "unittest",
        "urllib", "uu", "uuid", "warnings", "wave", "weakref", "webbrowser", "wsgiref", "xdg", "xml",
        "xmlrpc", "zipapp", "zipfile", "zipimport", "zlib", "zoneinfo", "__future__", "dataclasses",
        "secrets", "socketserver", "sys", "os"
    }

def find_imports(dir_path):
    imports = set()
    for root, _, files in os.walk(dir_path):
        for file in files:
            if file.endswith(".py"):
                path = Path(root) / file
                try:
                    tree = ast.parse(path.read_text(encoding="utf-8"))
                except Exception as e:
                    continue
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            imports.add(alias.name.split(".")[0])
                    elif isinstance(node, ast.ImportFrom):
                        if node.level == 0 and node.module:
                            imports.add(node.module.split(".")[0])
    return imports

def main():
    all_imports = find_imports("/home/dk/zentry-trail/zentry") | find_imports("/home/dk/zentry-trail/tests")
    std_libs = get_std_libs()
    
    filtered = sorted([
        imp for imp in all_imports
        if imp not in std_libs and imp not in ("zentry", "tests", "")
    ])
    
    print("All third-party imports in zentry & tests:")
    for imp in filtered:
        print(f"  - {imp}")

if __name__ == "__main__":
    main()
