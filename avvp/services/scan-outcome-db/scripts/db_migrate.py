#!/usr/bin/env python3
"""Simple DB migration runner for avvp/services/scan-outcome-db

Usage:
  python db_migrate.py --dsn "postgresql://avvp:avvp@localhost:5432/avvp"
"""
import argparse
import os
import psycopg2
from psycopg2.extras import execute_batch

MIGRATIONS_DIR = os.path.join(os.path.dirname(__file__), "../migrations")


def get_conn(dsn):
    return psycopg2.connect(dsn)


def ensure_migrations_table(conn):
    with conn.cursor() as cur:
        cur.execute("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
          id TEXT PRIMARY KEY,
          applied_at TIMESTAMPTZ DEFAULT now()
        )
        """)
        conn.commit()


def applied_migrations(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM schema_migrations")
        rows = cur.fetchall()
    return {r[0] for r in rows}


def apply_migration(conn, migration_path, migration_id):
    with open(migration_path, 'r') as f:
        sql = f.read()
    with conn.cursor() as cur:
        cur.execute(sql)
        cur.execute("INSERT INTO schema_migrations (id) VALUES (%s)", (migration_id,))
    conn.commit()
    print(f"Applied {migration_id}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dsn', help='Postgres DSN', default=os.environ.get('DATABASE_URL', 'postgresql://avvp:avvp@127.0.0.1:5432/avvp'))
    args = parser.parse_args()

    migrations_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'migrations'))
    files = sorted([f for f in os.listdir(migrations_dir) if f.endswith('.sql')])

    conn = get_conn(args.dsn)
    try:
        ensure_migrations_table(conn)
        applied = applied_migrations(conn)
        for f in files:
            if f in applied:
                print(f"Skipping already applied {f}")
                continue
            path = os.path.join(migrations_dir, f)
            apply_migration(conn, path, f)
    finally:
        conn.close()

if __name__ == '__main__':
    main()
