from sqlalchemy import inspect, text

from certwatch import db


def test_init_db_adds_columns_to_existing_database(env):
    """Uma base de dados criada pela v0.1 (sem as colunas novas) é atualizada no arranque."""
    engine = db.get_engine()
    with engine.begin() as conn:
        conn.execute(text("DROP INDEX IF EXISTS ix_certificates_ski"))
        conn.execute(text("ALTER TABLE certificates DROP COLUMN ski"))
        conn.execute(text("ALTER TABLE scan_results DROP COLUMN resolved_ip"))
        for col in ("application", "location", "cmdb_expired", "registered_at"):   # v0.3 -> v0.4
            conn.execute(text(f"ALTER TABLE api_records DROP COLUMN {col}"))
        conn.execute(text("DROP TABLE ssllabs_results"))
    cols = {c["name"] for c in inspect(engine).get_columns("certificates")}
    assert "ski" not in cols
    db.init_db()
    insp = inspect(engine)
    assert "ski" in {c["name"] for c in insp.get_columns("certificates")}
    assert "resolved_ip" in {c["name"] for c in insp.get_columns("scan_results")}
    assert "api_records" in insp.get_table_names() and "ssllabs_results" in insp.get_table_names()
    assert {"application", "location", "cmdb_expired", "registered_at"} <= {c["name"] for c in insp.get_columns("api_records")}
    assert "ix_certificates_ski" in {i["name"] for i in insp.get_indexes("certificates")}
