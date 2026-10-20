from certwatch.jobs import run_now


def test_pipeline_marks_error_when_ingest_fails(env):
    # cmdb.exemplo.local não resolve: a ingestão falha, o scan e a avaliação correm na mesma
    jr = run_now("pipeline", "teste", env)
    assert jr.status == "error"
    assert "erro" in jr.summary["ingest_cmdb"]
    assert "scan" in jr.summary and "evaluate" in jr.summary
