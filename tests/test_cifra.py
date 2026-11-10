"""Chave de cifra própria (secrets/data_key): migração da chave de origem, troca de chave e o que deixa de abrir."""
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from certwatch import cifra, config, mfa
from certwatch.db import session_scope
from certwatch.models import ConnectorConfig, User

K1 = "k1-" + "a" * 40
K2 = "k2-" + "b" * 40
AUTH = ("admin", "teste-admin-123")


def seed(settings):
    with session_scope() as s:
        s.merge(ConnectorConfig(role="cmdb", kind="rest", params={}, secrets_enc=cifra.encrypt(settings, {"password": "pw-secreta"})))
        s.add(User(email="ana@exemplo.pt", status="ativo", totp_on=True, totp_secret=mfa.seal(settings, "JBSWY3DPEHPK3PXP")))


def stored():
    with session_scope() as s:
        return (s.get(ConnectorConfig, "cmdb").secrets_enc, s.scalar(select(User.totp_secret).where(User.email == "ana@exemplo.pt")))


def test_without_own_key_everything_works_as_before(env):
    token = cifra.encrypt(env, {"a": 1})
    assert not token.startswith("v2:") and cifra.decrypt(env, token) == {"a": 1} and cifra.current(env, token)
    assert cifra.rekey_all(env) == {"cifrados_de_novo": 0, "ilegiveis": 0}
    assert cifra.encrypt(env, {}) == "" and cifra.decrypt(env, "") == {} and cifra.decrypt(env, "lixo") == {}


def test_own_key_migrates_what_was_stored_and_no_longer_depends_on_the_database_url(env):
    seed(env)
    st = replace(env, data_key=K1)
    assert cifra.status(st)["por_migrar"] == 2
    assert cifra.decrypt(st, stored()[0]) == {"password": "pw-secreta"}          # a de origem continua a abrir
    assert cifra.rekey_all(st) == {"cifrados_de_novo": 2, "ilegiveis": 0}
    a, b = stored()
    assert a.startswith("v2:") and b.startswith("v2:") and "pw-secreta" not in a
    assert cifra.rekey_all(st) == {"cifrados_de_novo": 0, "ilegiveis": 0}         # repetir não muda nada
    # mudar a palavra-passe da base de dados já não estraga nada
    moved = replace(st, database_url=st.database_url + "?outra=1")
    assert cifra.decrypt(moved, a) == {"password": "pw-secreta"} and mfa.unseal(moved, b) == "JBSWY3DPEHPK3PXP"
    assert cifra.decrypt(replace(moved, data_key=None), a) == {}                  # sem a chave não abre
    assert cifra.status(st) == {"propria": True, "problemas": [], "antiga": False, "valores": 2, "por_migrar": 0, "ilegiveis": 0}


def test_rotation_with_the_old_key_present_and_loss_without_it(env):
    st1 = replace(env, data_key=K1)
    seed(st1)
    before = stored()
    st2 = replace(env, data_key=K2, data_key_old=K1)
    assert cifra.decrypt(st2, before[0]) == {"password": "pw-secreta"} and not cifra.current(st2, before[0])
    assert cifra.rekey_all(st2) == {"cifrados_de_novo": 2, "ilegiveis": 0}
    after = stored()
    only_new = replace(env, data_key=K2)
    assert cifra.decrypt(only_new, after[0]) == {"password": "pw-secreta"} and mfa.unseal(only_new, after[1]) == "JBSWY3DPEHPK3PXP"
    assert cifra.decrypt(st1, after[0]) == {}                                     # a antiga já não abre o que foi trocado
    # chave trocada sem deixar a antiga: nada é estragado, só deixa de abrir, e a página diz quantos
    lost = replace(env, data_key="k3-" + "c" * 40)
    assert cifra.rekey_all(lost) == {"cifrados_de_novo": 0, "ilegiveis": 2} and stored() == after
    assert cifra.status(lost)["ilegiveis"] == 2


def test_short_key_is_refused_and_page_tells_the_state(env, monkeypatch):
    weak = replace(env, data_key="curta")
    assert "curto demais" in cifra.problems(weak)[0] and not cifra.own_key(weak)
    from certwatch.web import app as webapp
    monkeypatch.setattr(webapp, "get_settings", lambda: weak)
    with pytest.raises(RuntimeError, match="curto demais"):
        with TestClient(webapp.app):
            pass
    monkeypatch.setattr(webapp, "get_settings", config.get_settings)
    with TestClient(webapp.app) as c:
        assert "derivada da ligação à base de dados" in c.get("/fontes", auth=AUTH).text
        st = replace(env, data_key=K1)
        seed(st)
        monkeypatch.setattr(webapp, "get_settings", lambda: st)
        page = c.get("/fontes", auth=AUTH).text
        assert "própria (" in page and "2 valores guardados" in page and K1 not in page
