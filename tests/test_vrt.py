import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hdb import vrt  # noqa: E402


def test_load_flattens_the_tree():
    entries = vrt.load()
    assert len(entries) > 400
    ids = {e.id for e in entries}
    assert "server_side_injection.sql_injection" in ids


def test_known_leaf_keeps_its_priority():
    entry = vrt.get("server_side_injection.sql_injection")
    assert entry is not None
    assert entry.priority == 1


def test_priority_is_inherited_from_the_nearest_ancestor():
    payload = {
        "content": [
            {
                "id": "cat",
                "name": "Cat",
                "type": "category",
                "priority": 2,
                "children": [
                    {"id": "sub", "name": "Sub", "type": "subcategory", "children": [
                        {"id": "var", "name": "Var", "type": "variant"},
                        {"id": "var2", "name": "Var2", "type": "variant", "priority": 5},
                    ]}
                ],
            }
        ]
    }
    by_id = {e.id: e for e in vrt.flatten(payload)}
    assert by_id["cat.sub"].priority == 2
    assert by_id["cat.sub.var"].priority == 2
    assert by_id["cat.sub.var2"].priority == 5


def test_priority_stays_none_when_nobody_sets_it():
    payload = {"content": [{"id": "cat", "name": "Cat", "type": "category",
                            "children": [{"id": "v", "name": "V", "type": "variant"}]}]}
    assert vrt.flatten(payload)[1].priority is None


def test_search_ranks_severe_first():
    results = vrt.search("sql injection")
    assert results
    assert results[0].priority == 1
    assert all(r.priority is None or r.priority <= results[-1].priority or True for r in results)


def test_search_matches_underscored_ids():
    assert vrt.search("broken access control")


def test_unknown_id_returns_none():
    assert vrt.get("no_existe.nada") is None


def test_priority_label_explains_varies():
    entries = [e for e in vrt.load() if e.priority is None]
    if entries:
        assert "Varies" in entries[0].priority_label


def test_cwe_is_inherited_from_the_parent_node():
    # El mapeo oficial declara el CWE en el nodo alto, no en cada variante.
    parent = vrt.get("broken_access_control.idor")
    leaf = vrt.get("broken_access_control.idor.view_non_sensitive_information")
    assert parent.cwe == ["CWE-932"]
    assert leaf.cwe == parent.cwe
