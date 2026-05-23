import pytest

from app.core.errors import SecurityError
from app.core.security import SQLPolicy, guard_sql_query, validate_readonly_sql


def test_readonly_sql_allows_select_and_adds_limit():
    sql = validate_readonly_sql("select id from users", ["users"], 50)

    assert sql.lower().endswith("limit 50")


def test_readonly_sql_blocks_writes():
    with pytest.raises(SecurityError):
        validate_readonly_sql("delete from users", ["users"], 50)


def test_readonly_sql_blocks_non_allowlisted_table():
    with pytest.raises(SecurityError):
        validate_readonly_sql("select id from secrets", ["users"], 50)


def test_readonly_sql_blocks_multiple_statements():
    with pytest.raises(SecurityError):
        validate_readonly_sql("select id from users; select id from users", ["users"], 50)


def test_guard_sql_allows_show_in_readonly_mode():
    decision = guard_sql_query("show all", [], SQLPolicy(), None, 50)
    assert decision.category == "read"


def test_guard_sql_blocks_update_in_readonly_mode():
    with pytest.raises(SecurityError):
        guard_sql_query("update users set name='x'", ["users"], SQLPolicy(), None, 50)


def test_guard_sql_allows_update_when_enabled():
    policy = SQLPolicy(mode="guarded_write", allow_update=True)
    decision = guard_sql_query("update users set name='x'", ["users"], policy, None, 50)
    assert decision.category == "update"


def test_guard_sql_blocks_with_insert_even_in_readonly_mode():
    with pytest.raises(SecurityError):
        guard_sql_query(
            "with a as (insert into users(id) values (1) returning id) select * from a",
            ["users"],
            SQLPolicy(),
            None,
            50,
        )


def test_guard_sql_does_not_append_limit_to_show():
    decision = guard_sql_query("show search_path", [], SQLPolicy(), None, 50)
    assert decision.sql.lower() == "show search_path"
