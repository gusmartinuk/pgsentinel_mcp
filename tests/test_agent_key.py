from __future__ import annotations

from app.core.agent_key import (
    generate_agent_token,
    hash_agent_token,
    verify_agent_token,
    is_valid_agent_token_format,
    AGENT_KEY_PREFIX,
)


def test_token_format():
    token = generate_agent_token()
    assert token.startswith(AGENT_KEY_PREFIX)
    assert len(token) > len(AGENT_KEY_PREFIX) + 32
    assert is_valid_agent_token_format(token)


def test_invalid_format():
    assert not is_valid_agent_token_format("")
    assert not is_valid_agent_token_format("bad_token")
    assert not is_valid_agent_token_format("pgs_ai_short")


def test_hash_and_verify():
    token = generate_agent_token()
    h = hash_agent_token(token)
    assert verify_agent_token(token, h)
    assert not verify_agent_token(token + "x", h)
    assert not verify_agent_token("wrong_token", h)


def test_hash_uses_fresh_salt():
    token = generate_agent_token()
    assert hash_agent_token(token) != hash_agent_token(token)


def test_verify_with_bad_hash():
    token = generate_agent_token()
    assert not verify_agent_token(token, "not_a_valid_hash_format")


def test_unique_tokens():
    tokens = {generate_agent_token() for _ in range(50)}
    assert len(tokens) == 50


def test_rotation():
    old_token = generate_agent_token()
    old_hash = hash_agent_token(old_token)

    new_token = generate_agent_token()
    new_hash = hash_agent_token(new_token)

    assert verify_agent_token(old_token, old_hash)
    assert not verify_agent_token(old_token, new_hash)
    assert verify_agent_token(new_token, new_hash)
    assert not verify_agent_token(new_token, old_hash)
