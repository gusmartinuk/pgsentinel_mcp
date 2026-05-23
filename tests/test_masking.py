from app.core.masking import MASK, mask_data, mask_text


def test_mask_text_removes_common_secret_values():
    raw = "DB_PASSWORD=abc TOKEN=def Authorization: Bearer secret-token password=hunter2"
    masked = mask_text(raw, ["DB_PASSWORD=", "TOKEN=", "Authorization:", "Bearer ", "password="])

    assert "abc" not in masked
    assert "def" not in masked
    assert "hunter2" not in masked
    assert MASK in masked


def test_mask_data_masks_sensitive_keys():
    masked = mask_data({"api_key": "abc", "nested": {"token": "def"}, "name": "safe"})

    assert masked["api_key"] == MASK
    assert masked["nested"]["token"] == MASK
    assert masked["name"] == "safe"
