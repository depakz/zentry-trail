from modules.pipeline.brain.endpoint_normalizer import EndpointNormalizer


def test_normalize_url_and_infer_parameter_types():
    normalizer = EndpointNormalizer()

    assert normalizer.infer_parameter_type("123") == "{int}"
    assert normalizer.infer_parameter_type("550e8400-e29b-41d4-a716-446655440000") == "{uuid}"
    assert normalizer.infer_parameter_type("alice@example.test") == "{email}"
    assert normalizer.infer_parameter_type("d41d8cd98f00b204e9800998ecf8427e") == "{md5}"
    assert normalizer.infer_parameter_type("a" * 64) == "{sha256}"
    assert normalizer.infer_parameter_type("deadbeef") == "{hex}"
    assert normalizer.normalize_url("https://example.test/item.php?id=123&name=alice") == "/item.php?id={int}&name={str}"


def test_register_mark_skip_and_export():
    normalizer = EndpointNormalizer()

    pattern_key, already_scanned = normalizer.register_endpoint("https://example.test/item.php?id=1", "xss")
    assert already_scanned is False
    assert pattern_key == "/item.php?id={int}::xss"

    assert normalizer.should_skip_scan("https://example.test/item.php?id=2", "xss") is False
    normalizer.mark_pattern_scanned(pattern_key, result={"success": True}, confidence_adjustment=-0.1)
    assert normalizer.should_skip_scan("https://example.test/item.php?id=3", "xss") is True
    assert normalizer.get_confidence_adjustment(pattern_key) == -0.1

    candidates = normalizer.get_pattern_candidates("/item.php?id={int}")
    assert candidates == ["https://example.test/item.php?id=1", "https://example.test/item.php?id=2", "https://example.test/item.php?id=3"]

    variant = normalizer.get_or_create_exploitation_variant(pattern_key, "https://example.test/item.php?id=999")
    assert variant == "https://example.test/item.php?id=1"

    stats = normalizer.get_pattern_stats()
    assert stats["total_patterns"] == 1
    assert stats["scanned_patterns"] == 1
    assert stats["patterns_by_vuln_type"]["xss"] == 1

    exported = normalizer.export()
    assert pattern_key in exported

    normalizer.clear()
    assert normalizer.get_pattern_stats()["total_patterns"] == 0
