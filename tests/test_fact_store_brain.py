from modules.pipeline.brain.fact_store import Fact, FactCategory, FactStore, PrerequisiteQuery


def test_fact_store_add_query_export_and_summary():
    FactStore.reset()
    store = FactStore()
    store.clear()

    cred = store.add_credential("alice", password="secret", source_validator_id="cred_validator")
    host = store.add_internal_host("10.0.0.5", services=["ssh"], source_validator_id="ssrf_validator")
    vuln = store.add_confirmed_vulnerability(
        vuln_id="vuln-1",
        vuln_type="ssrf",
        target="https://example.test",
        source_validator_id="ssrf_validator",
        source_chain=["seed"],
    )
    artifact = store.add_exploitation_artifact(
        artifact_id="artifact-1",
        artifact_type="shell_output",
        content="uid=0(root)",
        source_vulnerability="rce",
    )

    assert store.get_fact(FactCategory.CREDENTIAL, cred.key) == cred
    assert store.get_chain_facts("ssrf_validator") == [host, vuln]
    assert store.get_exploitation_chain("vuln-1") == ["seed"]
    assert store.get_summary()[FactCategory.CREDENTIAL.value] == 1
    assert store.get_facts_with_confidence(0.9)[FactCategory.CONFIRMED_VULNERABILITY.value] == [vuln]

    exported = store.export()
    assert exported[FactCategory.CREDENTIAL.value][cred.key]["value"]["username"] == "alice"
    assert exported[FactCategory.EXPLOITATION_ARTIFACT.value][artifact.key]["value"]["type"] == "shell_output"


def test_fact_store_prerequisites_query_and_clear():
    FactStore.reset()
    store = FactStore()
    store.clear()

    store.add_internal_host("10.0.0.9", confidence=0.95)
    store.add_confirmed_vulnerability("vuln-2", "lfi", "/download", confidence=0.8)

    query = PrerequisiteQuery(
        required_facts={
            FactCategory.INTERNAL_HOST: ["10.0.0.9"],
            FactCategory.CONFIRMED_VULNERABILITY: ["vuln-2"],
        },
        min_confidence=0.7,
    )

    assert store.prerequisites_met(query)
    assert query.is_satisfied_by(store)

    store.clear()
    assert store.get_summary()[FactCategory.INTERNAL_HOST.value] == 0
