from keyholderd.leases import LeaseStore

def test_create_lookup_revoke_and_expiry(tmp_path):
    store = LeaseStore(str(tmp_path/"leases.db"))
    lease = store.create_lease("hermes", "default", "g", "fake", 60, "reason")
    found = store.get_lease(lease.lease_id)
    assert found.grant_name == "g" and not found.is_expired()
    store.revoke(lease.lease_id)
    assert store.get_lease(lease.lease_id).revoked_at is not None
    expired = store.create_lease("hermes", "default", "g", "fake", -1, "expired")
    assert store.get_lease(expired.lease_id).is_expired()
