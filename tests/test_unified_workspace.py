from controls.registry import ControlRegistry
from manual_review.workspace import ManualReviewWorkspace
from analysis.semi_automatic import SemiAutomaticWorkspace


def test_catalog_has_118_controls():
    assert len(ControlRegistry().get_all_controls()) == 118


def test_review_workspaces_share_catalog_control_ids():
    registry = ControlRegistry()
    ids = {item.control_id for item in registry.get_all_controls()}
    assert set(ManualReviewWorkspace(registry).records).issubset(ids)
    assert set(SemiAutomaticWorkspace(registry).reviews).issubset(ids)
