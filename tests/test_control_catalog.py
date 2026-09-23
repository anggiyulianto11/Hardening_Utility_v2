from controls.registry import ControlRegistry
def test_catalog_counts():
 r=ControlRegistry(); assert len(r.get_all_controls())==118; assert len(r.get_basic_controls())==78; assert len(r.get_advanced_controls())==40
def test_unique_ids_and_sequence():
 items=ControlRegistry().get_all_controls(); assert len({x.control_id for x in items})==118; assert len({x.sequence for x in items})==118
def test_known_controls():
 r=ControlRegistry(); assert r.get_control_by_id("AS-B23").control_name=="callbackFunctionsEnabled set to false"; assert r.get_control_by_id("AS-A4").profile=="Advanced"
def test_filters():
 r=ControlRegistry(); assert all(x.profile=="Basic" for x in r.filter(profile="Basic")); assert r.filter(query="AS-B23")[0].control_id=="AS-B23"
