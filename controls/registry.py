from controls.catalog import load_catalog

class ControlRegistry:
    def __init__(self):
        self.metadata,self._controls=load_catalog()
        self.validate()
    def validate(self):
        ids=[c.control_id for c in self._controls]; seq=[c.sequence for c in self._controls]
        if len(self._controls)!=118: raise ValueError(f"Catalog harus 118 kontrol, ditemukan {len(self._controls)}")
        if len(set(ids))!=len(ids): raise ValueError("ID kontrol duplikat")
        if len(set(seq))!=len(seq): raise ValueError("Urutan kontrol duplikat")
        if len(self.get_basic_controls())!=78 or len(self.get_advanced_controls())!=40: raise ValueError("Komposisi Basic/Advanced tidak valid")
        required=("control_id","control_name","profile","area","verification_method")
        for c in self._controls:
            if any(not getattr(c,x) for x in required): raise ValueError(f"Field wajib kosong: {c.control_id}")
        return True
    def get_all_controls(self): return list(sorted(self._controls,key=lambda c:c.sequence))
    def get_basic_controls(self): return [c for c in self._controls if c.profile=="Basic"]
    def get_advanced_controls(self): return [c for c in self._controls if c.profile=="Advanced"]
    def get_control_by_id(self,control_id): return next((c for c in self._controls if c.control_id==control_id),None)
    def filter(self,profile=None,area=None,method=None,risk=None,side=None,query=None):
        items=self.get_all_controls(); q=(query or "").strip().lower()
        if profile and profile!="Semua": items=[c for c in items if c.profile==profile]
        if area and area!="Semua": items=[c for c in items if c.area==area]
        if method and method!="Semua": items=[c for c in items if c.verification_method==method]
        if risk and risk!="Semua": items=[c for c in items if c.security_risk==risk]
        if side and side!="Semua": items=[c for c in items if c.implementation_side==side]
        if q: items=[c for c in items if q in c.control_id.lower() or q in c.control_name.lower()]
        return items
