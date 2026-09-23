class AnalyzerRegistry:
    def __init__(self):
        self._analyzers = []

    def register(self, analyzer):
        if any(item.control_id == analyzer.control_id for item in self._analyzers):
            raise ValueError(f"Analyzer duplikat: {analyzer.control_id}")
        self._analyzers.append(analyzer)
        return self

    def all(self):
        return list(self._analyzers)
