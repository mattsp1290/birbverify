import json
import time
from pathlib import Path

data = json.loads(Path('/candidate/value.json').read_text())
time.sleep(data.get('delay', 0))
value = data['value']
print(json.dumps({'assertion': 'value equals 42', 'observed': value, 'passed': value == 42}))
raise SystemExit(0 if value == 42 else 1)
