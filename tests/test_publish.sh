rm -rf dist build *.egg-info
python -m build
python -m venv .venv-test
. .venv-test/bin/activate
pip install dist/icp_py_core-*.whl
python - <<'PY'
from icp_core import Agent, Client, Identity, Principal, encode, decode, Types, Certificate
print("icp_core facade imports OK")
from icp_agent import Agent as A2, Client as C2
from icp_identity import Identity as I2
from icp_principal import Principal as P2
from icp_candid import encode as e2, decode as d2, Types as T2
from icp_certificate import Certificate as Cert2
print("subpackage imports OK")
PY