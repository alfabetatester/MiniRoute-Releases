import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

class SignatureTests(unittest.TestCase):
    def test_signed_manifest_and_tamper_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            key = root / "key.pem"
            pub = root / "public.pem"
            source = root / "snapshot.json"
            out = root / "out"
            source.write_text(json.dumps({"updatedAt": 123}))
            subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(key)], check=True)
            subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(pub)], check=True)
            subprocess.run([sys.executable, str(pathlib.Path(__file__).with_name("sign_snapshot.py")), str(source), str(key), str(out)], check=True)
            manifest = out / "manifest.json"
            data = json.loads(manifest.read_bytes())
            self.assertEqual(data["sha256"], hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertEqual((out / data["file"]).read_bytes(), source.read_bytes())
            cmd = ["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(pub), "-in", str(manifest), "-sigfile", str(out / "manifest.sig")]
            subprocess.run(cmd, check=True)
            manifest.write_bytes(manifest.read_bytes() + b" ")
            self.assertNotEqual(subprocess.run(cmd).returncode, 0)
