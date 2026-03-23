"""Tests for lockfile diff parsing."""

from __future__ import annotations

from heckler.lockfile import (
    detect_ecosystem,
    parse_changed_packages,
)


class TestDetectEcosystem:
    def test_npm(self) -> None:
        assert detect_ecosystem("package-lock.json") == "npm"

    def test_yarn(self) -> None:
        assert detect_ecosystem("yarn.lock") == "yarn"

    def test_pnpm(self) -> None:
        assert detect_ecosystem("pnpm-lock.yaml") == "pnpm"

    def test_pip(self) -> None:
        assert detect_ecosystem("requirements.txt") == "pip"

    def test_poetry(self) -> None:
        assert detect_ecosystem("poetry.lock") == "poetry"

    def test_unknown(self) -> None:
        assert detect_ecosystem("somefile.txt") == "unknown"

    def test_full_path(self) -> None:
        assert detect_ecosystem("/path/to/package-lock.json") == "npm"


class TestParseChangedPackages:
    def test_npm_lockfile_diff(self) -> None:
        diff = '''\
--- a/package-lock.json
+++ b/package-lock.json
@@ -1,5 +1,10 @@
+    "node_modules/lodash": {
+      "version": "4.17.21"
+    },
+    "node_modules/@scope/pkg": {
+      "version": "1.0.0"
     }
'''
        packages = parse_changed_packages(diff, "npm")
        names = [p[0] for p in packages]
        assert "lodash" in names
        assert "@scope/pkg" in names

    def test_pip_diff(self) -> None:
        diff = '''\
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,3 +1,5 @@
 flask==3.0.0
+requests==2.31.0
+django>=4.2
'''
        packages = parse_changed_packages(diff, "pip")
        names = [p[0] for p in packages]
        assert "requests" in names
        assert "django" in names

    def test_yarn_diff(self) -> None:
        diff = '''\
--- a/yarn.lock
+++ b/yarn.lock
@@ -1,5 +1,10 @@
+"lodash@^4.17.21":
+  version "4.17.21"
+"@babel/core@^7.24.0":
+  version "7.24.0"
'''
        packages = parse_changed_packages(diff, "yarn")
        names = [p[0] for p in packages]
        assert "lodash" in names
        assert "@babel/core" in names

    def test_pnpm_diff(self) -> None:
        diff = '''\
--- a/pnpm-lock.yaml
+++ b/pnpm-lock.yaml
@@ -1,5 +1,10 @@
+  /lodash@4.17.21:
+    resolution: {integrity: sha512-xxx}
+  /@scope/pkg@1.0.0:
+    resolution: {integrity: sha512-yyy}
'''
        packages = parse_changed_packages(diff, "pnpm")
        names = [p[0] for p in packages]
        assert "lodash" in names
        assert "@scope/pkg" in names

    def test_empty_diff(self) -> None:
        assert parse_changed_packages("", "npm") == []
