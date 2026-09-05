from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from ..models import Confidence, Evidence, Finding, Purpose, SourceSpan
from ..policy import (
    algorithm_status,
    default_severity,
    references_for,
    targets_for,
)
from ..util import (
    algorithm_display,
    normalize_algorithm,
    sha256_text,
    test_only_path,
)
from .base import AnalyzerContext


@dataclass
class _Import:
    module: str
    name: str | None


def _flatten(values: object) -> list[str]:
    result: list[str] = []
    if isinstance(values, (str, bytes)) or not isinstance(values, Iterable):
        return result
    for value in values:
        if isinstance(value, str):
            result.append(value)
        elif isinstance(value, list):
            result.extend(_flatten(value))
    return result


class PythonAnalyzer:
    name = "python-ast"

    def analyze(self, path: Path, source: str, context: AnalyzerContext) -> list[Finding]:
        try:
            tree = ast.parse(source, filename=str(path))
        except (SyntaxError, ValueError, TypeError, RecursionError, MemoryError) as exc:
            context.parser_errors.append(
                {"path": path.relative_to(context.root).as_posix(), "error": str(exc)}
            )
            return []

        rel = path.relative_to(context.root).as_posix()
        aliases, shadowed = self._imports(tree)
        inferred_types = self._inferred_types(tree, aliases, shadowed)
        lines = source.splitlines()
        observations: list[tuple[ast.AST, str, Purpose, str, Confidence, str, str]] = []
        parents = {
            child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)
        }
        for node in ast.walk(tree):
            if self._statically_unreachable(node, parents):
                continue
            if isinstance(node, ast.Call):
                qname = self._qualified_name(node.func, aliases, inferred_types)
                if self._shadowed_call(node.func, shadowed):
                    continue
                algorithm, purpose, detail, confidence = self._classify_call(node, qname, aliases)
                if algorithm is None:
                    continue
                observations.append(
                    (node, algorithm, purpose, detail, confidence, "ast_call", qname)
                )
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                for target in self._assignment_targets(node):
                    qname = self._qualified_name(target, aliases, inferred_types)
                    algorithm, purpose, detail, confidence = self._classify_assignment(
                        target, node.value, qname, aliases, inferred_types
                    )
                    if algorithm is not None:
                        observations.append(
                            (
                                node,
                                algorithm,
                                purpose,
                                detail,
                                confidence,
                                "ast_assignment",
                                qname,
                            )
                        )
            else:
                continue

        findings: list[Finding] = []
        for node, algorithm, purpose, detail, confidence, evidence_type, qname in observations:
            display = algorithm_display(algorithm)
            line = getattr(node, "lineno", 1)
            source_line = lines[line - 1] if 0 < line <= len(lines) else ""
            span = SourceSpan(
                start_line=line,
                start_column=getattr(node, "col_offset", 0),
                end_line=getattr(node, "end_lineno", None),
                end_column=getattr(node, "end_col_offset", None),
            )
            test_only = test_only_path(rel)
            severity = default_severity(display, purpose, test_only=test_only)
            rule = self._rule_id(display, purpose, context)
            refs = references_for(display, purpose, context.rules_root)
            targets = targets_for(display, purpose, context.rules_root)
            symbol = self._symbol_context(node, tree)
            evidence_detail = f"{detail}; {evidence_type.removeprefix('ast_')}={qname}"
            evidence = Evidence(
                evidence_type=evidence_type,
                detail=evidence_detail,
                snippet_sha256=sha256_text(source_line.strip()),
                references=tuple(refs),
            )
            finding_id = Finding.stable_id(rule, rel, span, display, purpose, detail)
            rationale = self._rationale(display, purpose, confidence)
            findings.append(
                Finding(
                    finding_id=finding_id,
                    rule_id=rule,
                    category="cryptographic-use",
                    algorithm=display,
                    purpose=purpose,
                    source_path=rel,
                    span=span,
                    symbol=symbol,
                    evidence=[evidence],
                    confidence=confidence,
                    quantum_risk=algorithm_status(display),
                    severity=severity,
                    rationale=rationale,
                    migration_target=targets,
                    migration_confidence=(
                        Confidence.HIGH
                        if targets and purpose != Purpose.UNKNOWN
                        else Confidence.UNKNOWN
                    ),
                    references=refs,
                    suppressible=True,
                    analyzer=self.name,
                    environment="test" if test_only else "production",
                )
            )
        return self._deduplicate(findings)

    @staticmethod
    def _assignment_targets(node: ast.Assign | ast.AnnAssign) -> list[ast.AST]:
        if isinstance(node, ast.Assign):
            return list(node.targets)
        return [node.target]

    def _classify_assignment(
        self,
        target: ast.AST,
        value: ast.AST | None,
        qname: str,
        aliases: dict[str, _Import],
        inferred_types: dict[str, str],
    ) -> tuple[str | None, Purpose, str, Confidence]:
        if not isinstance(target, ast.Attribute) or value is None:
            return None, Purpose.UNKNOWN, "", Confidence.UNKNOWN

        context_qname, _, attribute = qname.rpartition(".")
        if normalize_algorithm(context_qname) not in {
            "SSL.SSLCONTEXT",
            "SSL.CREATEDEFAULTCONTEXT",
            "SSLCONTEXT",
            "CREATEDEFAULTCONTEXT",
        }:
            return None, Purpose.UNKNOWN, "", Confidence.UNKNOWN

        if attribute == "check_hostname" and isinstance(value, ast.Constant):
            if value.value is False:
                return (
                    "TLS-insecure",
                    Purpose.UNKNOWN,
                    "TLS context assignment disables hostname verification",
                    Confidence.HIGH,
                )
            return None, Purpose.UNKNOWN, "", Confidence.UNKNOWN

        if attribute == "verify_mode":
            value_qname = normalize_algorithm(self._qualified_name(value, aliases, inferred_types))
            if value_qname == "SSL.CERTNONE":
                return (
                    "TLS-insecure",
                    Purpose.UNKNOWN,
                    "TLS context assignment disables certificate validation",
                    Confidence.HIGH,
                )
        return None, Purpose.UNKNOWN, "", Confidence.UNKNOWN

    def _statically_unreachable(
        self,
        node: ast.AST,
        parents: dict[ast.AST, ast.AST],
    ) -> bool:
        current = node
        while current in parents:
            parent = parents[current]
            if isinstance(parent, ast.If):
                truth = self._constant_truth(parent.test)
                if truth is False and current in parent.body:
                    return True
                if truth is True and current in parent.orelse:
                    return True
            elif isinstance(parent, ast.While):
                if self._constant_truth(parent.test) is False and current in parent.body:
                    return True
            current = parent
        return False

    def _constant_truth(self, node: ast.AST) -> bool | None:
        if isinstance(node, ast.Constant):
            return bool(node.value)
        return None

    def _imports(self, tree: ast.AST) -> tuple[dict[str, _Import], set[str]]:
        aliases: dict[str, _Import] = {}
        shadowed: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for item in node.names:
                    local = item.asname or item.name.split(".")[0]
                    aliases[local] = _Import(item.name, None)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for item in node.names:
                    if item.name == "*":
                        continue
                    local = item.asname or item.name
                    aliases[local] = _Import(module, item.name)
            elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                targets = []
                if isinstance(node, ast.Assign):
                    targets = node.targets
                elif isinstance(node, ast.AnnAssign):
                    targets = [node.target]
                else:
                    targets = [node.target]
                for target in targets:
                    if isinstance(target, ast.Name) and target.id in aliases:
                        shadowed.add(target.id)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node.name in aliases:
                    shadowed.add(node.name)
        return aliases, shadowed

    def _qualified_name(
        self,
        node: ast.AST,
        aliases: dict[str, _Import],
        inferred_types: dict[str, str] | None = None,
    ) -> str:
        parts: list[str] = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            parts.reverse()
            if inferred_types and parts[0] in inferred_types:
                return ".".join([inferred_types[parts[0]], *parts[1:]])
            if parts and parts[0] in aliases:
                imported = aliases[parts[0]]
                prefix = imported.module
                if imported.name:
                    prefix = f"{prefix}.{imported.name}" if prefix else imported.name
                return ".".join([prefix, *parts[1:]]) if prefix else ".".join(parts)
            return ".".join(parts)
        return ""

    def _inferred_types(
        self, tree: ast.AST, aliases: dict[str, _Import], shadowed: set[str]
    ) -> dict[str, str]:
        candidates: dict[str, set[str]] = {}

        def add(name: str, value: str) -> None:
            if value:
                candidates.setdefault(name, set()).add(value)

        for node in ast.walk(tree):
            if isinstance(node, ast.arg) and node.annotation:
                if not self._shadowed_reference(node.annotation, shadowed):
                    add(node.arg, self._qualified_name(node.annotation, aliases))
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                if node.annotation and not self._shadowed_reference(node.annotation, shadowed):
                    add(node.target.id, self._qualified_name(node.annotation, aliases))
            elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                if self._shadowed_call(node.value.func, shadowed):
                    continue
                value_type = self._qualified_name(node.value.func, aliases)
                if value_type.endswith((".from_private_bytes", ".from_public_bytes", ".generate")):
                    value_type = value_type.rsplit(".", 1)[0]
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        add(target.id, value_type)
        # File-wide single-type inference is deliberately conservative; move to
        # lexical scopes if measured real-corpus collisions justify the added complexity.
        return {name: next(iter(values)) for name, values in candidates.items() if len(values) == 1}

    def _shadowed_call(self, node: ast.AST, shadowed: set[str]) -> bool:
        return self._shadowed_reference(node, shadowed)

    def _shadowed_reference(self, node: ast.AST, shadowed: set[str]) -> bool:
        current = node
        while isinstance(current, ast.Attribute):
            current = current.value
        return isinstance(current, ast.Name) and current.id in shadowed

    def _classify_call(
        self,
        node: ast.Call,
        qname: str,
        aliases: dict[str, _Import],
    ) -> tuple[str | None, Purpose, str, Confidence]:
        normalized = normalize_algorithm(qname)
        literals = self._string_literals(node)
        kwargs = {
            keyword.arg.lower(): self._keyword_values(keyword.value)
            for keyword in node.keywords
            if keyword.arg
        }
        algorithm_hint = " ".join(filter(None, literals + _flatten(kwargs.values())))

        if normalized.endswith(("JWT.ENCODE", "JWS.ENCODE", "PYJWS.ENCODE")):
            token_alg = self._jwt_algorithm(
                (kwargs.get("algorithm") or [])
                + _flatten(kwargs.get("headers", []))
                + literals
                + _flatten(kwargs.values())
            )
            if token_alg.startswith(("RS", "PS")):
                return "RSA", Purpose.SIGNATURE, f"JWT algorithm {token_alg}", Confidence.HIGH
            if token_alg.startswith("ES"):
                return "ECDSA", Purpose.SIGNATURE, f"JWT algorithm {token_alg}", Confidence.HIGH
            if token_alg == "EDDSA":
                return "EdDSA", Purpose.SIGNATURE, "JWT algorithm EdDSA", Confidence.HIGH
            if token_alg.startswith("HS"):
                return "HMAC", Purpose.MAC, f"JWT algorithm {token_alg}", Confidence.HIGH
        if normalized.endswith(("JWT.DECODE", "JWS.DECODE", "PYJWS.DECODE")):
            for value in literals + _flatten(kwargs.values()):
                upper = value.upper()
                if upper.startswith(("RS", "PS")):
                    return (
                        "RSA",
                        Purpose.SIGNATURE,
                        f"JWT verification algorithm {upper}",
                        Confidence.HIGH,
                    )
                if upper.startswith("ES"):
                    return (
                        "ECDSA",
                        Purpose.SIGNATURE,
                        f"JWT verification algorithm {upper}",
                        Confidence.HIGH,
                    )
                if upper == "EDDSA":
                    return (
                        "EdDSA",
                        Purpose.SIGNATURE,
                        "JWT verification algorithm EdDSA",
                        Confidence.HIGH,
                    )
                if upper.startswith("HS"):
                    return (
                        "HMAC",
                        Purpose.MAC,
                        f"JWT verification algorithm {upper}",
                        Confidence.HIGH,
                    )

        if normalized.endswith(("PADDING.OAEP", "PKCS1OAEP.NEW")):
            return (
                "RSA",
                Purpose.ENCRYPTION,
                "RSA OAEP encryption/key transport padding",
                Confidence.HIGH,
            )
        if normalized.endswith(("PADDING.PSS", "PADDING.PKCS1V15")):
            return "RSA", Purpose.SIGNATURE, "RSA signature padding", Confidence.HIGH
        if normalized.endswith(("RSA.GENERATEPRIVATEKEY", "RSA.GENERATE")):
            return (
                "RSA",
                Purpose.UNKNOWN,
                "RSA key generation; downstream purpose not visible",
                Confidence.MEDIUM,
            )
        if normalized.endswith(("RSA.SIGN", "PRIVATEKEY.SIGN")) and "RSA" in normalized:
            return "RSA", Purpose.SIGNATURE, "RSA signing call", Confidence.MEDIUM
        if "RSAPSS" in normalized or "RSASSA" in normalized:
            return "RSA", Purpose.SIGNATURE, "RSA signature primitive", Confidence.HIGH
        if "RSA" in normalized and any(word in normalized for word in ("ENCRYPT", "OAEP")):
            return "RSA", Purpose.ENCRYPTION, "RSA encryption/key transport call", Confidence.HIGH

        if normalized.endswith(("ECDSA", "ECDSA.SIGN", "ECDSA.VERIFY")):
            return "ECDSA", Purpose.SIGNATURE, "ECDSA signature context", Confidence.HIGH
        if normalized.endswith(
            (
                "SIGNINGKEY.FROMPEM",
                "VERIFYINGKEY.FROMPEM",
                "SIGNINGKEY.FROMSECRETEXPONENT",
                "VERIFYINGKEY.FROMPUBLICPOINT",
            )
        ):
            return (
                "ECDSA",
                Purpose.UNKNOWN,
                "ECDSA key material operation; downstream purpose is not visible",
                Confidence.MEDIUM,
            )
        if normalized.endswith(("ELLIPTICCURVE.POINT", "ECDSA.POINTISVALID")):
            return (
                "ECDSA",
                Purpose.UNKNOWN,
                "ECDSA mathematical/key operation; downstream purpose is not visible",
                Confidence.LOW,
            )
        if normalized.endswith(("ECDH", "ECDH.EXCHANGE")) or "ECDH" in normalized:
            return "ECDH", Purpose.KEY_ESTABLISHMENT, "ECDH key agreement context", Confidence.HIGH
        if normalized.endswith(
            ("EC.GENERATEPRIVATEKEY", "EC.SECP256R1", "EC.SECP384R1", "EC.SECP521R1")
        ):
            return (
                "ECDSA",
                Purpose.UNKNOWN,
                "elliptic-curve key operation; purpose not visible",
                Confidence.LOW,
            )

        if any(token in normalized for token in ("X25519", "X448")):
            algorithm = "X25519" if "X25519" in normalized else "X448"
            purpose = (
                Purpose.KEY_ESTABLISHMENT
                if any(
                    token in normalized
                    for token in ("EXCHANGE", "PRIVATEKEY", "PUBLICKEY", "GENERATE")
                )
                else Purpose.UNKNOWN
            )
            return (
                algorithm,
                purpose,
                f"{algorithm} operation",
                Confidence.HIGH if purpose != Purpose.UNKNOWN else Confidence.MEDIUM,
            )

        if any(token in normalized for token in ("ED25519", "ED448", "EDDSA")):
            return "EdDSA", Purpose.SIGNATURE, "EdDSA signature operation", Confidence.HIGH

        if "SLHDSA" in normalized:
            return "SLH-DSA", Purpose.SIGNATURE, "SLH-DSA signature operation", Confidence.HIGH

        if "DH.GENERATE" in normalized or normalized.endswith(("DH", "DH.EXCHANGE")):
            return (
                "finite-field DH",
                Purpose.KEY_ESTABLISHMENT,
                "finite-field Diffie-Hellman operation",
                Confidence.HIGH,
            )

        if normalized.endswith(
            ("HASHLIB.SHA256", "HASHLIB.SHA384", "HASHLIB.SHA512", "SHA256", "SHA384", "SHA512")
        ):
            return "SHA-2/SHA-3", Purpose.HASHING, "hash constructor", Confidence.HIGH
        if normalized.endswith("HMAC.NEW") or normalized.endswith("HMAC"):
            return "HMAC", Purpose.MAC, "HMAC construction", Confidence.HIGH
        if normalized.endswith(("HKDF", "PBKDF2HMAC", "SCRYPT")):
            return "SHA-2/SHA-3", Purpose.KDF, "key derivation construction", Confidence.MEDIUM

        tokens = {normalize_algorithm(token) for token in algorithm_hint.split()}
        if normalized.endswith("SSL.WRAPSOCKET"):
            return (
                "TLS-legacy",
                Purpose.UNKNOWN,
                "deprecated ssl.wrap_socket; predates modern TLS 1.3 negotiation",
                Confidence.HIGH,
            )
        if normalized.endswith("SSL.CREATEUNVERIFIEDCONTEXT"):
            return (
                "TLS-insecure",
                Purpose.UNKNOWN,
                "ssl._create_unverified_context disables certificate validation",
                Confidence.HIGH,
            )
        legacy_protocols = {
            "PROTOCOLSSLV2",
            "PROTOCOLSSLV3",
            "PROTOCOLTLSV1",
            "PROTOCOLTLSV11",
        }
        if tokens & legacy_protocols:
            return (
                "TLS-legacy",
                Purpose.UNKNOWN,
                "legacy TLS protocol constant selected",
                Confidence.HIGH,
            )
        if kwargs.get("check_hostname", [""])[0].lower() == "false" or "CERTNONE" in tokens:
            return (
                "TLS-insecure",
                Purpose.UNKNOWN,
                "TLS context explicitly disables certificate validation",
                Confidence.HIGH,
            )
        if normalized.endswith(("SSL.CREATEDEFAULTCONTEXT", "SSL.CONTEXT")):
            negotiated = {
                normalize_algorithm(kwargs.get("minimum_version", [""])[0]),
                normalize_algorithm(kwargs.get("maximum_version", [""])[0]),
            } & {"TLSV12", "TLSV13"}
            if negotiated:
                return (
                    "TLS",
                    Purpose.UNKNOWN,
                    "TLS context with explicit modern version negotiation",
                    Confidence.MEDIUM,
                )
            return (
                "TLS",
                Purpose.UNKNOWN,
                "TLS context creation; certificate and key-establishment details may be external",
                Confidence.LOW,
            )
        if normalized.endswith(("SETCIPHERS", "SETCIPHERSUITES")):
            if "ECDHE" in algorithm_hint:
                return (
                    "ECDH",
                    Purpose.KEY_ESTABLISHMENT,
                    "TLS cipher configuration indicates ephemeral ECDH; the concrete curve/group is not proven by the cipher suite name",
                    Confidence.MEDIUM,
                )
            if any(token in algorithm_hint for token in ("TLS_RSA", "RSA")):
                return (
                    "RSA",
                    Purpose.KEY_ESTABLISHMENT,
                    "TLS cipher configuration contains RSA key transport",
                    Confidence.HIGH,
                )
            if "X25519" in algorithm_hint:
                return (
                    "X25519",
                    Purpose.KEY_ESTABLISHMENT,
                    "TLS cipher configuration contains classical key agreement",
                    Confidence.MEDIUM,
                )
        if any(token in algorithm_hint for token in ("ML-KEM", "MLKEM")):
            return (
                "ML-KEM",
                Purpose.KEY_ESTABLISHMENT,
                "PQC key-establishment configuration",
                Confidence.HIGH,
            )
        if any(token in algorithm_hint for token in ("ML-DSA", "MLDSA")):
            return "ML-DSA", Purpose.SIGNATURE, "PQC signature configuration", Confidence.HIGH
        return None, Purpose.UNKNOWN, "", Confidence.UNKNOWN

    @staticmethod
    def _jwt_algorithm(values: list[str]) -> str:
        for value in values:
            candidate = value.strip().upper()
            if candidate.startswith(("RS", "PS", "ES", "HS")) or candidate == "EDDSA":
                return candidate
        return ""

    def _string_literals(self, node: ast.Call) -> list[str]:
        result: list[str] = []
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                result.append(arg.value)
            elif isinstance(arg, ast.Attribute):
                result.append(arg.attr)
        return result

    def _keyword_values(self, node: ast.AST) -> list[str]:
        if isinstance(node, ast.Constant):
            if isinstance(node.value, str):
                return [node.value]
            if isinstance(node.value, bool):
                return [str(node.value)]
            return []
        if isinstance(node, ast.Attribute):
            return [node.attr]
        if isinstance(node, (ast.List, ast.Tuple)):
            return _flatten([self._keyword_values(item) for item in node.elts])
        if isinstance(node, ast.Dict):
            return _flatten([self._keyword_values(value) for value in node.values])
        return []

    def _symbol_context(self, node: ast.AST, tree: ast.AST) -> str | None:
        best: str | None = None
        for parent in ast.walk(tree):
            if not isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            for child in ast.walk(parent):
                if child is node:
                    best = getattr(parent, "name", None)
                    break
        return best

    def _rule_id(self, algorithm: str, purpose: Purpose, context: AnalyzerContext) -> str:
        from ..policy import matching_rule

        rule = matching_rule(algorithm, purpose, context.rules_root)
        if rule:
            return str(rule["id"])
        return "QG-UNKNOWN-CRYPTO"

    def _rationale(self, algorithm: str, purpose: Purpose, confidence: Confidence) -> str:
        if algorithm_status(algorithm) == "insecure-config":
            return (
                f"{algorithm} is an explicitly insecure or deprecated TLS posture observed "
                f"in a {purpose.value} context; replace it before planning protocol migration."
            )
        if algorithm_status(algorithm) == "shor-vulnerable":
            return (
                f"{algorithm} is a Shor-relevant public-key primitive observed in a "
                f"{purpose.value} context with {confidence.value.lower()} evidence. "
                "The finding is a migration signal, not a claim that the current system is already compromised."
            )
        if algorithm_status(algorithm) == "pqc-standard":
            return f"{algorithm} is a standardized post-quantum candidate observed in a {purpose.value} context."
        if algorithm == "SHA-2/SHA-3":
            return "Hash use is not treated as an equivalent Shor-vulnerable public-key finding; review security level and lifecycle."
        return f"{algorithm} was observed in a {purpose.value} context; external implementation and protocol boundaries remain unknown."

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        unique: dict[str, Finding] = {}
        for finding in findings:
            unique[finding.finding_id] = finding
        return sorted(
            unique.values(),
            key=lambda item: (
                item.source_path,
                item.span.start_line,
                item.span.start_column,
                item.finding_id,
            ),
        )
