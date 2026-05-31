#!/usr/bin/env python3
import csv
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qsl, unquote_plus, urlparse


DATA_PATH = Path(__file__).resolve().parents[1] / "csic_database.csv"


@dataclass(frozen=True)
class Request:
    label: int
    method: str
    url_raw: str
    url_decoded: str
    content_raw: str
    content_decoded: str
    path_raw: str
    path_decoded: str
    query_decoded: str
    request_raw: str
    request_decoded: str
    params_decoded: dict[str, list[str]]


@dataclass(frozen=True)
class Rule:
    name: str
    field: str
    pattern: str
    flags: int = re.IGNORECASE

    def compile(self) -> re.Pattern[str]:
        return re.compile(self.pattern, self.flags)


def load_requests() -> list[Request]:
    requests: list[Request] = []
    with DATA_PATH.open(newline="", encoding="latin-1") as f:
        for row in csv.DictReader(f):
            url_raw = row["URL"].removesuffix(" HTTP/1.1")
            url_decoded = unquote_plus(url_raw)
            content_raw = row["content"]
            content_decoded = unquote_plus(content_raw)
            parsed_raw = urlparse(url_raw)
            parsed_decoded = urlparse(url_decoded)
            params: dict[str, list[str]] = {}
            for source in (parsed_decoded.query, content_decoded):
                for key, value in parse_qsl(source, keep_blank_values=True):
                    params.setdefault(key, []).append(value)
            requests.append(
                Request(
                    label=int(row["classification"]),
                    method=row["Method"],
                    url_raw=url_raw,
                    url_decoded=url_decoded,
                    content_raw=content_raw,
                    content_decoded=content_decoded,
                    path_raw=parsed_raw.path,
                    path_decoded=parsed_decoded.path,
                    query_decoded=parsed_decoded.query,
                    request_raw=f"{row['Method']} {url_raw} {content_raw}",
                    request_decoded=f"{row['Method']} {url_decoded} {content_decoded}",
                    params_decoded=params,
                )
            )
    return requests


def has_rule_match(request: Request, compiled_rules: list[tuple[Rule, re.Pattern[str]]]) -> bool:
    for rule, pattern in compiled_rules:
        if pattern.search(getattr(request, rule.field)):
            return True
    return False


def evaluate(requests: Iterable[Request], rules: list[Rule]) -> dict[str, float | int]:
    compiled = [(rule, rule.compile()) for rule in rules]
    tp = fp = tn = fn = 0
    for request in requests:
        pred = int(has_rule_match(request, compiled))
        if pred == 1 and request.label == 1:
            tp += 1
        elif pred == 1 and request.label == 0:
            fp += 1
        elif pred == 0 and request.label == 0:
            tn += 1
        else:
            fn += 1
    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    accuracy = (tp + tn) / total if total else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
    }


def matching_rule_names(request: Request, rules: list[Rule]) -> list[str]:
    names = []
    for rule in rules:
        if rule.compile().search(getattr(request, rule.field)):
            names.append(rule.name)
    return names


def print_examples(requests: list[Request], rules: list[Rule], kind: str, limit: int = 5) -> None:
    compiled = [(rule, rule.compile()) for rule in rules]
    shown = 0
    print(f"\n{kind}:")
    for request in requests:
        pred = int(has_rule_match(request, compiled))
        is_target = (kind == "false_positives" and pred == 1 and request.label == 0) or (
            kind == "false_negatives" and pred == 0 and request.label == 1
        )
        if not is_target:
            continue
        print(f"- label={request.label} method={request.method} path={request.path_decoded}")
        print(f"  rules={matching_rule_names(request, rules)}")
        print(f"  url={request.url_decoded[:220]}")
        if request.content_decoded:
            print(f"  body={request.content_decoded[:220]}")
        shown += 1
        if shown >= limit:
            break


def endpoint_value_anomaly(request: Request) -> bool:
    numeric_keys = {"id", "precio", "cantidad", "modo_pago", "cp", "ntc", "mes", "anio"}
    for key in numeric_keys:
        for value in request.params_decoded.get(key, []):
            if value and not re.fullmatch(r"[0-9]+", value):
                return True
    return False


def register_business_anomaly(request: Request) -> bool:
    if "registro.jsp" not in request.path_decoded:
        return False
    expected = {
        "modo",
        "login",
        "password",
        "nombre",
        "apellidos",
        "email",
        "dni",
        "direccion",
        "ciudad",
        "cp",
        "provincia",
        "ntc",
        "B1",
    }
    seen = set(request.params_decoded)
    return bool(seen - expected)


EXPECTED_KEYSETS = {
    "/tienda1/publico/anadir.jsp": {"id", "nombre", "precio", "cantidad", "B1"},
    "/tienda1/publico/autenticar.jsp": {"modo", "login", "pwd", "remember", "B1"},
    "/tienda1/publico/registro.jsp": {
        "modo",
        "login",
        "password",
        "nombre",
        "apellidos",
        "email",
        "dni",
        "direccion",
        "ciudad",
        "cp",
        "provincia",
        "ntc",
        "B1",
    },
    "/tienda1/miembros/editar.jsp": {
        "modo",
        "login",
        "password",
        "nombre",
        "apellidos",
        "email",
        "dni",
        "direccion",
        "ciudad",
        "cp",
        "provincia",
        "ntc",
        "B1",
    },
    "/tienda1/publico/pagar.jsp": {"modo", "precio", "B1"},
    "/tienda1/publico/caracteristicas.jsp": {"id"},
    "/tienda1/publico/vaciar.jsp": {"B2"},
    "/tienda1/publico/entrar.jsp": {"errorMsg"},
}


STATIC_PATHS = {
    "/tienda1/index.jsp",
    "/tienda1/publico/carrito.jsp",
    "/tienda1/publico/miembros.jsp",
    "/tienda1/publico/productos.jsp",
    "/tienda1/global/creditos.jsp",
    "/tienda1/global/menum.jsp",
    "/tienda1/global/titulo.jsp",
    "/tienda1/global/menu.jsp",
    "/tienda1/global/estilos.css",
    "/tienda1/miembros/index.jsp",
    "/tienda1/miembros/fotos.jsp",
    "/tienda1/miembros/salir.jsp",
    "/tienda1/imagenes/1.gif",
    "/tienda1/imagenes/2.gif",
    "/tienda1/imagenes/3.gif",
    "/tienda1/imagenes/cmenbul.gif",
    "/tienda1/imagenes/logo.gif",
    "/tienda1/imagenes/nuestratierra.jpg",
    "/tienda1/miembros/imagenes/castro.jpg",
    "/tienda1/miembros/imagenes/ogono.jpg",
    "/tienda1/miembros/imagenes/zarauz.jpg",
}


def endpoint_keyset_anomaly(request: Request) -> bool:
    expected = EXPECTED_KEYSETS.get(request.path_decoded)
    if expected is None:
        return False
    seen = set(request.params_decoded)
    return seen != expected


def unexpected_path_or_host_anomaly(request: Request) -> bool:
    if request.path_decoded in EXPECTED_KEYSETS or request.path_decoded in STATIC_PATHS:
        return False
    if re.fullmatch(r"/tienda1/(miembros|imagenes)/imagenes/[A-Za-z0-9_-]+\.(jpg|gif)", request.path_decoded):
        return False
    return bool(
        request.path_decoded in {"", "/asf-logo-wide.gif"}
        or request.path_decoded.endswith(("~", ".bak", ".old", ".conf"))
        or "WEB-INF" in request.path_decoded
        or "META-INF" in request.path_decoded
    )


def stricter_path_or_method_anomaly(request: Request) -> bool:
    if request.method == "PUT":
        return True
    if request.path_decoded in EXPECTED_KEYSETS or request.path_decoded in STATIC_PATHS:
        return False
    if re.fullmatch(r"/tienda1/(miembros|imagenes)/imagenes/[A-Za-z0-9_-]+\.(jpg|gif)", request.path_decoded):
        return False
    return True


def button_value_anomaly(request: Request) -> bool:
    for key in ("B1", "B2"):
        for value in request.params_decoded.get(key, []):
            if any(ch in value for ch in "|<>\\"):
                return True
            if value.endswith("/") or value.endswith("~"):
                return True
    return False


def put_method_anomaly(request: Request) -> bool:
    return request.method == "PUT"


def stable_value_anomaly(request: Request) -> bool:
    allowed_by_path_key = {
        ("/tienda1/publico/autenticar.jsp", "modo"): {"entrar"},
        ("/tienda1/publico/autenticar.jsp", "remember"): {"on", "off"},
        ("/tienda1/publico/autenticar.jsp", "B1"): {"Entrar"},
        ("/tienda1/publico/pagar.jsp", "modo"): {"insertar"},
        ("/tienda1/publico/pagar.jsp", "B1"): {"Pasar por caja", "Confirmar"},
        ("/tienda1/publico/registro.jsp", "modo"): {"registro"},
        ("/tienda1/publico/registro.jsp", "B1"): {"Registrar"},
        ("/tienda1/miembros/editar.jsp", "modo"): {"registro"},
        ("/tienda1/miembros/editar.jsp", "B1"): {"Registrar"},
        ("/tienda1/publico/anadir.jsp", "B1"): {"A�adir al carrito"},
        ("/tienda1/publico/vaciar.jsp", "B2"): {"Vaciar carrito"},
        ("/tienda1/publico/entrar.jsp", "errorMsg"): {"Credenciales incorrectas"},
    }
    for (path, key), allowed in allowed_by_path_key.items():
        if request.path_decoded != path:
            continue
        for value in request.params_decoded.get(key, []):
            if value not in allowed:
                return True
    return False


def product_value_anomaly(request: Request) -> bool:
    if request.path_decoded != "/tienda1/publico/anadir.jsp":
        return False
    allowed_names = {"Vino Rioja", "Queso Manchego", "Jam�n Ib�rico"}
    allowed_prices = {"39", "85", "100"}
    for name in request.params_decoded.get("nombre", []):
        if name not in allowed_names:
            return True
    for price in request.params_decoded.get("precio", []):
        if price not in allowed_prices:
            return True
    return False


def field_format_anomaly(request: Request) -> bool:
    for value in request.params_decoded.get("dni", []):
        if value and not re.fullmatch(r"\d{8}[A-Z]", value):
            return True
    return False


def strict_identity_field_anomaly(request: Request) -> bool:
    for value in request.params_decoded.get("login", []):
        if value and not re.fullmatch(r"[A-Za-z0-9_-]{2,10}", value):
            return True
    for key in ("password", "pwd"):
        for value in request.params_decoded.get(key, []):
            if value == "" or value.isspace():
                return True
    for value in request.params_decoded.get("ntc", []):
        if value and not re.fullmatch(r"\d{16}", value):
            return True
    for value in request.params_decoded.get("cp", []):
        if value and not re.fullmatch(r"\d{5}", value):
            return True
    return False


def person_name_field_anomaly(request: Request) -> bool:
    if request.path_decoded not in {
        "/tienda1/publico/registro.jsp",
        "/tienda1/miembros/editar.jsp",
    }:
        return False
    for key in ("nombre", "apellidos"):
        for value in request.params_decoded.get(key, []):
            if any(ch in value for ch in "?*,/+"):
                return True
    return False


def contact_and_location_field_anomaly(request: Request) -> bool:
    for value in request.params_decoded.get("email", []):
        if value.strip() != value or value.count("@") != 1:
            return True
    for key in ("ciudad", "provincia"):
        for value in request.params_decoded.get(key, []):
            if any(ch in value for ch in "*+?@"):
                return True
    for value in request.params_decoded.get("provincia", []):
        if "/" in value:
            return True
    return False


def credential_value_anomaly(request: Request) -> bool:
    for key in ("pwd", "password"):
        for value in request.params_decoded.get(key, []):
            if "set-cookie" in value.lower():
                return True
            if any(ch in value for ch in "/',"):
                return True
    return False


def evaluate_with_callbacks(requests: Iterable[Request], rules: list[Rule], callbacks) -> dict[str, float | int]:
    compiled = [(rule, rule.compile()) for rule in rules]
    tp = fp = tn = fn = 0
    for request in requests:
        pred = has_rule_match(request, compiled) or any(callback(request) for callback in callbacks)
        pred_i = int(pred)
        if pred_i == 1 and request.label == 1:
            tp += 1
        elif pred_i == 1 and request.label == 0:
            fp += 1
        elif pred_i == 0 and request.label == 0:
            tn += 1
        else:
            fn += 1
    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    accuracy = (tp + tn) / total if total else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
    }


ROUND_1 = [
    Rule("script_tag_or_alert", "request_decoded", r"(<\s*/?\s*script\b|alert\s*\()"),
    Rule("sql_statement_cluster", "request_decoded", r"\b(select|drop|insert|delete|update|union)\b.{0,80}\b(from|where|table|usuarios|datos|set)\b"),
    Rule("etc_passwd", "request_decoded", r"(/etc/passwd|etc/passwd)"),
    Rule("null_byte", "request_raw", r"%00"),
]

ROUND_2 = ROUND_1 + [
    Rule("sql_comment_or_tautology", "request_decoded", r"(--|#|/\*|\*/|\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|\band\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)"),
    Rule("html_injection", "request_decoded", r"(<\s*/?\s*(iframe|img|object|embed|body|html|meta|style|input|form)\b|on(error|load|click|mouseover)\s*=)"),
    Rule("path_traversal", "request_decoded", r"(\.\./|\.\.\\|%2e%2e)", flags=re.IGNORECASE),
    Rule("shell_or_pipe_chars", "request_decoded", r"(\|\s*(cat|dir|ls|type)|;\s*(cat|dir|ls|type|drop|select)\b)"),
    Rule("backup_or_temp_suffix", "path_decoded", r"(\.jsp~|\.gif~|\.bak|\.old|~)$"),
]

ROUND_3 = ROUND_2 + [
    Rule("suspicious_quote_punctuation", "request_decoded", r"['\"][\s)]*(;|--|\bor\b|\band\b)"),
    Rule("windows_or_unix_file_probe", "request_decoded", r"(boot\.ini|winnt|cmd\.exe|/bin/|/usr/|/proc/|c:\\\\)"),
    Rule("absolute_external_url_param", "request_decoded", r"=(https?|ftp)://"),
]

ROUND_4 = ROUND_3 + [
    Rule("known_invalid_resource_probe", "path_decoded", r"(^/tienda1/asf-logo-wide\.gif|^/asf-logo-wide\.gif|^/tienda1/.*\.conf$|WEB-INF|META-INF)"),
    Rule("angle_bracket_payload", "request_decoded", r"[<>]"),
    Rule("sql_function_probe", "request_decoded", r"\b(concat|benchmark|sleep|substring|char|ascii|load_file|xp_cmdshell)\s*\("),
]

ROUND_7 = ROUND_4 + [
    Rule("encoded_xss_markup", "request_raw", r"%(25)?3c\s*/?\s*(script|iframe|img|body|html|object|embed)|%(25)?3e", flags=re.IGNORECASE),
    Rule("crlf_header_injection", "request_raw", r"(%(25)?0d%(25)?0a|%(25)?0a|%(25)?0d).{0,120}(set-cookie|cookie|location|content-type|tamper)", flags=re.IGNORECASE),
    Rule("encoded_shell_or_meta_chars", "request_raw", r"(%(25)?7c|%(25)?5c|%(25)?3b|%(25)?27.{0,40}(--|%(25)?23|%(25)?20or%(25)?20|%(25)?20and%(25)?20))", flags=re.IGNORECASE),
    Rule("encoded_or_decoded_null_byte", "request_raw", r"%(25)?00", flags=re.IGNORECASE),
]

ROUND_10 = ROUND_7 + [
    Rule("regex_meta_payload", "request_decoded", r"(\.\*\?|\[\]|[{}]|\\[dDsSwW])"),
    Rule("slashy_login_or_password", "request_decoded", r"(login|pwd|password)=[^&]*(//|/\?|,'|',|'/|/')"),
    Rule("mutated_short_field_value", "request_decoded", r"(remember|modo|B1|B2|errorMsg)=[^&]*(/|\\|\||<|>|\?)"),
]


def main() -> None:
    requests = load_requests()
    rounds = [
        ("round_1_seed_obvious_attacks", ROUND_1, []),
        ("round_2_add_injection_and_path_rules", ROUND_2, []),
        ("round_3_add_encoding_and_file_probe_rules", ROUND_3, []),
        ("round_4_add_resource_and_broad_markup_rules", ROUND_4, []),
        (
            "round_5_add_endpoint_value_callbacks",
            ROUND_4,
            [endpoint_value_anomaly, register_business_anomaly],
        ),
        (
            "round_6_add_endpoint_schema_callbacks",
            ROUND_4,
            [
                endpoint_value_anomaly,
                register_business_anomaly,
                endpoint_keyset_anomaly,
                unexpected_path_or_host_anomaly,
            ],
        ),
        (
            "round_7_encoded_payloads_and_strict_paths",
            ROUND_7,
            [
                endpoint_value_anomaly,
                register_business_anomaly,
                endpoint_keyset_anomaly,
                stricter_path_or_method_anomaly,
                button_value_anomaly,
            ],
        ),
        (
            "round_8_encoded_payloads_conservative_paths",
            ROUND_7,
            [
                endpoint_value_anomaly,
                register_business_anomaly,
                endpoint_keyset_anomaly,
                unexpected_path_or_host_anomaly,
                button_value_anomaly,
                put_method_anomaly,
            ],
        ),
        (
            "round_9_full_static_whitelist_and_put",
            ROUND_7,
            [
                endpoint_value_anomaly,
                register_business_anomaly,
                endpoint_keyset_anomaly,
                stricter_path_or_method_anomaly,
                button_value_anomaly,
            ],
        ),
        (
            "round_10_value_constraints_no_asterisk",
            ROUND_10,
            [
                endpoint_value_anomaly,
                register_business_anomaly,
                endpoint_keyset_anomaly,
                stricter_path_or_method_anomaly,
                button_value_anomaly,
                stable_value_anomaly,
                product_value_anomaly,
                field_format_anomaly,
            ],
        ),
        (
            "round_11_identity_field_shapes",
            ROUND_10,
            [
                endpoint_value_anomaly,
                register_business_anomaly,
                endpoint_keyset_anomaly,
                stricter_path_or_method_anomaly,
                button_value_anomaly,
                stable_value_anomaly,
                product_value_anomaly,
                field_format_anomaly,
                strict_identity_field_anomaly,
                person_name_field_anomaly,
            ],
        ),
        (
            "round_12_contact_location_credentials",
            ROUND_10,
            [
                endpoint_value_anomaly,
                register_business_anomaly,
                endpoint_keyset_anomaly,
                stricter_path_or_method_anomaly,
                button_value_anomaly,
                stable_value_anomaly,
                product_value_anomaly,
                field_format_anomaly,
                strict_identity_field_anomaly,
                person_name_field_anomaly,
                contact_and_location_field_anomaly,
                credential_value_anomaly,
            ],
        ),
    ]
    print(f"dataset={DATA_PATH}")
    print(f"rows={len(requests)} positives={sum(r.label for r in requests)} negatives={sum(1-r.label for r in requests)}")
    for name, rules, callbacks in rounds:
        metrics = evaluate_with_callbacks(requests, rules, callbacks)
        print(
            f"{name}: "
            f"accuracy={metrics['accuracy']:.4f} precision={metrics['precision']:.4f} "
            f"recall={metrics['recall']:.4f} f1={metrics['f1']:.4f} "
            f"tp={metrics['tp']} fp={metrics['fp']} tn={metrics['tn']} fn={metrics['fn']} "
            f"regex_rules={len(rules)} callbacks={len(callbacks)}"
        )
    print_examples(requests, ROUND_4, "false_positives")
    print_examples(requests, ROUND_4, "false_negatives")


if __name__ == "__main__":
    main()
