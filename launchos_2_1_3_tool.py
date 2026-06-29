#!/usr/bin/env python3
"""
LaunchOS 2.1.3(362) patch + 本地注册机一体脚本。

用法：
  只 patch App：
    python3 launchos_2_1_3_tool.py patch

  只启动本地注册机服务：
    python3 launchos_2_1_3_tool.py serve

  先 patch，再启动本地注册机服务：
    python3 launchos_2_1_3_tool.py all
"""

import argparse
import base64
import json
import os
import shutil
import socketserver
import subprocess
import tempfile
import time
import uuid
from http.server import BaseHTTPRequestHandler
from pathlib import Path


# =========================
# 通用路径配置
# =========================

ROOT = Path(__file__).resolve().parent
WORK = ROOT / "launchos_keygen_work"
PRIVATE_KEY = WORK / "private.pem"
KEYGEN_PUBLIC_KEY = WORK / "public.pem"

APP = Path("/Applications/LaunchOS.app")
BIN = APP / "Contents/MacOS/LaunchOS"
INFO = APP / "Contents/Info.plist"

# App 用这个公钥验证服务端返回的 JWT。
# 注册机用 PRIVATE_KEY 签 JWT，所以这里必须把 App 内置 public.pem
# 替换成和 PRIVATE_KEY 配套的 KEYGEN_PUBLIC_KEY。
APP_PUBLIC_KEY = APP / "Contents/Resources/public.pem"

EXPECTED_VERSION = "2.1.3"
EXPECTED_BUILD = "362"


# =========================
# patch 配置
# =========================

# arm64 slice 信息来自：
#   otool -f /Applications/LaunchOS.app/Contents/MacOS/LaunchOS
# 2.1.3(362) arm64 slice offset = 0x60c000。
ARM64_SLICE_OFFSET = 0x60C000
ARM64_VM_BASE = 0x100000000

# 响应签名校验失败分支位置。
# 反汇编附近：
#   0x100063058  bl  stringCompareWithSmolCheck
#   0x10006305c  mov x20, x0
#   0x100063068  tbz w20, #0x0, 0x10006307c
#   0x10006307c  ... "network error: si "
SIGCHECK_VA = 0x100063068
SIGCHECK_FILE_OFFSET = ARM64_SLICE_OFFSET + (SIGCHECK_VA - ARM64_VM_BASE)

# arm64 指令：
#   b4000036 = tbz w20, #0, <fail_branch>
#   1f2003d5 = nop
TBZ_BYTES = bytes.fromhex("b4000036")
NOP_BYTES = bytes.fromhex("1f2003d5")

# API 字符串替换必须保持长度一致，避免破坏 Mach-O 字符串布局。
REPLACEMENTS = [
    (b"https://api.remixdesign.app/", b"http://127.000.000.001:8765/"),
    (b"https://api.remixdesign.site/", b"http://127.000.000.001:8765//"),
]


# =========================
# 注册机服务配置
# =========================

HOST = "127.0.0.1"
PORT = 8765
SUCCESS_CODE = 1000


def run(cmd: list[str]) -> None:
    print("+", " ".join(cmd))
    subprocess.check_call(cmd)


def plist_value(key: str) -> str:
    return subprocess.check_output(
        ["/usr/libexec/PlistBuddy", "-c", f"Print :{key}", str(INFO)],
        text=True,
    ).strip()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def der_to_raw_p1363(der: bytes) -> bytes:
    """openssl 输出 DER ECDSA 签名；JWT ES256 需要 r||s 原始 64 字节。"""
    if len(der) < 8 or der[0] != 0x30:
        raise ValueError("not an ECDSA DER sequence")

    pos = 2
    if der[1] & 0x80:
        n = der[1] & 0x7F
        pos = 2 + n

    if der[pos] != 0x02:
        raise ValueError("bad r")
    r_len = der[pos + 1]
    r = der[pos + 2 : pos + 2 + r_len]
    pos += 2 + r_len

    if der[pos] != 0x02:
        raise ValueError("bad s")
    s_len = der[pos + 1]
    s = der[pos + 2 : pos + 2 + s_len]

    return r.lstrip(b"\x00").rjust(32, b"\x00") + s.lstrip(b"\x00").rjust(32, b"\x00")


def sign_es256(message: bytes) -> bytes:
    """使用 private.pem 对 JWT signing input 做 ES256 签名。"""
    with tempfile.NamedTemporaryFile(delete=False) as inp:
        inp.write(message)
        inp_path = inp.name

    try:
        der = subprocess.check_output(
            ["openssl", "dgst", "-sha256", "-sign", str(PRIVATE_KEY), inp_path]
        )
        return der_to_raw_p1363(der)
    finally:
        try:
            os.unlink(inp_path)
        except FileNotFoundError:
            pass


def make_token(req: dict) -> str:
    """为任意邮箱/许可证生成 LaunchOS 可接受的 Pro JWT。"""
    now = int(time.time())
    email = str(req.get("email") or "keygen@example.com")
    license_key = str(req.get("key") or req.get("license") or req.get("licenseKey") or "KEYGEN")
    fingerprint = str(req.get("fingerprint") or "")
    machine_id = str(req.get("machineId") or fingerprint or str(uuid.uuid4()))

    header = {"alg": "ES256", "typ": "JWT"}
    payload = {
        "product": "LaunchOS",
        "tokenVersion": 1,
        "fingerprint": fingerprint,
        "tier": "pro",
        "buildVersion": str(req.get("buildVersion") or EXPECTED_BUILD),
        "trialStartedAt": 0,
        "licenseId": "KG-" + uuid.uuid5(uuid.NAMESPACE_DNS, email + "|" + license_key).hex[:16],
        "machineId": machine_id,
        "iss": "remixdesign.launchos",
        "aud": ["launchos-macos"],
        "iat": now,
        "exp": now + 10 * 365 * 24 * 3600,
    }

    signing_input = (
        b64url(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + b64url(json.dumps(payload, separators=(",", ":")).encode())
    ).encode()

    return signing_input.decode() + "." + b64url(sign_es256(signing_input))


def decode_payload_for_log(token: str) -> dict:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload.encode()))
    except Exception as exc:
        return {"decode_error": str(exc)}


class LicenseHandler(BaseHTTPRequestHandler):
    def _read_json(self) -> dict:
        length = int(self.headers.get("content-length") or "0")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(raw.decode() or "{}")
        except Exception:
            return {}

    def _send_json(self, obj: dict, status: int = 200) -> None:
        data = json.dumps(obj, separators=(",", ":")).encode()

        # 响应签名校验已经在 App 里 NOP 掉；这里保留占位头，避免缺头导致解析分支异常。
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.send_header("timestamp", str(int(time.time())))
        self.send_header("nonce", str(uuid.uuid4()).upper())
        self.send_header("signature", "patched")
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        req = self._read_json()
        print(f"POST {self.path} body={json.dumps(req, ensure_ascii=False)}")

        if "deactivate" in self.path:
            self._send_json({"message": "", "code": SUCCESS_CODE, "data": {"ok": True}, "ok": True})
            return

        token = make_token(req)
        print(
            "RESP "
            + json.dumps(
                {"code": SUCCESS_CODE, "token_payload": decode_payload_for_log(token)},
                ensure_ascii=False,
            )
        )
        self._send_json({"message": "", "code": SUCCESS_CODE, "data": {"token": token}, "token": token})

    def do_GET(self) -> None:
        if "machines" in self.path:
            data = {"maxMachineCount": 999, "activatedMachines": []}
            self._send_json({"message": "", "code": SUCCESS_CODE, "data": data, **data})
        else:
            self._send_json({"message": "", "code": SUCCESS_CODE, "data": {"ok": True}, "ok": True})

    def log_message(self, fmt: str, *args) -> None:
        print("[%s] %s" % (self.log_date_time_string(), fmt % args))


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


def patch_binary() -> None:
    data = bytearray(BIN.read_bytes())

    for old, new in REPLACEMENTS:
        if len(old) != len(new):
            raise SystemExit(f"replacement length mismatch: {old!r} -> {new!r}")

        old_count = data.count(old)
        new_count = data.count(new)
        print(f"{old.decode()} old_count={old_count} patched_count={new_count}")

        if old_count:
            data = bytearray(bytes(data).replace(old, new))

    current = bytes(data[SIGCHECK_FILE_OFFSET : SIGCHECK_FILE_OFFSET + 4])
    print(f"sigcheck offset={SIGCHECK_FILE_OFFSET:#x} bytes={current.hex()}")

    if current == TBZ_BYTES:
        data[SIGCHECK_FILE_OFFSET : SIGCHECK_FILE_OFFSET + 4] = NOP_BYTES
        print(f"sigcheck patched -> {NOP_BYTES.hex()}")
    elif current == NOP_BYTES:
        print("sigcheck already patched")
    else:
        raise SystemExit(f"unexpected bytes at {SIGCHECK_FILE_OFFSET:#x}: {current.hex()}")

    BIN.write_bytes(data)


def replace_public_key() -> None:
    shutil.copyfile(KEYGEN_PUBLIC_KEY, APP_PUBLIC_KEY)
    print(f"public.pem replaced: {APP_PUBLIC_KEY}")


def patch_app() -> None:
    if not APP.exists():
        raise SystemExit(f"missing app: {APP}")
    if not BIN.exists():
        raise SystemExit(f"missing binary: {BIN}")
    if not KEYGEN_PUBLIC_KEY.exists():
        raise SystemExit(f"missing keygen public key: {KEYGEN_PUBLIC_KEY}")

    version = plist_value("CFBundleShortVersionString")
    build = plist_value("CFBundleVersion")
    print(f"LaunchOS version: {version} ({build})")

    # offset 是 2.1.3(362) 专用的，版本不一致就退出。
    if (version, build) != (EXPECTED_VERSION, EXPECTED_BUILD):
        raise SystemExit(
            f"unsupported version: {version} ({build}); "
            f"expected {EXPECTED_VERSION} ({EXPECTED_BUILD})"
        )

    patch_binary()
    replace_public_key()
    run(["xattr", "-cr", str(APP)])
    run(["codesign", "--force", "--deep", "--sign", "-", str(APP)])
    print("patch done")


def serve() -> None:
    if not PRIVATE_KEY.exists():
        raise SystemExit(f"missing private key: {PRIVATE_KEY}")

    with ReusableTCPServer((HOST, PORT), LicenseHandler) as httpd:
        print(f"LaunchOS keygen server listening on http://{HOST}:{PORT}")
        httpd.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="LaunchOS 2.1.3 patch + keygen tool")
    parser.add_argument(
        "command",
        choices=["patch", "serve", "all"],
        help="patch=只 patch App；serve=只启动注册机；all=patch 后启动注册机",
    )
    args = parser.parse_args()

    if args.command in {"patch", "all"}:
        patch_app()
    if args.command in {"serve", "all"}:
        serve()


if __name__ == "__main__":
    main()
