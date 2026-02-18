"""
XRPL Wallet Manager
====================
Requirements: pip install xrpl-py cryptography

Features:
- Password-protected encrypted local wallet file
- Multiple wallets (add / switch / delete)
- Dashboard: XRP balance, correct reserve calc, token names via xrplmeta
- Send XRP
- Manage trust lines (with token name lookup)
- Transaction history (fixed parsing)
- Sortable columns on all tables
"""

import tkinter as tk
from tkinter import ttk, messagebox
import json, os, threading, base64, urllib.request, urllib.error

# ── Colours (dark theme) ─────────────────────────────────────────────────────
BG      = "#1e1e2e"
BG2     = "#2a2a3e"
BG3     = "#313145"
ACCENT  = "#7c6af7"
ACCENT2 = "#5a4fcf"
FG      = "#cdd6f4"
FG2     = "#a6adc8"
GREEN   = "#a6e3a1"
RED     = "#f38ba8"
YELLOW  = "#f9e2af"
BORDER  = "#45475a"

# ── Encryption ───────────────────────────────────────────────────────────────
def _derive_key(password: str, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480_000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_data(data: dict, password: str) -> bytes:
    from cryptography.fernet import Fernet
    salt  = os.urandom(16)
    token = Fernet(_derive_key(password, salt)).encrypt(json.dumps(data).encode())
    return salt + token

def decrypt_data(raw: bytes, password: str) -> dict:
    from cryptography.fernet import Fernet, InvalidToken
    salt, token = raw[:16], raw[16:]
    try:
        return json.loads(Fernet(_derive_key(password, salt)).decrypt(token).decode())
    except InvalidToken:
        raise ValueError("Wrong password or corrupt file.")

WALLET_FILE = os.path.join(os.path.expanduser("~"), ".xrpl_wallets.enc")

def load_wallets(password: str) -> dict:
    if not os.path.exists(WALLET_FILE):
        return {"wallets": []}
    with open(WALLET_FILE, "rb") as fh:
        return decrypt_data(fh.read(), password)

def save_wallets(data: dict, password: str):
    with open(WALLET_FILE, "wb") as fh:
        fh.write(encrypt_data(data, password))

# ── Token name cache & lookup ─────────────────────────────────────────────────
_token_cache: dict = {}   # "CURRENCY.ISSUER" -> display name

def _hex_to_ascii(hex_str: str) -> str:
    """Convert 40-char hex currency codes to readable ASCII."""
    if len(hex_str) == 40:
        try:
            return bytes.fromhex(hex_str).decode("ascii").rstrip("\x00")
        except Exception:
            pass
    return hex_str

def resolve_token_name(currency: str, issuer: str) -> str:
    """
    Returns a human-readable token name.
    Tries xrplmeta first, falls back to xrpscan, then raw currency code.
    Results are cached in memory.
    """
    raw = _hex_to_ascii(currency)
    key = f"{currency}.{issuer}"
    if key in _token_cache:
        return _token_cache[key]

    # 1) xrplmeta  (CURRENCY:ISSUER)
    try:
        url = f"https://s1.xrplmeta.org/token/{raw}:{issuer}"
        req = urllib.request.Request(url, headers={"User-Agent": "xrpl-wallet-manager/1.0"})
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read())
        name = (data.get("meta", {}).get("token", {}).get("name") or
                data.get("name") or raw)
        _token_cache[key] = f"{name} ({raw})"
        return _token_cache[key]
    except Exception:
        pass

    # 2) xrpscan  (CURRENCY.ISSUER)
    try:
        url = f"https://api.xrpscan.com/api/v1/token/{raw}.{issuer}"
        req = urllib.request.Request(url, headers={"User-Agent": "xrpl-wallet-manager/1.0"})
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read())
        name = (data.get("meta", {}).get("token", {}).get("name") or
                data.get("name") or data.get("code") or raw)
        _token_cache[key] = f"{name} ({raw})"
        return _token_cache[key]
    except Exception:
        pass

    _token_cache[key] = raw
    return raw

# ── XRPL helpers ─────────────────────────────────────────────────────────────
MAINNET_HTTP = "https://xrplcluster.com"

def _client():
    import xrpl
    return xrpl.clients.JsonRpcClient(MAINNET_HTTP)

def xrpl_get_account_info(address: str) -> dict:
    import xrpl
    return _client().request(
        xrpl.models.requests.AccountInfo(account=address,
                                          ledger_index="validated")).result

def xrpl_get_transactions(address: str, limit: int = 25) -> list:
    import xrpl
    return _client().request(
        xrpl.models.requests.AccountTx(account=address, limit=limit)
    ).result.get("transactions", [])

def xrpl_get_trust_lines(address: str) -> list:
    import xrpl
    return _client().request(
        xrpl.models.requests.AccountLines(account=address)
    ).result.get("lines", [])

def xrpl_send_xrp(seed: str, destination: str, amount_xrp: float,
                   memo: str = "") -> dict:
    import xrpl
    from xrpl.models.transactions import Payment
    from xrpl.models.transactions.transaction import Memo, MemoWrapper
    from xrpl.utils import xrp_to_drops
    from xrpl.transaction import submit_and_wait
    wallet = xrpl.wallet.Wallet.from_seed(seed)
    memos = ([MemoWrapper(memo=Memo(memo_data=memo.encode().hex().upper()))]
             if memo else None)
    tx = Payment(account=wallet.address, destination=destination,
                 amount=xrp_to_drops(amount_xrp), memos=memos)
    return submit_and_wait(tx, _client(), wallet).result

def xrpl_set_trust_line(seed: str, currency: str, issuer: str,
                         limit: float) -> dict:
    import xrpl
    from xrpl.models.transactions import TrustSet
    from xrpl.models.amounts import IssuedCurrencyAmount
    from xrpl.transaction import submit_and_wait
    wallet = xrpl.wallet.Wallet.from_seed(seed)
    tx = TrustSet(
        account=wallet.address,
        limit_amount=IssuedCurrencyAmount(
            currency=currency, issuer=issuer, value=str(int(limit))))
    return submit_and_wait(tx, _client(), wallet).result

def seed_to_address(seed: str) -> str:
    import xrpl
    return xrpl.wallet.Wallet.from_seed(seed).address

# ── Reserve calculation ───────────────────────────────────────────────────────
BASE_RESERVE  = 1.0   # XRP  (current mainnet value as of 2024 amendment)
OWNER_RESERVE = 0.2   # XRP per owner object / trust line

def calc_reserve(owner_count: int) -> float:
    return BASE_RESERVE + owner_count * OWNER_RESERVE

# ── Sortable Treeview ─────────────────────────────────────────────────────────
class SortableTree(ttk.Treeview):
    """Treeview with click-to-sort on any column header."""

    def __init__(self, parent, columns: list, **kw):
        col_ids = [c[0] for c in columns]
        super().__init__(parent, columns=col_ids, show="headings", **kw)
        self._sort_reverse = {c[0]: False for c in columns}

        for col_id, header, width, anchor in columns:
            self.heading(col_id, text=header,
                         command=lambda c=col_id: self._sort_by(c))
            self.column(col_id, width=width, anchor=anchor)

    def _sort_by(self, col: str):
        data = [(self.set(k, col), k) for k in self.get_children("")]
        try:
            data.sort(key=lambda t: float(t[0].replace(",", "").split()[0]),
                      reverse=self._sort_reverse[col])
        except (ValueError, IndexError):
            data.sort(key=lambda t: t[0].lower(),
                      reverse=self._sort_reverse[col])
        for idx, (_, k) in enumerate(data):
            self.move(k, "", idx)
        self._sort_reverse[col] = not self._sort_reverse[col]
        # Refresh all headers, add arrow to active column
        for c in self["columns"]:
            self.heading(c, text=self.heading(c)["text"].rstrip(" ▲▼"))
        arrow = " ▲" if not self._sort_reverse[col] else " ▼"
        self.heading(col, text=self.heading(col)["text"] + arrow)

# ── Widget helpers ────────────────────────────────────────────────────────────
def styled_btn(parent, text, command, color=ACCENT, fg=FG, width=None, **kw):
    cfg = dict(bg=color, fg=fg, font=("Segoe UI", 10, "bold"),
               relief="flat", cursor="hand2", padx=12, pady=6,
               activebackground=ACCENT2, activeforeground=FG, bd=0)
    if width:
        cfg["width"] = width
    return tk.Button(parent, text=text, command=command, **cfg, **kw)

def styled_entry(parent, show=None, width=40):
    e = tk.Entry(parent, bg=BG3, fg=FG, insertbackground=FG,
                 relief="flat", font=("Segoe UI", 10),
                 highlightthickness=1, highlightbackground=BORDER,
                 highlightcolor=ACCENT, width=width)
    if show:
        e.config(show=show)
    return e

def section_frame(parent):
    return tk.Frame(parent, bg=BG2, relief="flat",
                    highlightthickness=1, highlightbackground=BORDER)

def _style_tree(tree):
    s = ttk.Style()
    name = f"T{id(tree)}.Treeview"
    s.configure(name, background=BG3, foreground=FG, fieldbackground=BG3,
                font=("Segoe UI", 9), rowheight=26, borderwidth=0)
    s.configure(name + ".Heading", background=BG2, foreground=FG2,
                font=("Segoe UI", 9, "bold"), relief="flat")
    s.map(name, background=[("selected", ACCENT)],
               foreground=[("selected", "#fff")])
    tree.configure(style=name)

def _scrolled_tree(parent, columns, height=8) -> SortableTree:
    frm = tk.Frame(parent, bg=BG)
    frm.pack(fill="both", expand=True, padx=16, pady=(0, 8))
    tree = SortableTree(frm, columns, height=height)
    _style_tree(tree)
    sb = ttk.Scrollbar(frm, orient="vertical", command=tree.yview)
    tree.configure(yscroll=sb.set)
    tree.pack(side="left", fill="both", expand=True)
    sb.pack(side="right", fill="y")
    return tree

# ── Login dialog ──────────────────────────────────────────────────────────────
class LoginDialog(tk.Toplevel):
    def __init__(self, parent, first_time=False):
        super().__init__(parent)
        self.result = None
        self.title("XRPL Wallet Manager – Login")
        self.resizable(False, False)
        self.configure(bg=BG)
        self.grab_set()
        pad = dict(padx=20, pady=8)

        tk.Label(self, text="🔐  XRPL Wallet Manager",
                 bg=BG, fg=ACCENT, font=("Segoe UI", 14, "bold")).pack(pady=(20, 4))
        tk.Label(self,
                 text="Create a master password:" if first_time
                      else "Enter your master password:",
                 bg=BG, fg=FG2, font=("Segoe UI", 10)).pack(**pad)

        self.pw_var = tk.StringVar()
        pw_e = styled_entry(self, show="•", width=30)
        pw_e.config(textvariable=self.pw_var)
        pw_e.pack(**pad)
        pw_e.focus()

        if first_time:
            tk.Label(self, text="Confirm password:", bg=BG, fg=FG2,
                     font=("Segoe UI", 10)).pack(**pad)
            self.pw2_var = tk.StringVar()
            pw2_e = styled_entry(self, show="•", width=30)
            pw2_e.config(textvariable=self.pw2_var)
            pw2_e.pack(**pad)
            pw2_e.bind("<Return>", lambda _: self._submit(first_time))
        else:
            pw_e.bind("<Return>", lambda _: self._submit(first_time))

        styled_btn(self, "Continue",
                   lambda: self._submit(first_time), width=20).pack(pady=(8, 20))
        self.first_time = first_time

    def _submit(self, first_time):
        pw = self.pw_var.get()
        if not pw:
            messagebox.showerror("Error", "Password cannot be empty.", parent=self)
            return
        if first_time and pw != self.pw2_var.get():
            messagebox.showerror("Error", "Passwords do not match.", parent=self)
            return
        self.result = pw
        self.destroy()

# ── Add Wallet dialog ─────────────────────────────────────────────────────────
class AddWalletDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.result = None
        self.title("Add Wallet")
        self.resizable(False, False)
        self.configure(bg=BG)
        self.grab_set()
        pad = dict(padx=20, pady=6)

        tk.Label(self, text="➕  Add Wallet", bg=BG, fg=ACCENT,
                 font=("Segoe UI", 13, "bold")).pack(pady=(16, 4))

        name_var = tk.StringVar()
        seed_var = tk.StringVar()
        self.name_var = name_var
        self.seed_var = seed_var

        for label, var, show in [("Label / name:", name_var, None),
                                   ("Seed (sXXXX… or mXXXX…):", seed_var, "•")]:
            tk.Label(self, text=label, bg=BG, fg=FG2,
                     font=("Segoe UI", 10)).pack(**pad)
            e = styled_entry(self, show=show, width=34)
            e.config(textvariable=var)
            e.pack(**pad)
            if not show:
                e.focus()

        styled_btn(self, "Add Wallet", self._submit, width=18).pack(pady=(10, 16))

    def _submit(self):
        name = self.name_var.get().strip()
        seed = self.seed_var.get().strip()
        if not name or not seed:
            messagebox.showerror("Error", "Please fill in all fields.", parent=self)
            return
        try:
            address = seed_to_address(seed)
        except Exception as ex:
            messagebox.showerror("Invalid Seed",
                                  f"Could not derive address:\n{ex}", parent=self)
            return
        self.result = {"name": name, "seed": seed, "address": address}
        self.destroy()

# ── Main Application ──────────────────────────────────────────────────────────
class XRPLApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("XRPL Wallet Manager")
        self.configure(bg=BG)
        self.geometry("1040x700")
        self.minsize(880, 560)

        self.password    = None
        self.wallet_data = {"wallets": []}
        self.active_idx  = None

        self._check_deps()
        self._login()
        if not self.password:
            self.destroy()
            return
        self._build_ui()
        self._refresh_wallet_list()

    # ── deps ──────────────────────────────────────────────────────────────────
    def _check_deps(self):
        missing = []
        for pkg, install in [("xrpl", "xrpl-py"),
                              ("cryptography", "cryptography")]:
            try:
                __import__(pkg)
            except ImportError:
                missing.append(f"  pip install {install}")
        if missing:
            messagebox.showerror(
                "Missing packages",
                "Please install the following and restart:\n\n" + "\n".join(missing))
            self.destroy()
            raise SystemExit

    # ── login ─────────────────────────────────────────────────────────────────
    def _login(self):
        first_time = not os.path.exists(WALLET_FILE)
        dlg = LoginDialog(self, first_time=first_time)
        self.wait_window(dlg)
        if not dlg.result:
            return
        if first_time:
            self.password = dlg.result
            save_wallets(self.wallet_data, self.password)
        else:
            try:
                self.wallet_data = load_wallets(dlg.result)
                self.password = dlg.result
            except ValueError as e:
                messagebox.showerror("Login failed", str(e))

    # ── UI ────────────────────────────────────────────────────────────────────
    def _build_ui(self):
        # Sidebar
        self.sidebar = tk.Frame(self, bg=BG2, width=215)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        tk.Label(self.sidebar, text="💜  XRPL Manager",
                 bg=BG2, fg=ACCENT, font=("Segoe UI", 12, "bold"),
                 pady=16).pack(fill="x")
        tk.Label(self.sidebar, text="WALLETS", bg=BG2, fg=FG2,
                 font=("Segoe UI", 8, "bold"), padx=12).pack(anchor="w")

        lf = tk.Frame(self.sidebar, bg=BG2)
        lf.pack(fill="both", expand=True, padx=6, pady=4)
        self.wallet_lb = tk.Listbox(
            lf, bg=BG3, fg=FG, selectbackground=ACCENT, selectforeground="#fff",
            font=("Segoe UI", 10), relief="flat", bd=0,
            highlightthickness=0, activestyle="none")
        self.wallet_lb.pack(fill="both", expand=True)
        self.wallet_lb.bind("<<ListboxSelect>>", self._on_wallet_select)

        br = tk.Frame(self.sidebar, bg=BG2)
        br.pack(fill="x", padx=6, pady=4)
        styled_btn(br, "＋  Add",    self._add_wallet,    width=8).pack(side="left", padx=2)
        styled_btn(br, "✕  Delete", self._remove_wallet,
                   color=RED, fg="#fff", width=8).pack(side="left", padx=2)

        # Content
        self.content = tk.Frame(self, bg=BG)
        self.content.pack(side="right", fill="both", expand=True)

        # Top bar
        top = tk.Frame(self.content, bg=BG2, height=48)
        top.pack(fill="x")
        top.pack_propagate(False)
        self.wallet_title = tk.Label(
            top, text="Select a wallet →",
            bg=BG2, fg=FG, font=("Segoe UI", 12, "bold"), padx=16)
        self.wallet_title.pack(side="left", pady=12)
        self.addr_lbl = tk.Label(top, text="", bg=BG2, fg=FG2,
                                  font=("Segoe UI", 9), padx=4)
        self.addr_lbl.pack(side="left", pady=12)
        styled_btn(top, "🔄  Refresh", self._refresh_data,
                   width=12).pack(side="right", padx=12, pady=8)

        # Notebook
        s = ttk.Style()
        s.theme_use("default")
        s.configure("Dark.TNotebook", background=BG, borderwidth=0)
        s.configure("Dark.TNotebook.Tab", background=BG3, foreground=FG2,
                     padding=[14, 6], font=("Segoe UI", 10))
        s.map("Dark.TNotebook.Tab",
              background=[("selected", ACCENT)],
              foreground=[("selected", "#fff")])

        self.nb = ttk.Notebook(self.content, style="Dark.TNotebook")
        self.nb.pack(fill="both", expand=True, padx=8, pady=8)

        self._build_dashboard_tab()
        self._build_send_tab()
        self._build_trustlines_tab()
        self._build_tx_tab()

    # ── Tab: Dashboard ────────────────────────────────────────────────────────
    def _build_dashboard_tab(self):
        tab = tk.Frame(self.nb, bg=BG)
        self.nb.add(tab, text="📊  Dashboard")

        top_row = tk.Frame(tab, bg=BG)
        top_row.pack(fill="x", padx=16, pady=(16, 8))

        # Balance card
        bal_f = section_frame(top_row)
        bal_f.pack(side="left", fill="both", expand=True, padx=(0, 8))
        tk.Label(bal_f, text="XRP Balance", bg=BG2, fg=FG2,
                 font=("Segoe UI", 9)).pack(anchor="w", padx=14, pady=(10, 0))
        self.bal_lbl = tk.Label(bal_f, text="—", bg=BG2, fg=GREEN,
                                 font=("Segoe UI", 28, "bold"), padx=14, pady=8)
        self.bal_lbl.pack(anchor="w")

        # Info card
        info_f = section_frame(top_row)
        info_f.pack(side="left", fill="both", expand=True)
        for label, attr in [("Sequence",       "seq_lbl"),
                             ("Reserve (XRP)",  "res_lbl"),
                             ("Owner objects",  "own_lbl")]:
            r = tk.Frame(info_f, bg=BG2)
            r.pack(fill="x", padx=14, pady=5)
            tk.Label(r, text=label + ":", bg=BG2, fg=FG2,
                     font=("Segoe UI", 9), width=16, anchor="w").pack(side="left")
            lbl = tk.Label(r, text="—", bg=BG2, fg=FG,
                           font=("Segoe UI", 10, "bold"))
            lbl.pack(side="left")
            setattr(self, attr, lbl)

        # Reserve legend
        legend = tk.Label(
            tab,
            text=f"Reserve = {BASE_RESERVE} XRP (base) + owner objects × {OWNER_RESERVE} XRP",
            bg=BG, fg=FG2, font=("Segoe UI", 8), padx=16)
        legend.pack(anchor="w", pady=(0, 4))

        # Token table  (sortable)
        tk.Label(tab, text="Token / IOU Balances  — click a column header to sort",
                 bg=BG, fg=FG2, font=("Segoe UI", 9, "bold"),
                 padx=16).pack(anchor="w", pady=(4, 2))

        token_cols = [
            ("name",    "Token Name",  250, "w"),
            ("balance", "Balance",     150, "e"),
            ("limit",   "Limit",       150, "e"),
            ("issuer",  "Issuer",      300, "w"),
        ]
        self.token_tree = _scrolled_tree(tab, token_cols, height=9)

    # ── Tab: Send XRP ─────────────────────────────────────────────────────────
    def _build_send_tab(self):
        tab = tk.Frame(self.nb, bg=BG)
        self.nb.add(tab, text="💸  Send XRP")

        frm = section_frame(tab)
        frm.pack(padx=32, pady=24, anchor="n", fill="x")

        tk.Label(frm, text="Send XRP", bg=BG2, fg=ACCENT,
                 font=("Segoe UI", 13, "bold"), padx=20, pady=12).pack(anchor="w")

        for label, attr in [
            ("Destination address:", "send_dest_entry"),
            ("Amount (XRP):",        "send_amt_entry"),
            ("Memo (optional):",     "send_memo_entry"),
        ]:
            r = tk.Frame(frm, bg=BG2)
            r.pack(fill="x", padx=20, pady=6)
            tk.Label(r, text=label, bg=BG2, fg=FG2,
                     font=("Segoe UI", 10), width=22, anchor="w").pack(side="left")
            e = styled_entry(r, width=46)
            e.pack(side="left")
            setattr(self, attr, e)

        br = tk.Frame(frm, bg=BG2)
        br.pack(padx=20, pady=(8, 16), anchor="w")
        styled_btn(br, "✈  Send", self._do_send, width=14).pack(side="left")
        self.send_status = tk.Label(br, text="", bg=BG2, fg=GREEN,
                                     font=("Segoe UI", 10), padx=12)
        self.send_status.pack(side="left")

    # ── Tab: Trust Lines ──────────────────────────────────────────────────────
    def _build_trustlines_tab(self):
        tab = tk.Frame(self.nb, bg=BG)
        self.nb.add(tab, text="🔗  Trust Lines")

        tk.Label(tab, text="Existing Trust Lines  — click a column header to sort",
                 bg=BG, fg=FG2, font=("Segoe UI", 9, "bold"),
                 padx=16).pack(anchor="w", pady=(12, 2))

        tl_cols = [
            ("name",    "Token Name",  250, "w"),
            ("balance", "Balance",     150, "e"),
            ("limit",   "Limit",       150, "e"),
            ("issuer",  "Issuer",      300, "w"),
        ]
        self.tl_tree = _scrolled_tree(tab, tl_cols, height=7)

        # Form
        frm2 = section_frame(tab)
        frm2.pack(padx=16, pady=8, fill="x")
        tk.Label(frm2, text="Set / Update Trust Line", bg=BG2, fg=ACCENT,
                 font=("Segoe UI", 12, "bold"), padx=16, pady=8).pack(anchor="w")

        for label, attr in [
            ("Currency code (e.g. USD):", "tl_currency_entry"),
            ("Issuer address:",            "tl_issuer_entry"),
            ("Limit amount:",              "tl_limit_entry"),
        ]:
            r = tk.Frame(frm2, bg=BG2)
            r.pack(fill="x", padx=16, pady=4)
            tk.Label(r, text=label, bg=BG2, fg=FG2,
                     font=("Segoe UI", 10), width=24, anchor="w").pack(side="left")
            e = styled_entry(r, width=46)
            e.pack(side="left")
            setattr(self, attr, e)

        br = tk.Frame(frm2, bg=BG2)
        br.pack(padx=16, pady=(6, 14), anchor="w")
        styled_btn(br, "✔  Set Trust Line",
                   self._do_trust_line, width=18).pack(side="left")
        self.tl_status = tk.Label(br, text="", bg=BG2, fg=GREEN,
                                   font=("Segoe UI", 10), padx=12)
        self.tl_status.pack(side="left")

    # ── Tab: Transactions ─────────────────────────────────────────────────────
    def _build_tx_tab(self):
        tab = tk.Frame(self.nb, bg=BG)
        self.nb.add(tab, text="📜  Transactions")

        tk.Label(tab,
                 text="Recent Transactions  — click a column header to sort"
                      "  |  Green = incoming   Yellow = outgoing",
                 bg=BG, fg=FG2, font=("Segoe UI", 9, "bold"),
                 padx=16).pack(anchor="w", pady=(12, 2))

        tx_cols = [
            ("ledger",      "Ledger",        80, "e"),
            ("type",        "Type",         120, "w"),
            ("amount",      "Amount",       120, "e"),
            ("fee",         "Fee (XRP)",     80, "e"),
            ("account",     "From",         170, "w"),
            ("destination", "To",           170, "w"),
            ("result",      "Status",        90, "w"),
        ]
        self.tx_tree = _scrolled_tree(tab, tx_cols, height=22)

    # ── Wallet list ───────────────────────────────────────────────────────────
    def _refresh_wallet_list(self):
        self.wallet_lb.delete(0, "end")
        for w in self.wallet_data["wallets"]:
            self.wallet_lb.insert("end", f"  {w['name']}")
        if (self.active_idx is not None and
                self.active_idx < len(self.wallet_data["wallets"])):
            self.wallet_lb.selection_set(self.active_idx)

    def _on_wallet_select(self, _=None):
        sel = self.wallet_lb.curselection()
        if not sel:
            return
        self.active_idx = sel[0]
        w = self.wallet_data["wallets"][self.active_idx]
        self.wallet_title.config(text=w["name"])
        self.addr_lbl.config(text=w["address"])
        self._refresh_data()

    def _add_wallet(self):
        dlg = AddWalletDialog(self)
        self.wait_window(dlg)
        if dlg.result:
            self.wallet_data["wallets"].append(dlg.result)
            save_wallets(self.wallet_data, self.password)
            self._refresh_wallet_list()

    def _remove_wallet(self):
        if self.active_idx is None:
            return
        w = self.wallet_data["wallets"][self.active_idx]
        if not messagebox.askyesno(
                "Delete Wallet",
                f"Remove '{w['name']}' from this manager?\n\n"
                "Your XRP stays on the ledger — only the seed entry is deleted."):
            return
        self.wallet_data["wallets"].pop(self.active_idx)
        save_wallets(self.wallet_data, self.password)
        self.active_idx = None
        self.wallet_title.config(text="Select a wallet →")
        self.addr_lbl.config(text="")
        self._clear_ui()
        self._refresh_wallet_list()

    def _clear_ui(self):
        self.bal_lbl.config(text="—")
        self.seq_lbl.config(text="—")
        self.res_lbl.config(text="—")
        self.own_lbl.config(text="—")
        for tree in (self.token_tree, self.tl_tree, self.tx_tree):
            tree.delete(*tree.get_children())

    # ── Data refresh ─────────────────────────────────────────────────────────
    def _refresh_data(self):
        if self.active_idx is None:
            return
        w = self.wallet_data["wallets"][self.active_idx]
        self.bal_lbl.config(text="Loading…", fg=YELLOW)
        threading.Thread(target=self._fetch_all, args=(w,), daemon=True).start()

    def _fetch_all(self, wallet):
        addr = wallet["address"]
        try:
            info  = xrpl_get_account_info(addr)
            acc   = info.get("account_data", {})
            bal   = int(acc.get("Balance", 0)) / 1_000_000
            seq   = acc.get("Sequence", "?")
            own   = int(acc.get("OwnerCount", 0))
            res   = calc_reserve(own)
            lines = xrpl_get_trust_lines(addr)
            txs   = xrpl_get_transactions(addr, limit=25)

            # Resolve token names (network calls cached after first lookup)
            resolved = []
            for line in lines:
                currency = line.get("currency", "")
                issuer   = line.get("account", "")
                name     = resolve_token_name(currency, issuer)
                resolved.append({
                    "name":    name,
                    "balance": line.get("balance", "0"),
                    "limit":   line.get("limit", "0"),
                    "issuer":  issuer,
                })

            self.after(0, lambda: self._update_dashboard(bal, seq, res, own, resolved))
            self.after(0, lambda: self._update_tx(txs, addr))

        except Exception as e:
            self.after(0, lambda: self.bal_lbl.config(text=f"Error: {e}", fg=RED))

    def _update_dashboard(self, bal, seq, res, own, resolved_lines):
        self.bal_lbl.config(text=f"{bal:,.6f} XRP", fg=GREEN)
        self.seq_lbl.config(text=str(seq))
        self.res_lbl.config(
            text=f"{res:.1f}  ({BASE_RESERVE} base + {own}×{OWNER_RESERVE})")
        self.own_lbl.config(text=str(own))

        for tree in (self.token_tree, self.tl_tree):
            tree.delete(*tree.get_children())
        for item in resolved_lines:
            row = (item["name"], item["balance"],
                   item["limit"], item["issuer"])
            self.token_tree.insert("", "end", values=row)
            self.tl_tree.insert("",    "end", values=row)

    def _update_tx(self, txs, own_address: str):
        self.tx_tree.delete(*self.tx_tree.get_children())
        for entry in txs:
            # AccountTx wraps each record: {"tx": {...}, "meta": {...}}
            # Newer xrpl-py may use "transaction" key
            tx   = entry.get("tx") or entry.get("transaction") or {}
            meta = entry.get("meta") or entry.get("metaData") or {}

            ttype  = tx.get("TransactionType", "—")
            ledger = (tx.get("inLedger") or
                      tx.get("ledger_index") or
                      entry.get("ledger_index", "—"))

            # Amount: XRP → drops string; IOU → dict with value/currency
            raw_amt = tx.get("Amount", "")
            if isinstance(raw_amt, str):
                if raw_amt.isdigit():
                    amount = f"{int(raw_amt) / 1_000_000:.6f} XRP"
                else:
                    amount = raw_amt
            elif isinstance(raw_amt, dict):
                cur = _hex_to_ascii(raw_amt.get("currency", ""))
                amount = f"{raw_amt.get('value', '')} {cur}"
            else:
                amount = "—"

            raw_fee = tx.get("Fee", "")
            fee = (f"{int(raw_fee) / 1_000_000:.6f}"
                   if raw_fee and str(raw_fee).isdigit() else "—")

            frm    = tx.get("Account", "—")
            dst    = tx.get("Destination", "—")
            result = (meta.get("TransactionResult", "—")
                      if isinstance(meta, dict) else "—")

            tag = "out" if frm == own_address else "in"
            self.tx_tree.insert("", "end",
                values=(ledger, ttype, amount, fee, frm, dst, result),
                tags=(tag,))

        self.tx_tree.tag_configure("in",  foreground=GREEN)
        self.tx_tree.tag_configure("out", foreground=YELLOW)

    # ── Send XRP ──────────────────────────────────────────────────────────────
    def _do_send(self):
        if self.active_idx is None:
            messagebox.showwarning("No wallet", "Please select a wallet first.")
            return
        dest    = self.send_dest_entry.get().strip()
        amt_str = self.send_amt_entry.get().strip()
        memo    = self.send_memo_entry.get().strip()
        if not dest or not amt_str:
            messagebox.showwarning("Missing info",
                                    "Please fill in destination and amount.")
            return
        try:
            amt = float(amt_str)
        except ValueError:
            messagebox.showerror("Error", "Invalid amount.")
            return
        if not messagebox.askyesno("Confirm Send",
                                    f"Send {amt} XRP to:\n{dest}\n\n"
                                    "This transaction cannot be undone."):
            return
        seed = self.wallet_data["wallets"][self.active_idx]["seed"]
        self.send_status.config(text="Sending…", fg=YELLOW)
        threading.Thread(target=self._async_send,
                         args=(seed, dest, amt, memo), daemon=True).start()

    def _async_send(self, seed, dest, amt, memo):
        try:
            result   = xrpl_send_xrp(seed, dest, amt, memo)
            res_code = (result.get("meta") or {}).get("TransactionResult", "Unknown")
            if res_code == "tesSUCCESS":
                h = result.get("hash", "?")[:16]
                self.after(0, lambda: self.send_status.config(
                    text=f"✓ Sent!  hash: {h}…", fg=GREEN))
            else:
                self.after(0, lambda: self.send_status.config(
                    text=f"Failed: {res_code}", fg=RED))
        except Exception as e:
            self.after(0, lambda: self.send_status.config(
                text=f"Error: {e}", fg=RED))
        self.after(2000, self._refresh_data)

    # ── Trust Lines ───────────────────────────────────────────────────────────
    def _do_trust_line(self):
        if self.active_idx is None:
            messagebox.showwarning("No wallet", "Please select a wallet first.")
            return
        currency  = self.tl_currency_entry.get().strip().upper()
        issuer    = self.tl_issuer_entry.get().strip()
        limit_str = self.tl_limit_entry.get().strip()
        if not currency or not issuer or not limit_str:
            messagebox.showwarning("Missing info", "Please fill in all fields.")
            return
        try:
            limit = float(limit_str)
        except ValueError:
            messagebox.showerror("Error", "Invalid limit amount.")
            return
        seed = self.wallet_data["wallets"][self.active_idx]["seed"]
        self.tl_status.config(text="Submitting…", fg=YELLOW)
        threading.Thread(target=self._async_trustline,
                         args=(seed, currency, issuer, limit), daemon=True).start()

    def _async_trustline(self, seed, currency, issuer, limit):
        try:
            result   = xrpl_set_trust_line(seed, currency, issuer, limit)
            res_code = (result.get("meta") or {}).get("TransactionResult", "Unknown")
            if res_code == "tesSUCCESS":
                self.after(0, lambda: self.tl_status.config(
                    text="✓ Trust line updated!", fg=GREEN))
            else:
                self.after(0, lambda: self.tl_status.config(
                    text=f"Failed: {res_code}", fg=RED))
        except Exception as e:
            self.after(0, lambda: self.tl_status.config(
                text=f"Error: {e}", fg=RED))
        self.after(2000, self._refresh_data)


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = XRPLApp()
    app.mainloop()