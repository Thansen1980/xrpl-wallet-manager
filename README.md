# 💜 XRPL Wallet Manager

A lightweight, local GUI wallet manager for the XRP Ledger — built with Python and Tkinter.  
No cloud. No third-party custody. Your seeds stay on your machine, encrypted.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

---

## ✨ Features

- 🔐 **Encrypted local storage** — seeds are protected with PBKDF2 + Fernet (AES-128-CBC)
- 👛 **Multiple wallets** — add, switch between, and delete wallets
- 📊 **Dashboard** — live XRP balance, correct reserve calculation, token/IOU balances with resolved names
- 💸 **Send XRP** — with optional memo and confirmation dialog
- 🔗 **Trust Lines** — view existing trust lines and set/update new ones
- 📜 **Transaction history** — last 25 transactions with incoming/outgoing colour coding
- 🔤 **Token name resolution** — hex currency codes resolved to human-readable names via [xrplmeta.org](https://xrplmeta.org) and [xrpscan.com](https://xrpscan.com)
- ↕️ **Sortable tables** — click any column header to sort

---

## 📋 Requirements

- Python 3.10 or higher
- The following pip packages:

```bash
pip install xrpl-py cryptography
```

---

## 🚀 Getting Started

1. **Clone the repository**

```bash
git clone https://github.com/your-username/xrpl-wallet-manager.git
cd xrpl-wallet-manager
```

2. **Install dependencies**

```bash
pip install xrpl-py cryptography
```

3. **Run the app**

```bash
python xrpl_wallet_manager.py
```

4. **First launch** — you will be asked to create a master password. This password encrypts your wallet file. There is no recovery option, so keep it safe.

---

## 🖥️ Interface Overview

### Dashboard
Displays your XRP balance and a breakdown of your account reserve:

```
Reserve = 1.0 XRP (base) + owner objects × 0.2 XRP
```

Token/IOU balances are shown with resolved names (e.g. `Ripple USD (RLUSD)`) fetched from xrplmeta.org. All columns are sortable.

### Send XRP
Enter a destination address, amount, and optional memo. A confirmation dialog is shown before the transaction is submitted.

### Trust Lines
View all existing trust lines with token names and balances. Set or update a trust line by entering a currency code, issuer address, and limit.

### Transactions
The last 25 transactions for the selected wallet. Incoming transactions are shown in **green**, outgoing in **yellow**.

---

## 🔒 Security & Storage

### Where seeds are stored

Seeds are saved locally at:

| Platform | Path |
|----------|------|
| Windows  | `C:\Users\<YourUsername>\.xrpl_wallets.enc` |
| macOS / Linux | `~/.xrpl_wallets.enc` |

### Encryption details

| Layer | Algorithm |
|-------|-----------|
| Key derivation | PBKDF2-HMAC-SHA256, 480,000 iterations, 16-byte random salt |
| Encryption | Fernet (AES-128-CBC + HMAC-SHA256) |

The salt is prepended to the encrypted file. Without the correct master password, the file cannot be decrypted.

### Important notes

- Seeds are held in **plaintext in memory** while the app is running — required for transaction signing
- If you lose your master password, **the encrypted file cannot be recovered**
- Always keep a separate offline backup of your seeds (paper, hardware wallet, etc.)
- This tool is for **personal use** — do not use it to manage funds you cannot afford to lose without a seed backup

---

## 🌐 Network

This app connects to the **XRP Ledger Mainnet** via:

```
https://xrplcluster.com
```

Token names are resolved using:
- `https://s1.xrplmeta.org` (primary)
- `https://api.xrpscan.com` (fallback)

No data is sent to any server other than the official XRPL node and the above metadata services.

---

## 📦 Project Structure

```
xrpl-wallet-manager/
├── xrpl_wallet_manager.py   # Main application (single file)
└── README.md
```

---

## 🛠️ Built With

- [xrpl-py](https://github.com/XRPLF/xrpl-py) — Official Python library for the XRP Ledger
- [cryptography](https://cryptography.io) — Encryption (Fernet / PBKDF2)
- [Tkinter](https://docs.python.org/3/library/tkinter.html) — Built-in Python GUI framework
- [xrplmeta.org](https://xrplmeta.org) — Token metadata API
- [xrpscan.com](https://xrpscan.com) — Token info fallback API

---

## ⚠️ Disclaimer

This software is provided as-is for personal use. It is not audited for security. Do not use it as your sole method of key management. Always maintain an independent backup of your seeds.

The author(s) are not responsible for lost funds due to software bugs, user error, or compromised master passwords.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
