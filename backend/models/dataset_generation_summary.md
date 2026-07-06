# Dataset Generation Summary

This report documents the procedural rules engines and heuristics used to safely generate >70,000 new payloads for VIREX.

## 1. Normal Traffic Generators
We synthesized complex, non-malicious structures that frequently trigger False Positives in naive WAF logic.

* **REST APIs:** Generated combinations of `GET/POST/PUT/DELETE/PATCH` across common endpoints (`/api/v1/users`, `/api/auth/login`) with randomized numeric query strings.
* **JSON Serialization:** Generated valid `{"key": "value"}` structures. By exposing the model to `{`, `"`, and `:`, it learns that these characters are structural (not SSTI or SQLi markers).
* **XML Bodies:** Generated `<data><user>ID</user></data>` structures, neutralizing the model's fear of `<` and `>` (historically heavily biased toward XSS).
* **GraphQL Queries:** Generated nested `query { user(id: "123") { name } }` structures.
* **JWT & Bearer Tokens:** Generated cryptographically valid 3-part base64 headers. This forces the model to accept the base64 padding `==` without assuming it is a base64-encoded command injection.

## 2. Attack Obfuscation Engine
We aggressively mutated the existing attack baseline to increase the model's structural resilience to obfuscated variants. The following techniques were applied to payloads across `sqli`, `xss`, `ssti`, `xxe`, `ssrf`, `command_injection`, `path_traversal`, and `log4shell`:

1. **Standard URL Encoding:** Converts specific characters to `%XX`.
2. **Double URL Encoding:** Converts `%` to `%25XX`, bypassing weak unquote layers.
3. **Unicode Escaping:** Converts characters to `\uXXXX` format (frequently used to bypass XSS and JSON filters).
4. **HTML Entity Encoding:** Converts characters to `&#xXX;` (bypasses naive XSS filters).
5. **Base64 Encoding:** Wraps the entire string into base64, common for hidden `eval()` injections.
6. **Case Randomization:** Flips characters (`sElEcT` instead of `SELECT`), destroying exact string matches.
7. **Random Spacing:** Injects multiple spaces between keywords, breaking hardcoded regex boundaries.
8. **Inline Comments:** Replaces spaces with `/**/` (a massive blind spot for classic SQLi parsers).

## 3. Safety Mechanisms
- **Label Preservation:** A core rule was strict class isolation. Normal generation logic ONLY ever produced `normal` labels, and attack augmentation ONLY mutated payloads already belonging to an attack class.
- **Hash De-duplication:** All payloads were hashed and checked for exact matches against the existing `val.csv` and `test.csv`. Any generated payload matching a pre-existing validation payload was explicitly discarded, ensuring 0% dataset leakage.
