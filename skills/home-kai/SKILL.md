---
name: home-kai
description: Управление оверлей-сетью home-kai (self-hosted аналог Tailscale на WireGuard) через админский CLI `kai` — enroll-токены, узлы и subnet-маршруты, static peers с QR (телефоны/роутеры), ACL-политики по тегам, network lock, журнал событий, диагностика status/ping. Use when the user asks to add a device to the kai overlay/VPN, create an enroll token, approve a node, enable subnet routes, create a static peer or QR config, manage ACL policies or tags, sign network lock, check peer connectivity (direct/relay), or otherwise administer a home-kai network.
metadata:
  author: kaidstor
---

# kai CLI — администрирование сети home-kai

`kai` — админский CLI координатора home-kai. Команды двух типов:

- **Локальные** (`home-kai status`, `home-kai ping`) — ходят в unix-socket агента `kai-agent` на этой же машине, креды не нужны.
- **Админские** (всё остальное) — ходят в admin API координатора и требуют env-переменных:

```sh
export KAI_URL=https://vpn.example.com:8443   # public_url координатора
export KAI_ADMIN_TOKEN=...                    # печатает `kai-coordinator gen-admin-token` на VPS
export KAI_FINGERPRINT=sha256:...             # отпечаток TLS: journalctl -u kai-coordinator | grep fingerprint
```

Правила безопасности:

- `KAI_ADMIN_TOKEN` — секрет. Не выводи его в чат/логи, не подставляй в argv; подгружай из файла или менеджера секретов (например `sec run home-kai -- kai ...`).
- Без `KAI_FINGERPRINT` CLI работает, но **не проверяет TLS** (печатает warning) — для реальной сети отпечаток обязателен.
- `~/.config/kai/lock.key` (network lock) живёт только на админской машине — не копируй и не показывай его.

## Команды

```
home-kai token create [--name HINT] [--ttl SECONDS]        # одноразовый enroll-токен + готовая join-команда (ttl по умолчанию 3600)
home-kai node list                                          # узлы: id, имя, overlay-IP, online, теги, маршруты
home-kai node delete <node_id>
home-kai node routes <node_id> --enable CIDR,CIDR           # включить подмножество анонсированных узлом подсетей
home-kai node approve <node_id>                             # одобрить узел (при require_approval = true)
home-kai node tag <node_id> --tags a,b                      # теги для ACL (пустое значение очищает)
home-kai policy list
home-kai policy create <name> --from tagA --to tagB [--proto any|tcp|udp|icmp] [--ports 22,443] [--disabled]
home-kai policy delete <id>
home-kai events [--limit N]                                 # журнал координатора (enroll/approve/routes/policy/…)
home-kai peer create <name> [--png FILE] [--full]           # static peer: конфиг WireGuard + QR; --full = exit node (весь трафик через хаб)
home-kai peer list
home-kai peer tag <peer_id> --tags a,b
home-kai status                                             # локально: пиры, путь direct/relay, handshake, rx/tx
home-kai ping <name|ip>                                     # резолв имени устройства + ping + путь
home-kai lock init|sign|status|disable [--key FILE]         # network lock: подписанные привязки пиров
```

## Типовые сценарии

**Подключить новый узел (Linux/macOS):**

1. `home-kai token create --name <имя>` — команда печатает токен и готовую join-команду.
2. На новом узле под root: `sudo kai-agent up --coordinator $KAI_URL --token <...> --fingerprint <...>`
   (полезные флаги: `--advertise-routes CIDR,CIDR`, `--rekey-days N`, `--no-hosts`).
3. Если у координатора `require_approval = true` — узел висит без доступа до `home-kai node approve <node_id>` (id смотри в `home-kai node list`).
4. Если включён network lock — новое устройство не заработает до `home-kai lock sign` с админской машины.

**Подключить телефон/роутер (static peer):** `home-kai peer create iphone --png iphone.png` — QR сканируется официальным WireGuard-клиентом. `--full` — полный туннель (exit node через хаб). Имена `*.kai` на static peers работают через DNS-резолвер хаба (прописан в конфиге автоматически).

**Включить subnet router:** узел анонсирует LAN (`kai-agent up --advertise-routes 192.168.1.0/24`), но в netmap подсеть попадает только после `home-kai node routes <node_id> --enable 192.168.1.0/24`.

**Настроить ACL:** проставь теги (`home-kai node tag`, `home-kai peer tag`), затем `home-kai policy create web-ssh --from admin --to web --proto tcp --ports 22`. ⚠️ Первая же включённая политика переводит сеть в режим default-deny — всё, что явно не разрешено, блокируется (enforcement на Linux-агентах через iptables-цепочку `KAI-FILTER`; macOS не enforce'ит). Проверяй, что нужные пары тегов покрыты, прежде чем включать.

**Network lock:** `home-kai lock init` (создаёт ed25519-ключ — сразу предложи пользователю забэкапить `~/.config/kai/lock.key`), затем `home-kai lock sign`. После добавления устройств или ротации WG-ключей подписи надо обновлять повторным `home-kai lock sign`. `home-kai lock status` — проверка, `home-kai lock disable` — откат.

**Диагностика:** `home-kai status` показывает путь до каждого пира (`direct` = p2p, `relay` = через хаб), время handshake и трафик; `home-kai ping nas` — резолв имени + путь + ping. Data plane живёт независимо от координатора: если координатор лежит, туннели продолжают работать на кэшированном netmap.

## Ориентиры

- Оверлей по умолчанию `100.87.0.0/16`, хаб — `100.87.0.1`; имена устройств — `<имя>.kai` (через /etc/hosts на узлах).
- Web UI со всем тем же функционалом: `https://<хаб>:8444/ui` (вход по admin-токену).
- Подробный гайд: `docs/tutor.html` в репозитории home-kai; обзор — `README.md`.
