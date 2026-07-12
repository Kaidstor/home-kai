# home-kai

Свой аналог Tailscale для homelab: доступ ко всем своим машинам по приватной оверлей-сети, **не открывая ни одного входящего порта** на них. Data plane — WireGuard, control plane — свой, на Go.

Zero-dependency: три статических Go-бинаря, состояние в SQLite, никаких внешних сервисов. Свой координатор вместо Headscale/NetBird — цель была написать своё и получить рабочий инструмент для homelab. Pet-проект, лицензия [MIT](LICENSE).

> ⚠️ Домены/IP в этом репозитории — плейсхолдеры (`vpn.example.com`, `203.0.113.x`). Подставь адрес своего VPS.

Подробный гайд (как работает, как подключать устройства, диагностика): **[docs/tutor.html](docs/tutor.html)**.
Архитектурный план и roadmap: `plans/wondrous-strolling-finch.md`.

## Компоненты

| Бинарь | Где живёт | Что делает |
|---|---|---|
| `kai-coordinator` | VPS, TCP 8443 | enrollment по одноразовым токенам, раздача netmap (HTTP long-poll), admin API, **web UI на `/ui`**, `/metrics`, DNS-имена устройств |
| `kai-agent` | каждый узел (Linux/macOS, root) | WireGuard-интерфейс, синхронизация пиров, p2p-prober, subnet router, /etc/hosts-имена, funnel-форвардеры (на хабе), кэш netmap |
| `home-kai` | админская машина | токены, узлы/маршруты, static peers с QR, публикации, `status`/`ping`, network lock |

Правило имён: `kai-*` — служебные бинарники и сеть (`kai-coordinator`, `kai-agent`, интерфейс `kai0`, имена `*.kai`), `home-kai` — админский CLI.

Базовая топология — hub-and-spoke: узлы держат исходящий туннель к хабу (VPS), хаб форвардит. Наружу открыт только VPS: TCP 8443 (координатор) и UDP 51820 (WireGuard). iPhone/Android/роутер подключаются официальным WireGuard-клиентом (`home-kai peer create` → QR).

Ключевые свойства:
- **Data plane независим от control plane**: координатор может лежать — туннели работают (netmap кэшируется в state-файле агента).
- **Приватный ключ WireGuard не покидает узел** (кроме static peers — там иначе никак).
- TLS координатора — self-signed + пиннинг sha256-отпечатка в агенте: не нужен ни домен, ни CA, переживает смену IP.

## Фичи

- **Прямые p2p-соединения (M3).** Споки получают друг друга в netmap с кандидатами (LAN-адреса + reflexive-адреса, которые хаб видит по keepalive). Prober агента ставит пира с *пустыми* AllowedIPs — handshake пробивает NAT (обе стороны инициируют одновременно), а relay-путь через хаб не рвётся. После подтверждения пир получает свой `/32`, который побеждает `/16` хаба по longest prefix; стух handshake (>3 мин) — мгновенный откат на хаб. Путь виден в `home-kai status` (`direct`/`relay`).
- **Subnet router.** `kai-agent up --advertise-routes 192.168.1.0/24` — узел предлагает роутить свою LAN; в netmap подсеть попадает только после включения админом (UI-чекбокс или `home-kai node routes <id> --enable ...`). Анонсирующий узел сам включает форвардинг и ставит MASQUERADE/FORWARD-правила (DOCKER-USER-совместимо); агенты пропускают маршрут, если он конфликтует с их локальной сетью (docker-бриджи!).
- **Имена устройств.** Каждый агент ведёт блок в `/etc/hosts`: `ssh user@nas.kai`. Работает офлайн, без своего DNS. Отключается `--no-hosts`. Для static peers (телефоны/роутеры), где `/etc/hosts` недоступен, хаб поднимает DNS-резолвер на своём overlay-IP: отвечает на `*.kai` из netmap, остальное форвардит в 1.1.1.1/8.8.8.8; конфиг static peer прописывает его в `DNS =` вместе с search-доменом `kai` — с телефона работает и `nas.kai`, и просто `nas`.
- **Exit node для static peers.** Тумблер «полный туннель» в UI (или `home-kai peer create имя --full`): конфиг с `AllowedIPs 0.0.0.0/0` — весь трафик телефона идёт через VPS (хаб маскарадит наружу). IPv6 сознательно не заворачивается.
- **Публикации (funnel).** TCP-проброс с публичного порта VPS на сервис в оверлее: `{"name":"jellyfin","listen_port":8096,"target":"nas.kai:8096"}` — хаб слушает порт и форвардит. Управление в UI или через `POST /v1/admin/publishes`.
- **Ротация WG-ключей.** `kai-agent up --rekey-days 30` — авторотация на живом устройстве; `kai-agent rekey` — офлайн. Прерванная ротация самолечится (агент ре-ассертит ключ при старте).
- **Network lock** (аналог tailnet lock). `home-kai lock init` создаёт ed25519-ключ **только на админской машине** (`~/.config/kai/lock.key` — забэкапь!), `home-kai lock sign` подписывает привязки (wg-ключ, overlay-IP) всех устройств. Агенты пинят ключ и отбрасывают неподписанных пиров: скомпрометированный координатор не может подсунуть своего. Новые устройства и ротации ключей требуют `home-kai lock sign`. `home-kai lock status` / `home-kai lock disable`.
- **ACL-политики.** Узлам и static peers назначаются теги; политика `src-теги → dst-теги, протокол, порты` разрешает трафик. Как только появляется первая включённая политика — оверлей работает по принципу «запрещено всё, кроме явно разрешённого». Enforcement двухуровневый: Linux-агенты ставят цепочку `KAI-FILTER` на входе `kai0` (свой входящий трафик), а хаб и subnet-роутеры дополнительно фильтруют **пересылаемый** трафик цепочкой `KAI-FORWARD` — так под ACL попадают и static peers (телефоны), и LAN-подсети за роутером (подсеть наследует теги анонсирующего узла). Узлы без iptables (macOS) при включённом ACL лишаются прямых p2p-путей: их трафик принудительно идёт через хаб, где и фильтруется. Управление в UI («Добавить политику», кнопка «теги») или `home-kai policy` / `home-kai node tag`.
- **Peer approval.** С `require_approval = true` в конфиге новый узел висит без доступа (никого не видит и невидим другим), пока админ не одобрит его в UI или через `home-kai node approve <id>`.
- **Журнал событий.** Координатор пишет ключевые действия (enroll/approve/routes/policy/publish/lock/…) в SQLite; смотреть в панели (карточка «Журнал»), через `home-kai events` или `GET /v1/admin/events`. Опциональный `event_webhook` в конфиге шлёт JSON-POST на каждое событие (мост в SIEM/чат).
- **`/metrics`** — Prometheus-метрики (admin bearer): узлы total/online/pending, публикации, политики, версия netmap, сессии, lock.

## Адресация и доступ

- Оверлей по умолчанию `100.87.0.0/16`; хаб получает `100.87.0.1` (диапазон меняется в `overlay_cidr`).
- Admin-токен печатает `kai-coordinator gen-admin-token` — сохрани его (например в `/root/kai-admin-token.txt`, `chmod 600`) для CLI/панели; в конфиг кладётся только его hash.
- Отпечаток TLS координатора — в его логе: `journalctl -u kai-coordinator | grep fingerprint`; нужен агентам при подключении (пиннинг).

## Web UI

**`https://vpn.example.com:8444/ui`** — панель управления: устройства с online-статусом (теги, одобрение, анонсированные подсети), enroll-токены (готовая join-команда), static peers с QR/конфигом и тумблером полного туннеля, публикации сервисов, ACL-политики, индикатор network lock и журнал последних событий. Страница встроена в бинарь координатора, отдельного фронтенда нет.

- Вход по admin-токену; он обменивается на HttpOnly session-cookie (30 дней) и **в браузере не хранится** — сессии живут в памяти координатора, рестарт разлогинивает.
- Порт 8444 — отдельный листенер с **Let's Encrypt сертификатом**: на домен (`vpn.example.com`, обычный 90-дневный — удобно вместе с секцией `dns`) либо на голый IP (профиль `shortlived`, 160 ч), если домена нет. certbot на VPS продлевает по таймеру, deploy-hook кладёт файлы в `/etc/kai/ui-tls/`, координатор перечитывает их с диска на лету — рестарт (и разлогин) не нужен.
- `:8443/ui` тоже работает — это листенер агентов с self-signed сертификатом (пиннинг отпечатка, LE его не заменяет: отпечаток LE-серта ротировался бы каждые 6 дней); в браузере там будет предупреждение — это fallback на случай проблем с LE.

## Быстрые команды

```sh
# локально на любом узле (без токенов — через unix socket агента;
# сокет 0660 root:kai — либо sudo, либо groupadd kai && usermod -aG kai $USER)
home-kai status                        # пиры: direct/relay, handshake, rx/tx
home-kai ping nas                      # резолв имени + путь + ping

# админский доступ. Секреты (KAI_URL/KAI_ADMIN_TOKEN/KAI_FINGERPRINT) держим
# в sec, чтобы admin-токен не светился в env/истории — префикс `sec run --`
# инъектит их в процесс. Один раз завести: admin-токен с VPS
#   ssh root@<vps> 'awk "/admin token:/ {print \$3}" /root/kai-admin-token.txt' | sec set home-kai/KAI_ADMIN_TOKEN
# (KAI_URL/KAI_FINGERPRINT — публичные, тоже кладём в sec для удобства).
sec run home-kai -- home-kai node list
sec run home-kai -- home-kai token create --name <имя>   # токен + join-команда
sec run home-kai -- home-kai node delete <node_id>
sec run home-kai -- home-kai node routes <node_id> --enable 192.168.1.0/24
sec run home-kai -- home-kai node approve <node_id>       # peer approval
sec run home-kai -- home-kai node tag <node_id> --tags web,prod
sec run home-kai -- home-kai policy create web-ssh --from admin --to web --proto tcp --ports 22
sec run home-kai -- home-kai peer create iphone [--full]   # QR; --full = exit node
sec run home-kai -- home-kai peer tag <peer_id> --tags phones   # теги для ACL (home-kai peer list — id)
sec run home-kai -- home-kai events                        # журнал
home-kai lock init && home-kai lock sign    # network lock (ed25519-ключ остаётся на этой машине)

# подключение нового узла (Linux/macOS, root)
sudo kai-agent up --coordinator https://vpn.example.com:8443 --token ... --fingerprint ...
# полезные флаги: --advertise-routes CIDR,CIDR  --rekey-days N  --no-hosts
```

> Без sec можно по-старому — `export KAI_URL/KAI_ADMIN_TOKEN/KAI_FINGERPRINT` и вызывать `home-kai` напрямую; sec лишь держит admin-токен вне окружения и истории. Все три переменные обязательны: без отпечатка CLI не подключится (TLS-пиннинг не отключается).

## Разработка

```sh
just build          # сборка под текущую платформу в ./bin
just build-linux    # кросс-компиляция под VPS (linux/amd64)
just test           # go vet + go test
just provision-vps  # первичная установка юнитов/sysctl на VPS
just deploy-vps     # заливка бинарей + рестарт сервисов
```

Раскладка кода: `cmd/*` — три бинаря; `internal/coordinator` — control plane (store/ipam/netmap/dns); `internal/agent` — демон узла (`wgdev` — платформенный слой WireGuard: netlink+wgctrl на Linux, embedded wireguard-go на macOS); `internal/api` — типы протокола; `deploy/` — systemd/launchd/sysctl.

## Конфиг координатора (`/etc/kai/coordinator.toml`)

```toml
listen           = ":8443"
public_url       = "https://vpn.example.com:8443"
hub_endpoint     = "vpn.example.com:51820"
overlay_cidr     = "100.87.0.0/16"
data_dir         = "/var/lib/kai"
admin_token_hash = "<kai-coordinator gen-admin-token>"

[dns]                        # опционально: DNS-имена устройств {16random}.{domain}
provider = "timeweb"
token    = "<jwt из панели timeweb → API и Terraform>"
zone     = "example.com"     # зона, делегированная на NS Timeweb
domain   = "kai.example.com" # суффикс имён устройств (по умолчанию = zone)

[ui]                         # опционально: листенер для браузера с доверенным сертом
listen    = ":8444"
cert_file = "/etc/kai/ui-tls/fullchain.pem"  # LE-серт на IP, hot-reload при обновлении
key_file  = "/etc/kai/ui-tls/privkey.pem"

require_approval = false     # true → новые узлы ждут одобрения (home-kai node approve / кнопка в UI)
event_webhook    = ""        # URL: POST JSON на каждое событие журнала (SIEM/чат)
reserved_ports   = []        # доп. порты этого хоста, запрещённые для публикаций (напр. [9443, 10050])
```

## Статус и лицензия

Личный проект, который дорос до рабочего инструмента: M1–M5 реализованы и обкатаны на живой сети (VPS-хаб + узлы Linux/macOS). Не рассчитан на прод в организации — для этого есть Headscale/NetBird/Tailscale. Лицензия — **[MIT](LICENSE)**, PR и issue welcome.

Английский README и бинарные релизы пока не сделаны — гайд и код на русском/английском вперемешку (комментарии в коде — английские). Если проект окажется полезен кому-то ещё, добавлю.
