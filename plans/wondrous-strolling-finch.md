# home-kai — свой аналог Tailscale на Go

## Context

Нужен безопасный доступ к своим серверам (VPS, домашние машины за NAT) без проброса портов наружу: серверы делают только исходящие соединения. Готовые решения (Headscale, NetBird) сознательно не берём — это pet-проект: цель написать своё, но получить реально рабочий инструмент для homelab.

Вводные:
- Стек: **Go**. Data plane: **WireGuard** (свою криптографию не изобретаем, control plane — свой).
- Устройства: Linux-серверы, Mac (рабочая машина), домашний роутер/NAS, iPhone/Android.
- Свой агент — только для Linux/macOS. Мобильные и роутер подключаются **официальным WireGuard-клиентом** по сгенерированному конфигу/QR («static peers», всегда ходят через хаб).

## VPS под координатор/relay (требования)

- Любой Linux с ядром ≥ 5.6 (есть kernel-модуль WireGuard) — например Ubuntu 22.04/24.04. wireguard-tools не обязательны (управление через netlink/wgctrl).
- Ресурсов нужно немного: 1 vCPU / 512 MB–1 GB RAM хватает (координатор < 50 MB).
- Координатор слушает **TCP 8443**, WireGuard-хаб — **UDP 51820**; при желании панель на **TCP 8444**. Порты настраиваются в конфиге, если стандартные заняты другими сервисами.
- Наружу должны быть открыты только 22 (SSH), 8443/tcp, 51820/udp (+ 8444/tcp для панели).
- Если публичный IP VPS может меняться — **не хардкодим IP**: адрес координатора задаётся в конфиге агента, endpoint хаба агенты получают из netmap (переживает смену IP); конфиги static peers содержат endpoint статически, при ротации их надо перегенерировать (или завести DNS-имя, см. риски).

## Архитектура

Три бинаря в одном Go-модуле `github.com/kaidstor/home-kai`:

1. **`kai-coordinator`** (VPS, TCP 8443) — control plane: enrollment по одноразовым токенам, хранение публичных ключей, IPAM оверлея, раздача netmap агентам (HTTP long-poll), генерация конфигов/QR для static peers. Состояние — SQLite.
2. **`kai-agent`** (Linux + macOS) — демон узла: генерирует WG-ключи локально (приватный ключ не покидает узел), регистрируется, поднимает WireGuard-интерфейс, применяет netmap. На VPS работает в роли `hub` (форвардинг между пирами + отчёт о наблюдаемых endpoint'ах).
3. **`kai`** — админ-CLI: токены, список узлов, static peers c QR, статус.

Топология поэтапно: **M1 hub-and-spoke** (все узлы держат исходящий WG-туннель к хабу, хаб форвардит) → **M3 mesh** (прямые p2p-соединения с hole punching, fallback на хаб). Порты наружу не открывает ни один узел, кроме VPS.

### TLS координатора: self-signed + пиннинг отпечатка

443 занят xray, autocert не вариант. Координатор при первом старте генерирует self-signed сертификат; `kai token create` выдаёт готовую команду join, включающую **отпечаток сертификата**, агент его пинит. Плюсы: не нужен домен и LE, переживает ротацию IP, безопасно (никакого доверия системным CA). Если позже появится DNS-имя — можно перейти на LE без изменения протокола.

## Библиотеки (проверены на актуальность)

| Библиотека | Зачем | Нюансы |
|---|---|---|
| `golang.zx2c4.com/wireguard/wgctrl` | конфигурация WG-устройств (Linux kernel + userspace UAPI) | только ключи/пиры; интерфейс, IP и маршруты — самим. Нужен root/CAP_NET_ADMIN |
| `golang.zx2c4.com/wireguard` (wireguard-go) | userspace-WG для macOS, embed в агент: `tun` (utun), `device` (`IpcSet`), `conn` | тегов нет — пинить pseudo-version; требует свежий toolchain (`toolchain go1.24+`); root обязателен для utun; имя брать из `tun.Name()`; MTU 1420 |
| `github.com/vishvananda/netlink` | Linux: создание wg-линка, адреса, маршруты | v1.3.1, живая; kernel WG есть во всех ядрах ≥5.6 |
| `modernc.org/sqlite` | стейт координатора, CGO_ENABLED=0 | WAL + busy_timeout + один writer-конн, иначе SQLITE_BUSY |
| `github.com/pion/stun/v3` | только диагностика `kai netcheck` (M3) | основной путь discovery обходится без STUN (см. M3) |
| `skip2/go-qrcode` + `mdp/qrterminal/v3` | QR для static peers (PNG + ANSI в терминал) | стабильные |
| `BurntSushi/toml` | конфиги | — |

## Раскладка репозитория

```
cmd/kai-coordinator/  cmd/kai-agent/  cmd/kai/
internal/
  api/types.go            # общие типы протокола (EnrollRequest, Netmap, Peer, ...)
  coordinator/            # server.go (mux, TLS, auth), netmap.go, ipam.go,
                          # staticpeer.go, store/store.go (sqlite + миграции)
  agent/                  # agent.go (enroll→sync→apply), sync.go (long-poll, backoff,
                          # кэш netmap на диске), state.go (identity, 0600),
                          # hub.go (форвардинг, observed endpoints), probe.go (M3)
  agent/wgdev/            # Device-интерфейс: wgdev_linux.go (netlink+wgctrl),
                          # wgdev_darwin.go (embed wireguard-go + exec ifconfig/route)
  wgkeys/
deploy/systemd/ deploy/launchd/ deploy/sysctl/
justfile                  # build/cross-compile/deploy рецепты
docs/protocol.md
```

## Протокол управления: HTTPS + JSON + long-poll

Осознанно не gRPC/SSE: всё отлаживается curl'ом, сервер держит `GET /v1/netmap?since=N` до ~55 с и отвечает при росте версии. Netmap всегда **полный** (без диффов) — применение идемпотентно.

Node API (bearer = per-node `auth_secret`, выдаётся при enroll):
- `POST /v1/enroll` (bearer = одноразовый токен) → `{node_id, auth_secret, overlay_ip, netmap_version}`
- `GET /v1/netmap?since=N` — long-poll, 200 с netmap либо 304 по таймауту
- `POST /v1/status` — heartbeat: локальные endpoint'ы; для хаба — наблюдаемые reflexive-адреса пиров

Admin API (bearer = admin-токен из конфига): `POST /v1/admin/tokens`, `GET/DELETE /v1/admin/nodes`, `POST /v1/admin/static-peers`.

Схема SQLite: `nodes`, `enroll_tokens` (хранится hash), `static_peers`, `endpoints`, `meta(netmap_version)`.

## Оверлей и маршрутизация

- Диапазон `100.87.0.0/16` (внутри CGNAT 100.64.0.0/10, не пересекается с реальным Tailscale). Хаб — `100.87.0.1`. Выдача последовательная из SQLite.
- **M1**: у спока один пир — хаб с `AllowedIPs = 100.87.0.0/16` (cryptokey routing сам ставит маршрут); у хаба — все узлы по `/32`, `net.ipv4.ip_forward=1`, **без MASQUERADE** (исходные IP сохраняются). `PersistentKeepalive=25` у всех к хабу — держит NAT-mapping (и кормит M3).
- **M3, ключевой трюк**: AllowedIPs матчатся по longest prefix → спок держит хаб с `/16` И добавляет прямого пира с `/32` — `/32` побеждает, трафик идёт напрямую; убрал прямого пира — мгновенный fallback на хаб. Никакого своего disco-слоя. (Один и тот же префикс не может быть у двух пиров — netmap единственный источник истины, применение атомарное с `ReplacePeers: true`.)
- Default route **не захватываем** (AllowedIPs только оверлей) — нет routing loop к endpoint'у хаба; exit-node — сознательно отложенная фича.

## Static peers (iPhone/Android/роутер)

`kai peer add-static iphone` → координатор генерирует пару ключей server-side (неизбежно: приватник должен попасть в конфиг/QR), выделяет IP, отдаёт `.conf`: `Address=100.87.0.X/32`, `Peer=хаб`, `Endpoint=<vps>:51820`, `AllowedIPs=100.87.0.0/16`, `Keepalive=25`. CLI рендерит ANSI-QR в терминал и `--png`. В netmap они есть только у хаба (`/32`), весь их трафик — через хаб, hole punching для них не делаем.

## DNS-имена устройств (по запросу пользователя)

- Для хаба берётся **домен** (DNS-зона управляется в Timeweb). Endpoint хаба и адрес координатора — DNS-имя, а не IP → переживает ротацию IP, static-peer конфиги не протухают.
- **Абстрактный интерфейс DNS-провайдера** `internal/coordinator/dns`: `Provider { EnsureA(ctx, fqdn, ip) error; DeleteA(ctx, fqdn) error }`; реализации: `timeweb` (REST API) и `noop` (DNS выключен).
- При enroll узла координатор генерирует метку из **16 случайных символов** → создаёт A-запись `{label}.{domain}` → overlay-IP (100.87.x.x), сохраняет в `nodes.dns_name`, раздаёт в netmap. При удалении узла запись удаляется. Static peers — аналогично.
- Публичная A-запись на CGNAT-IP валидна и резолвится отовсюду; риск: **DNS rebind protection** на некоторых домашних роутерах режет ответы с приватными/CGNAT IP — документировать (лечится exception в роутере или своим resolver'ом позже).

## Этапы

### M0 — скелет (~полдня)
`go.mod`, заглушки cmd, `internal/api/types.go`, keygen, justfile с матрицей кросс-компиляции.
✅ `go build ./...` собирает все три бинаря под `linux/amd64` и `darwin/arm64`.

### M1 — hub-and-spoke MVP (~30–40 ч) ← главный payoff
Координатор (enroll, netmap long-poll, admin API, SQLite, self-signed TLS + fingerprint), агент: dataplane Linux (netlink+wgctrl) и macOS (embed wireguard-go + `IpcSet` + exec `ifconfig`/`route`), роль hub, sync-цикл с jittered backoff и кэшем netmap на диске, systemd-юниты, деплой на VPS.
✅ Демо: с Mac `ssh user@100.87.0.3` на домашний сервер за NAT; `wg show` на хабе — свежие handshake обоих; **останавливаем координатор — SSH продолжает работать** (независимость data plane).

### M2 — static peers + QR (~6–10 ч)
Admin-endpoint, рендер `.conf`, QR, включение в netmap хаба.
✅ iPhone сканирует QR в официальный WireGuard-app → пингует `100.87.0.1`, открывает сервис homelab по overlay-IP; Mac пингует iPhone через хаб.

### M3 — прямые соединения (~20–30 ч)
Discovery **без STUN**: хаб и так знает reflexive `ip:port` каждого узла (keepalive-туннель) — hub-агент читает endpoints через wgctrl и шлёт в `/v1/status`; координатор раздаёт `candidates` (LAN-адреса от самих агентов + observed от хаба) в netmap. Prober: добавить прямого пира `/32` с кандидатом, обе стороны инициируют (одновременные handshake пробивают NAT), подтверждение за ~15 с; при неудаче/стухании (>180 с) — снять пира → fallback на хаб. Фиксированный listen-port у агентов (стабильный NAT-mapping). LAN-кандидаты пробовать первыми. `kai netcheck` на pion/stun — классификация NAT для диагностики.
✅ Mac (LTE/кафе) ↔ домашний сервер: `wg show` показывает реальные endpoint'ы друг друга; `tcpdump udp port 51820` на VPS не видит их трафика; RTT падает. Отдельно проверить same-LAN кейс (выбор `192.168.x.x`).

### M4 — качество жизни (~10–20 ч, по мере надобности)
Имена через управляемые блоки в `/etc/hosts` (`100.87.0.3 home-server.kai`); LaunchDaemon для Mac; `kai status` через unix-socket агента; ротация ключей; `/metrics`; бэкап SQLite = копия файла.

## Деплой на VPS

- Сборка на Mac: `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w"` → один статический бинарь, `scp` (рецепт в justfile).
- `/etc/kai/coordinator.toml`: `listen = ":8443"`, `data_dir = "/var/lib/kai"`, `overlay_cidr`, `hub_endpoint = "vpn.example.com:51820"`, `admin_token_hash`.
- systemd: координатор под `User=kai` (+`StateDirectory`, `ProtectSystem=strict`, `Restart=always`); hub-агент под root (netlink). `/etc/sysctl.d/99-kai-forward.conf` с `net.ipv4.ip_forward=1` — **проверить, не сломает ли это xray-контейнеры (не должно — docker и так включает форвардинг)**.

## Риски / грабли

1. **macOS root**: utun требует root — агент как LaunchDaemon, при ручном запуске `sudo`. Чистить ifconfig/маршруты при выходе.
2. **MTU 1420**: за PPPoE/LTE может понадобиться 1400/1380 (knob в конфиге). Симптом: SSH коннектится и виснет, мелкие пинги ходят.
3. **Symmetric NAT**: observed-mapping хаба не валиден для других адресатов → punching не выйдет → остаёмся на relay (by design), `kai netcheck` объяснит почему.
4. **Ротация IP у VPS**: агенты получат новый endpoint хаба через netmap (координатор — по конфигному адресу), но **конфиги static peers придётся перегенерить** — либо завести DNS-имя для хаба.
5. **Координатор упал** — data plane живёт: WG-конфиг применён, агенты держат кэш netmap на диске и ретраят long-poll. Явно тестируем в M1.
6. **Cryptokey routing footgun**: одинаковый префикс у двух пиров тихо «переезжает» — netmap считается только на координаторе, агент применяет атомарно.
7. **Cloud-firewall провайдера** должен пропускать udp/51820 — классический тихий фейл.
8. **RAM 1 GB вместе с xray**: следить за памятью координатора (ожидаемо <50 MB); zabbix уже есть — можно повесить триггер.

## Верификация (сквозная, после M1)

1. На VPS: `systemctl status kai-coordinator kai-agent`, `wg show` — интерфейс поднят.
2. На Mac: `sudo kai-agent up --coordinator https://vpn.example.com:8443 --token ... --fingerprint ...` → `ping 100.87.0.1`.
3. Домашний Linux-сервер за NAT enroll'ится тем же способом → с Mac `ssh user@100.87.0.3` **при закрытых inbound-портах на сервере** (проверить `ss -tulnp` — только outbound).
4. Kill coordinator → SSH-сессия живёт, новые соединения по оверлею работают.
5. `kai node delete` → пир исчезает из `wg show` хаба за ≤60 с (long-poll).
