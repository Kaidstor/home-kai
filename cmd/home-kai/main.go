// home-kai is the admin CLI for the coordinator.
//
// Admin commands talk to the coordinator admin API with the settings from
// ~/.config/kai/admin.json (`home-kai login`) overlaid by KAI_* env vars; the
// token comes from $KAI_ADMIN_TOKEN, sec (token_ref) or, legacy, the file.
// `status`, `ping` and `agent` talk to the local kai-agent instead and need
// no credentials. Output is text by default, the kai CLI envelope with --json
// (internal/output), exit codes are in internal/exit.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kaidstor/home-kai/internal/exit"
	"github.com/kaidstor/home-kai/internal/output"
)

// commandTimeout bounds a whole command; the API client alone waits up to
// 70s per request.
const commandTimeout = 2 * time.Minute

const usage = `home-kai — админский CLI оверлей-сети home-kai: координатор и локальный kai-agent

Использование:
  home-kai <команда> [аргументы] [--json]

Сеть (admin API координатора, нужен токен):
  token create [--name <имя>] [--ttl <сек>]    одноразовый enroll-токен и готовая join-команда
                                               (ttl по умолчанию 3600)
  node list                                    узлы: id, имя, роль, ОС, overlay-IP, DNS, последний контакт
  node delete <node_id>
  node routes <node_id> --enable <CIDR,CIDR>   включить подсети из анонсированных узлом;
                                               --enable "" выключает все
  node approve <node_id>                       одобрить узел (при require_approval = true)
  node tag <node_id> --tags <a,b>              теги для ACL; пустое значение очищает
  peer create <имя> [--png <файл>] [--full]    static peer (телефон, роутер): конфиг WireGuard и QR;
                                               --full — весь трафик через хаб
  peer list
  peer tag <peer_id> --tags <a,b>
  policy list
  policy create <имя> [--from <теги>] [--to <теги>] [--proto any|tcp|udp|icmp] [--ports <22,443>] [--disabled]
                                               пустые --from/--to — любой узел
  policy delete <id>
  events [--limit <N>]                         журнал координатора (по умолчанию 50 последних)
  lock init|sign|status|disable [--key <файл>] network lock: подписанные привязки пиров;
                                               ключ по умолчанию ~/.config/kai/lock.key

Эта машина (сокет kai-agent, токен не нужен):
  status                                       пиры, путь direct/relay, handshake, трафик
  ping <имя|ip>                                резолв имени, путь до пира и три пинга
  agent up|down|status                         запуск и остановка службы kai-agent
                                               (launchd/systemd; up и down перезапускаются через sudo)

Служебное:
  login --url <URL> --fingerprint <HEX> [--token-ref <проект>/<KEY>]
                                               проверить доступ к координатору и сохранить настройки;
                                               без --token-ref токен читается из stdin и ложится
                                               в файл открытым текстом
  logout                                       удалить файл настроек
  doctor                                       настройки, источник токена, доступ к координатору

Настройки — ~/.config/kai/admin.json (url, fingerprint, token_ref), путь меняет $HOME_KAI_CONFIG,
поверх файла — переменные KAI_URL, KAI_FINGERPRINT, KAI_TOKEN_REF. Токен ищется по порядку:
$KAI_ADMIN_TOKEN, sec get <token_ref>, поле token в файле (устаревшее, doctor о нём предупреждает).
В argv токен не попадает. Отпечаток TLS обязателен: journalctl -u kai-coordinator | grep fingerprint.

Общие флаги:
  --json                                       JSON-конверт {v, command, exit, data, warning, error}
                                               в stdout, отказы тоже
  --human                                      текст (по умолчанию)
  -h, --help                                   справка

Коды выхода:
  0 сделано
  1 ответ есть, результата нет: ping без ответов, служба kai-agent не поднялась или не
    остановилась, network lock не инициализирован
  2 ошибка инструмента, аргументов, настроек или токена
  3 не найдено: узел, пир, политика, устройство, служба kai-agent
  4 координатор не ответил в срок; читающие команды можно повторить, изменяющие — сначала
    сверить результат списком`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	jsonMode, args := splitGlobalFlags(args)

	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Println(usage)
		return exit.OK
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()

	p := output.New(jsonMode)
	name, rest := args[0], args[1:]
	sub := ""
	if len(rest) > 0 {
		sub = rest[0]
	}

	switch {
	case name == "token" && sub == "create":
		return cmdTokenCreate(ctx, p, rest[1:])
	case name == "node" && sub == "list":
		return cmdNodeList(ctx, p, rest[1:])
	case name == "node" && sub == "delete":
		return cmdNodeDelete(ctx, p, rest[1:])
	case name == "node" && sub == "routes":
		return cmdNodeRoutes(ctx, p, rest[1:])
	case name == "node" && sub == "approve":
		return cmdNodeApprove(ctx, p, rest[1:])
	case name == "node" && sub == "tag":
		return cmdNodeTag(ctx, p, rest[1:])
	case name == "policy":
		return cmdPolicy(ctx, p, rest)
	case name == "events":
		return cmdEvents(ctx, p, rest)
	case name == "peer" && sub == "create":
		return cmdPeerCreate(ctx, p, rest[1:])
	case name == "peer" && sub == "list":
		return cmdPeerList(ctx, p, rest[1:])
	case name == "peer" && sub == "tag":
		return cmdPeerTag(ctx, p, rest[1:])
	case name == "status":
		return cmdStatus(ctx, p, rest)
	case name == "ping":
		return cmdPing(ctx, p, rest)
	case name == "agent":
		return cmdAgent(ctx, p, rest)
	case name == "lock":
		return cmdLock(ctx, p, rest)
	case name == "login":
		return cmdLogin(ctx, p, rest)
	case name == "logout":
		return cmdLogout(p, rest)
	case name == "doctor":
		return cmdDoctor(ctx, p, rest)
	case name == "token" || name == "node" || name == "peer":
		return p.Fail(name, exit.Tool, "usage",
			"неизвестная подкоманда %q; home-kai --help покажет список", name+" "+sub)
	default:
		return p.Fail("", exit.Tool, "usage",
			"неизвестная команда %q; home-kai --help покажет список", name)
	}
}
