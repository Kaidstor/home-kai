set shell := ["bash", "-cu"]
set dotenv-load := true          # локальный .env (gitignored): KAI_VPS=root@your-vps-ip

# Deploy target — override in .env or `export KAI_VPS=root@your-vps-ip`
vps := env_var_or_default("KAI_VPS", "root@vpn.example.com")
version := `git describe --tags --always --dirty 2>/dev/null || echo dev`
ldflags := "-s -w -X github.com/kaidstor/home-kai/internal/agent.Version=" + version

# Список рецептов
default:
    @just --list

# Сборка всех бинарей под текущую платформу в ./bin
build:
    CGO_ENABLED=0 go build -trimpath -ldflags "{{ldflags}}" -o bin/ ./cmd/...

# Кросс-компиляция под VPS (linux/amd64)
build-linux:
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "{{ldflags}}" -o bin/linux-amd64/ ./cmd/...

# Тесты и статический анализ
test:
    go vet ./...
    go test ./...

# Залить бинари на VPS (rsync: временный файл + rename, поэтому безопасно поверх работающего бинаря)
deploy-vps: build-linux
    rsync -az bin/linux-amd64/kai-coordinator bin/linux-amd64/kai-agent bin/linux-amd64/kai {{vps}}:/usr/local/bin/
    ssh {{vps}} 'systemctl restart kai-coordinator kai-agent 2>/dev/null || true'

# Первичная установка на VPS: конфиг-каталоги, systemd-юниты, sysctl
provision-vps:
    ssh {{vps}} 'mkdir -p /etc/kai /var/lib/kai'
    scp deploy/systemd/kai-coordinator.service deploy/systemd/kai-agent.service {{vps}}:/etc/systemd/system/
    scp deploy/sysctl/99-kai-forward.conf {{vps}}:/etc/sysctl.d/
    ssh {{vps}} 'sysctl -p /etc/sysctl.d/99-kai-forward.conf && systemctl daemon-reload'
