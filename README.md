# SRE Practice: Kubernetes, Observability & Reliability

Репозиторий содержит практические задания по курсу **Site Reliability Engineering**, посвящённые эксплуатации и надёжности приложений в Kubernetes.

## Что реализовано
- Деплой и публикация приложения Oncall в Kubernetes через **Ingress** (маршрутизация, таймауты, балансировка, sticky sessions).
- Практика стратегий развёртывания: **Recreate, Rolling Update, Blue/Green, Canary** с трафиком во время обновлений.
- Настройка **логирования** и доставка логов в **Sage Observability** (Vector, JSON-логи).
- Экспорт и сбор **Prometheus-метрик**, интеграция с Sage.
- Формирование **SLI / SLO / SLA**, реализация проберов доступности и расчёт SLA.
- Визуализация метрик и SLA в **Grafana**, демонстрация деградации надёжности.
- Настройка **алертов** с уведомлениями в Telegram (реализовано через UI Sage).

## Технологии
Kubernetes, Nginx Ingress, Prometheus, Grafana, Sage Observability, Vector, Docker.

Репозиторий используется в учебных целях для демонстрации SRE-практик.
