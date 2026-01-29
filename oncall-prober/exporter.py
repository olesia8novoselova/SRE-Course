#!/usr/bin/env python3

import sys
import logging
import requests
import signal
import time
import uuid
from environs import Env
from prometheus_client import start_http_server, Gauge, Counter

# метрики сценария создания пользователя
PROBER_CREATE_USER_SCENARIO_TOTAL = Counter(
    "prober_create_user_scenario_total",
    "Total runs of create user scenario to OnCall API",
)
PROBER_CREATE_USER_SCENARIO_SUCCESS_TOTAL = Counter(
    "prober_create_user_scenario_success_total",
    "Total successful runs of create user scenario to OnCall API",
)
PROBER_CREATE_USER_SCENARIO_FAIL_TOTAL = Counter(
    "prober_create_user_scenario_fail_total",
    "Total failed runs of create user scenario to OnCall API",
)
PROBER_CREATE_USER_SCENARIO_DURATION_SECONDS = Gauge(
    "prober_create_user_scenario_duration_seconds",
    "Duration in seconds of the last create user run",
)

PROBER_CREATE_USER_LAST_CREATE_STATUS = Gauge(
    "prober_create_user_last_create_status",
    "HTTP status of the last create user request",
)
PROBER_CREATE_USER_LAST_DELETE_STATUS = Gauge(
    "prober_create_user_last_delete_status",
    "HTTP status of the last delete user request",
)

# метрики сценария создания дежурства
PROBER_CREATE_EVENT_SCENARIO_TOTAL = Counter(
    "prober_create_event_scenario_total",
    "Total runs of create event scenario to OnCall API",
)
PROBER_CREATE_EVENT_SCENARIO_SUCCESS_TOTAL = Counter(
    "prober_create_event_scenario_success_total",
    "Total successful runs of create event scenario to OnCall API",
)
PROBER_CREATE_EVENT_SCENARIO_FAIL_TOTAL = Counter(
    "prober_create_event_scenario_fail_total",
    "Total failed runs of create event scenario to OnCall API",
)
PROBER_CREATE_EVENT_SCENARIO_DURATION_SECONDS = Gauge(
    "prober_create_event_scenario_duration_seconds",
    "Duration in seconds of the last create event run",
)

PROBER_CREATE_EVENT_LAST_CREATE_STATUS = Gauge(
    "prober_create_event_last_create_status",
    "HTTP status of the last create event request",
)
PROBER_CREATE_EVENT_LAST_DELETE_STATUS = Gauge(
    "prober_create_event_last_delete_status",
    "HTTP status of the last delete event request",
)

# метрика статуса health
PROBER_HEALTH_LAST_STATUS = Gauge(
    "prober_health_last_status",
    "HTTP status of the last health check",
)

env = Env()
env.read_env()


class Config(object):
    oncall_exporter_api_url = env("ONCALL_EXPORTER_API_URL", "http://oncall:8080").rstrip("/")
    oncall_exporter_scrape_interval = env.int("ONCALL_EXPORTER_SCRAPE_INTERVAL", 30)
    oncall_exporter_log_level = env.log_level("ONCALL_EXPORTER_LOG_LEVEL", logging.INFO)
    oncall_exporter_metrics_port = env.int("ONCALL_EXPORTER_METRICS_PORT", 9081)
    oncall_exporter_timeout = env.int("ONCALL_EXPORTER_HTTP_TIMEOUT", 5)

    # параметры для событий
    oncall_exporter_event_user = env("ONCALL_EXPORTER_EVENT_USER", "")
    oncall_exporter_event_team = env("ONCALL_EXPORTER_EVENT_TEAM", "")
    oncall_exporter_event_role = env("ONCALL_EXPORTER_EVENT_ROLE", "primary")


HEALTH_CANDIDATES = ("/healthcheck", "/health", "/metrics")
USERS_CANDIDATES = ("/api/v0/users",)
EVENTS_CANDIDATES = ("/api/v0/events",)


class OncallProberClient:
    def __init__(self, config: Config) -> None:
        # базовый URL и таймаут
        self.base = config.oncall_exporter_api_url
        self.timeout = config.oncall_exporter_timeout

        # HTTP-сессия
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})

        logging.info("Auth mode: NONE")

        self._users_path = None
        self._events_path = None
        self._health_path = None

        # параметры для событий
        self.event_user = config.oncall_exporter_event_user.strip()
        self.event_team = config.oncall_exporter_event_team.strip()
        self.event_role = config.oncall_exporter_event_role.strip() or "primary"

    def _url(self, path: str) -> str:
        # абсолютный URL
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if path.startswith("/"):
            return f"{self.base}{path}"
        return f"{self.base}/{path}"

    def _try_paths(self, candidates):
        for p in candidates:
            url = self._url(p)
            try:
                r = self.session.get(url, timeout=self.timeout)
                if r.status_code != 404:
                    return p, r.status_code
            except Exception:
                pass
        return None, None

    def ensure_health_path(self):
        # health endpoint
        if self._health_path is not None:
            return self._health_path
        p, code = self._try_paths(HEALTH_CANDIDATES)
        if p:
            logging.info("Health path detected: %s (first status=%s)", p, code)
            self._health_path = p
        else:
            logging.warning("No working health path found among: %s", HEALTH_CANDIDATES)
            self._health_path = None
        return self._health_path

    def ensure_users_path(self):
        # users endpoint
        if self._users_path is not None:
            return self._users_path
        p, code = self._try_paths(USERS_CANDIDATES)
        if p:
            logging.info("Users path detected: %s (first status=%s)", p, code)
            self._users_path = p
        else:
            logging.warning("No working users path found among: %s", USERS_CANDIDATES)
            self._users_path = None
        return self._users_path

    def ensure_events_path(self):
        # events endpoint
        if self._events_path is not None:
            return self._events_path
        p, code = self._try_paths(EVENTS_CANDIDATES)
        if p:
            logging.info("Events path detected: %s (first status=%s)", p, code)
            self._events_path = p
        else:
            logging.warning("No working events path found among: %s", EVENTS_CANDIDATES)
            self._events_path = None
        return self._events_path

    def health_check(self):
        # health-check oncall
        path = self.ensure_health_path()
        status = 0
        if path:
            url = self._url(path)
            try:
                r = self.session.get(url, timeout=self.timeout)
                status = r.status_code
            except Exception:
                status = 0
        PROBER_HEALTH_LAST_STATUS.set(float(status))

    def probe_create_user(self) -> None:
        # сценарий: создание и удаление пользователя
        PROBER_CREATE_USER_SCENARIO_TOTAL.inc()
        username = f"test_prober_user_{uuid.uuid4().hex[:8]}"
        start = time.perf_counter()
        create_status = 0
        delete_status = 0

        users_path = self.ensure_users_path()
        if not users_path:
            PROBER_CREATE_USER_SCENARIO_FAIL_TOTAL.inc()
            PROBER_CREATE_USER_SCENARIO_DURATION_SECONDS.set(time.perf_counter() - start)
            PROBER_CREATE_USER_LAST_CREATE_STATUS.set(float(create_status))
            PROBER_CREATE_USER_LAST_DELETE_STATUS.set(float(delete_status))
            return

        try:
            create_resp = self.session.post(
                self._url(users_path),
                json={"name": username},
                timeout=self.timeout,
            )
            create_status = create_resp.status_code
            logging.info("Create user '%s' -> %s", username, create_status)
        except Exception as e:
            logging.warning("Create user failed: %s", e)

        try:
            r = self.session.delete(
                self._url(f"{users_path.rstrip('/')}/{username}"),
                timeout=self.timeout,
            )
            delete_status = r.status_code
            logging.info("Delete user '%s' -> %s", username, delete_status)
        except Exception as e:
            logging.warning("Delete user failed: %s", e)

        ok = (create_status == 201) and (200 <= delete_status < 300)
        if ok:
            PROBER_CREATE_USER_SCENARIO_SUCCESS_TOTAL.inc()
        else:
            PROBER_CREATE_USER_SCENARIO_FAIL_TOTAL.inc()

        PROBER_CREATE_USER_SCENARIO_DURATION_SECONDS.set(time.perf_counter() - start)
        PROBER_CREATE_USER_LAST_CREATE_STATUS.set(float(create_status))
        PROBER_CREATE_USER_LAST_DELETE_STATUS.set(float(delete_status))

    def _parse_event_id(self, resp: requests.Response):
        # id события из текстового тела
        text = (resp.text or "").strip()
        try:
            return int(text)
        except (TypeError, ValueError):
            return None

    def probe_create_event(self) -> None:
        # сценарий: создание и удаление дежурства
        PROBER_CREATE_EVENT_SCENARIO_TOTAL.inc()
        start = time.perf_counter()
        create_status = 0
        delete_status = 0

        if not self.event_user or not self.event_team:
            logging.warning(
                "Event scenario disabled: ONCALL_EXPORTER_EVENT_USER or "
                "ONCALL_EXPORTER_EVENT_TEAM is empty"
            )
            PROBER_CREATE_EVENT_SCENARIO_FAIL_TOTAL.inc()
            PROBER_CREATE_EVENT_SCENARIO_DURATION_SECONDS.set(time.perf_counter() - start)
            PROBER_CREATE_EVENT_LAST_CREATE_STATUS.set(float(create_status))
            PROBER_CREATE_EVENT_LAST_DELETE_STATUS.set(float(delete_status))
            return

        events_path = self.ensure_events_path()
        if not events_path:
            PROBER_CREATE_EVENT_SCENARIO_FAIL_TOTAL.inc()
            PROBER_CREATE_EVENT_SCENARIO_DURATION_SECONDS.set(time.perf_counter() - start)
            PROBER_CREATE_EVENT_LAST_CREATE_STATUS.set(float(create_status))
            PROBER_CREATE_EVENT_LAST_DELETE_STATUS.set(float(delete_status))
            return

        now = int(time.time())
        event_start = now
        event_end = now + 3600

        event_id = None

        try:
            create_resp = self.session.post(
                self._url(events_path),
                json={
                    "start": event_start,
                    "end": event_end,
                    "user": self.event_user,
                    "team": self.event_team,
                    "role": self.event_role,
                },
                timeout=self.timeout,
            )
            create_status = create_resp.status_code
            logging.info(
                "Create event user='%s' team='%s' role='%s' -> %s",
                self.event_user,
                self.event_team,
                self.event_role,
                create_status,
            )
            if create_status == 201:
                event_id = self._parse_event_id(create_resp)
        except Exception as e:
            logging.warning("Create event failed: %s", e)

        if event_id is not None:
            try:
                r = self.session.delete(
                    self._url(f"{events_path.rstrip('/')}/{event_id}"),
                    timeout=self.timeout,
                )
                delete_status = r.status_code
                logging.info("Delete event id=%s -> %s", event_id, delete_status)
            except Exception as e:
                logging.warning("Delete event failed: %s", e)

        ok = (create_status == 201) and (event_id is not None) and (200 <= delete_status < 300)
        if ok:
            PROBER_CREATE_EVENT_SCENARIO_SUCCESS_TOTAL.inc()
        else:
            PROBER_CREATE_EVENT_SCENARIO_FAIL_TOTAL.inc()

        PROBER_CREATE_EVENT_SCENARIO_DURATION_SECONDS.set(time.perf_counter() - start)
        PROBER_CREATE_EVENT_LAST_CREATE_STATUS.set(float(create_status))
        PROBER_CREATE_EVENT_LAST_DELETE_STATUS.set(float(delete_status))

    def probe(self) -> None:
        # основной сценарий пробера
        self.health_check()
        self.probe_create_user()
        self.probe_create_event()


def setup_logging(config: Config):
    logging.basicConfig(
        stream=sys.stdout,
        level=config.oncall_exporter_log_level,
        format="%(asctime)s %(levelname)s:%(message)s",
    )


def main():
    config = Config()
    setup_logging(config)
    logging.info(
        "Starting prober on port %s; base URL=%s",
        config.oncall_exporter_metrics_port,
        config.oncall_exporter_api_url,
    )

    start_http_server(config.oncall_exporter_metrics_port, addr="0.0.0.0")

    client = OncallProberClient(config)

    def terminate(_signal, _frame):
        logging.info("Terminating")
        sys.exit(0)

    signal.signal(signal.SIGTERM, terminate)

    period = float(config.oncall_exporter_scrape_interval)
    next_tick = time.monotonic()
    while True:
        client.probe()
        next_tick += period
        time.sleep(max(0.0, next_tick - time.monotonic()))


if __name__ == "__main__":
    main()