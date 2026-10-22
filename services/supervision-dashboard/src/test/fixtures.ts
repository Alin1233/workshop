// Incidents réels du moteur de remédiation (GET /api/incidents/{id}), relevés sur la pile locale le 20/10/2026 :
// arrêt de payment-api (redémarrage), registre corrompu (restauration par le pont), force brute (blocage d'IP).
// Seuls les identifiants aléatoires (empreintes, virements, demandes) sont remplacés par des valeurs lisibles.
import type { IncidentDetail } from "../lib/types";

export const serviceDownIncident: IncidentDetail = {
  "id": "inc-20261020-074212-d07757",
  "key": "service:payment-api",
  "alertname": "ServiceDown",
  "rule": "ServiceDown",
  "strategy": "restart",
  "nature": "availability",
  "domain": "availability",
  "severity": "critical",
  "service": "payment-api",
  "state": "recovered",
  "open": false,
  "outcome": "recovered",
  "attempts": 1,
  "created_at": "2026-10-20T07:42:12.398+00:00",
  "updated_at": "2026-10-20T07:42:42.418+00:00",
  "closed_at": "2026-10-20T07:42:42.418+00:00",
  "recovered_at": "2026-10-20T07:42:19.079+00:00",
  "alert_started_at": "2026-10-20T07:42:03.661+00:00",
  "duration_s": 6.7,
  "alerts": [
    {
      "fingerprint": "fp-1",
      "status": "resolved",
      "labels": {
        "alertname": "ServiceDown",
        "domain": "availability",
        "instance": "payment-api:8000",
        "job": "payment-api",
        "platform": "resilience-alpha",
        "service": "payment-api",
        "severity": "critical"
      },
      "annotations": {
        "summary": "payment-api ne répond plus au scrape Prometheus"
      },
      "starts_at": "2026-10-20T07:42:03.661+00:00",
      "received_at": "2026-10-20T07:42:12.398+00:00",
      "last_received_at": "2026-10-20T07:42:12.398+00:00",
      "notifications": 1,
      "ends_at": "2026-10-20T07:42:23.661+00:00",
      "resolved_received_at": "2026-10-20T07:42:42.418+00:00"
    },
    {
      "fingerprint": "fp-2",
      "status": "resolved",
      "labels": {
        "alertname": "EndToEndProbeFailed",
        "domain": "availability",
        "instance": "http://waf:8080/api/payments/health",
        "job": "blackbox-http",
        "platform": "resilience-alpha",
        "service": "payments",
        "severity": "critical"
      },
      "annotations": {
        "summary": "Le parcours client vers payments échoue (http://waf:8080/api/payments/health)"
      },
      "starts_at": "2026-10-20T07:42:03.661+00:00",
      "received_at": "2026-10-20T07:42:12.417+00:00",
      "last_received_at": "2026-10-20T07:42:12.417+00:00",
      "notifications": 1,
      "ends_at": "2026-10-20T07:42:23.661+00:00",
      "resolved_received_at": "2026-10-20T07:42:42.399+00:00"
    }
  ],
  "decision": {
    "kind": "act",
    "nature": "availability",
    "reason": "payment-api est exited : redémarrage de payment-api",
    "action": "restart",
    "service": "payment-api",
    "target": "payment-api",
    "chain": [
      "postgres",
      "payment-api"
    ],
    "limits": "restart",
    "checks": [
      "containers",
      "probes",
      "witness"
    ],
    "when_healthy": "restart",
    "symptom": "max(up{{job=\"{svc}\"}})",
    "evidence": {
      "containers": {
        "postgres": "healthy",
        "payment-api": "exited"
      }
    }
  },
  "escalation": null,
  "last_action": {
    "ts": 1792482132.6006901,
    "at": "2026-10-20T07:42:12.600+00:00",
    "action": "start",
    "target": "payment-api",
    "result": "success",
    "duration_ms": 160,
    "previous": "exited"
  },
  "actions": [
    {
      "ts": 1792482132.6006901,
      "at": "2026-10-20T07:42:12.600+00:00",
      "action": "start",
      "target": "payment-api",
      "result": "success",
      "duration_ms": 160,
      "previous": "exited"
    }
  ],
  "timeline": [
    {
      "ts": 1792482132.3986473,
      "at": "2026-10-20T07:42:12.398+00:00",
      "state": "detected",
      "event": "state:detected",
      "detail": {
        "alertname": "ServiceDown",
        "labels": {
          "alertname": "ServiceDown",
          "domain": "availability",
          "instance": "payment-api:8000",
          "job": "payment-api",
          "platform": "resilience-alpha",
          "service": "payment-api",
          "severity": "critical"
        },
        "summary": "payment-api ne répond plus au scrape Prometheus"
      }
    },
    {
      "ts": 1792482132.417269,
      "at": "2026-10-20T07:42:12.417+00:00",
      "state": "detected",
      "event": "alert:correlated",
      "detail": {
        "alertname": "EndToEndProbeFailed",
        "fingerprint": "fp-3"
      }
    },
    {
      "ts": 1792482132.4278007,
      "at": "2026-10-20T07:42:12.427+00:00",
      "state": "decided",
      "event": "state:decided",
      "detail": {
        "kind": "act",
        "nature": "availability",
        "reason": "payment-api est exited : redémarrage de payment-api",
        "action": "restart",
        "service": "payment-api",
        "target": "payment-api",
        "chain": [
          "postgres",
          "payment-api"
        ],
        "limits": "restart",
        "checks": [
          "containers",
          "probes",
          "witness"
        ],
        "when_healthy": "restart",
        "symptom": "max(up{{job=\"{svc}\"}})",
        "evidence": {
          "containers": {
            "postgres": "healthy",
            "payment-api": "exited"
          }
        }
      }
    },
    {
      "ts": 1792482132.4318342,
      "at": "2026-10-20T07:42:12.431+00:00",
      "state": "acting",
      "event": "state:acting",
      "detail": {
        "action": "restart",
        "target": "payment-api"
      }
    },
    {
      "ts": 1792482132.6006901,
      "at": "2026-10-20T07:42:12.600+00:00",
      "state": "acting",
      "event": "action:start",
      "detail": {
        "target": "payment-api",
        "result": "success",
        "previous": "exited"
      }
    },
    {
      "ts": 1792482138.6244416,
      "at": "2026-10-20T07:42:18.624+00:00",
      "state": "acting",
      "event": "container:health",
      "detail": {
        "target": "payment-api",
        "status": "healthy"
      }
    },
    {
      "ts": 1792482138.6244664,
      "at": "2026-10-20T07:42:18.624+00:00",
      "state": "verifying",
      "event": "state:verifying",
      "detail": {
        "checks": [
          "containers",
          "probes",
          "witness"
        ]
      }
    },
    {
      "ts": 1792482138.649163,
      "at": "2026-10-20T07:42:18.649+00:00",
      "state": "verifying",
      "event": "verification:containers",
      "detail": {
        "containers": {
          "postgres": "healthy",
          "payment-api": "healthy"
        },
        "result": "ok",
        "check_ms": 7
      }
    },
    {
      "ts": 1792482138.6542695,
      "at": "2026-10-20T07:42:18.654+00:00",
      "state": "verifying",
      "event": "verification:probes",
      "detail": {
        "probes": {
          "auth": 1.0,
          "frontend": 1.0,
          "payments": 1.0
        },
        "result": "ok",
        "check_ms": 1
      }
    },
    {
      "ts": 1792482139.075309,
      "at": "2026-10-20T07:42:19.075+00:00",
      "state": "verifying",
      "event": "verification:witness",
      "detail": {
        "transfer_id": "transfer-4",
        "duration_ms": 417,
        "steps": [
          {
            "step": "inscription emetteur",
            "ok": true,
            "status": 201
          },
          {
            "step": "connexion emetteur",
            "ok": true,
            "status": 200
          },
          {
            "step": "compte emetteur",
            "ok": true,
            "status": 200
          },
          {
            "step": "inscription beneficiaire",
            "ok": true,
            "status": 201
          },
          {
            "step": "connexion beneficiaire",
            "ok": true,
            "status": 200
          },
          {
            "step": "compte beneficiaire",
            "ok": true,
            "status": 200
          },
          {
            "step": "virement",
            "ok": true,
            "status": 201,
            "transfer_id": "transfer-5"
          },
          {
            "step": "soldes",
            "ok": true,
            "status": 200,
            "balances": {
              "emetteur": 99900,
              "beneficiaire": 100100
            }
          }
        ],
        "result": "ok",
        "check_ms": 417
      }
    },
    {
      "ts": 1792482139.079062,
      "at": "2026-10-20T07:42:19.079+00:00",
      "state": "recovered",
      "event": "state:recovered",
      "detail": {
        "reason": "vérification réussie"
      }
    },
    {
      "ts": 1792482162.3994448,
      "at": "2026-10-20T07:42:42.399+00:00",
      "state": "recovered",
      "event": "alert:resolved",
      "detail": {
        "alertname": "EndToEndProbeFailed"
      }
    },
    {
      "ts": 1792482162.418151,
      "at": "2026-10-20T07:42:42.418+00:00",
      "state": "recovered",
      "event": "alert:resolved",
      "detail": {
        "alertname": "ServiceDown"
      }
    },
    {
      "ts": 1792482162.4182298,
      "at": "2026-10-20T07:42:42.418+00:00",
      "state": "recovered",
      "event": "closed",
      "detail": {
        "outcome": "recovered"
      }
    }
  ]
};

export const restoreIncident: IncidentDetail = {
  "id": "inc-20261020-091218-591df5",
  "key": "integrity:payment-api",
  "alertname": "LedgerIntegrityBroken",
  "rule": "LedgerIntegrityBroken",
  "strategy": "integrity_restore",
  "nature": "compromise",
  "domain": "integrity",
  "severity": "critical",
  "service": "payment-api",
  "state": "recovered",
  "open": false,
  "outcome": "recovered",
  "attempts": 1,
  "created_at": "2026-10-20T09:12:18.073+00:00",
  "updated_at": "2026-10-20T09:14:52.515+00:00",
  "closed_at": "2026-10-20T09:14:52.515+00:00",
  "recovered_at": "2026-10-20T09:12:30.061+00:00",
  "alert_started_at": "2026-10-20T09:12:09.337+00:00",
  "duration_s": 12.0,
  "alerts": [
    {
      "fingerprint": "fp-6",
      "status": "resolved",
      "labels": {
        "alertname": "LedgerIntegrityBroken",
        "domain": "integrity",
        "instance": "payment-api:8000",
        "job": "payment-api",
        "platform": "resilience-alpha",
        "service": "payment-api",
        "severity": "critical"
      },
      "annotations": {
        "summary": "Le registre de paiement est incohérent (voir /internal/integrity)"
      },
      "starts_at": "2026-10-20T09:12:09.337+00:00",
      "received_at": "2026-10-20T09:12:18.073+00:00",
      "last_received_at": "2026-10-20T09:12:18.073+00:00",
      "notifications": 1,
      "ends_at": "2026-10-20T09:12:29.337+00:00",
      "resolved_received_at": "2026-10-20T09:12:48.074+00:00"
    },
    {
      "fingerprint": "fp-7",
      "status": "resolved",
      "labels": {
        "alertname": "LedgerIntegrityViolationLogged",
        "compose_project": "resilience-alpha",
        "detected_level": "error",
        "domain": "integrity",
        "event_type": "integrity_violation",
        "level": "error",
        "service": "payment-api",
        "service_name": "payment-api",
        "severity": "critical",
        "stream": "stdout"
      },
      "annotations": {
        "summary": "Violation d'intégrité du registre journalisée par payment-api"
      },
      "starts_at": "2026-10-20T09:12:15.442+00:00",
      "received_at": "2026-10-20T09:12:22.510+00:00",
      "last_received_at": "2026-10-20T09:12:22.510+00:00",
      "notifications": 1,
      "ends_at": "2026-10-20T09:14:30.442+00:00",
      "resolved_received_at": "2026-10-20T09:14:52.515+00:00"
    }
  ],
  "decision": {
    "kind": "act",
    "nature": "compromise",
    "reason": "corruption confirmée (PostgreSQL sain, /internal/integrity = 409) : restauration de la dernière sauvegarde saine",
    "action": "restore_db",
    "service": "payment-api",
    "target": "paydb",
    "chain": [
      "postgres",
      "auth-service",
      "payment-api"
    ],
    "limits": "restore",
    "checks": [
      "containers",
      "integrity",
      "probes",
      "witness"
    ],
    "when_healthy": "restart",
    "evidence": {
      "postgres": "healthy",
      "integrity_status": 409,
      "checks": {
        "ledger_sum_is_zero": true,
        "balances_match_ledger": false,
        "transfers_balanced": true,
        "no_negative_balance": true
      }
    }
  },
  "escalation": null,
  "last_action": {
    "ts": 1792487549.646047,
    "at": "2026-10-20T09:12:29.646+00:00",
    "action": "restore_db",
    "target": "paydb",
    "result": "success",
    "duration_ms": 11514,
    "restore": {
      "backup_age_seconds": 118,
      "backup_created_at": "2026-10-20T09:10:31Z",
      "restore_seconds": 10.4,
      "restored": "20261020T091030Z-manual",
      "request_id": "request-8",
      "status": "restored"
    },
    "bridge_duration_s": 11.5
  },
  "actions": [
    {
      "ts": 1792487549.646047,
      "at": "2026-10-20T09:12:29.646+00:00",
      "action": "restore_db",
      "target": "paydb",
      "result": "success",
      "duration_ms": 11514,
      "restore": {
        "backup_age_seconds": 118,
        "backup_created_at": "2026-10-20T09:10:31Z",
        "restore_seconds": 10.4,
        "restored": "20261020T091030Z-manual",
        "request_id": "request-9",
        "status": "restored"
      },
      "bridge_duration_s": 11.5
    }
  ],
  "timeline": [
    {
      "ts": 1792487538.0737793,
      "at": "2026-10-20T09:12:18.073+00:00",
      "state": "detected",
      "event": "state:detected",
      "detail": {
        "alertname": "LedgerIntegrityBroken",
        "labels": {
          "alertname": "LedgerIntegrityBroken",
          "domain": "integrity",
          "instance": "payment-api:8000",
          "job": "payment-api",
          "platform": "resilience-alpha",
          "service": "payment-api",
          "severity": "critical"
        },
        "summary": "Le registre de paiement est incohérent (voir /internal/integrity)"
      }
    },
    {
      "ts": 1792487538.1085815,
      "at": "2026-10-20T09:12:18.108+00:00",
      "state": "decided",
      "event": "state:decided",
      "detail": {
        "kind": "act",
        "nature": "compromise",
        "reason": "corruption confirmée (PostgreSQL sain, /internal/integrity = 409) : restauration de la dernière sauvegarde saine",
        "action": "restore_db",
        "service": "payment-api",
        "target": "paydb",
        "chain": [
          "postgres",
          "auth-service",
          "payment-api"
        ],
        "limits": "restore",
        "checks": [
          "containers",
          "integrity",
          "probes",
          "witness"
        ],
        "when_healthy": "restart",
        "evidence": {
          "postgres": "healthy",
          "integrity_status": 409,
          "checks": {
            "ledger_sum_is_zero": true,
            "balances_match_ledger": false,
            "transfers_balanced": true,
            "no_negative_balance": true
          }
        }
      }
    },
    {
      "ts": 1792487538.116182,
      "at": "2026-10-20T09:12:18.116+00:00",
      "state": "acting",
      "event": "state:acting",
      "detail": {
        "action": "restore_db",
        "target": "paydb"
      }
    },
    {
      "ts": 1792487538.1321883,
      "at": "2026-10-20T09:12:18.132+00:00",
      "state": "acting",
      "event": "restore:requested",
      "detail": {
        "reason": "demande déposée au pont hôte (resilience-pg-restore)"
      }
    },
    {
      "ts": 1792487542.510432,
      "at": "2026-10-20T09:12:22.510+00:00",
      "state": "acting",
      "event": "alert:correlated",
      "detail": {
        "alertname": "LedgerIntegrityViolationLogged",
        "fingerprint": "fp-10"
      }
    },
    {
      "ts": 1792487549.646047,
      "at": "2026-10-20T09:12:29.646+00:00",
      "state": "acting",
      "event": "action:restore_db",
      "detail": {
        "target": "paydb",
        "result": "success",
        "restore": {
          "backup_age_seconds": 118,
          "backup_created_at": "2026-10-20T09:10:31Z",
          "restore_seconds": 10.4,
          "restored": "20261020T091030Z-manual",
          "request_id": "request-11",
          "status": "restored"
        },
        "bridge_duration_s": 11.5
      }
    },
    {
      "ts": 1792487549.6706488,
      "at": "2026-10-20T09:12:29.670+00:00",
      "state": "verifying",
      "event": "state:verifying",
      "detail": {
        "checks": [
          "containers",
          "integrity",
          "probes",
          "witness"
        ]
      }
    },
    {
      "ts": 1792487549.686459,
      "at": "2026-10-20T09:12:29.686+00:00",
      "state": "verifying",
      "event": "verification:containers",
      "detail": {
        "containers": {
          "postgres": "healthy",
          "auth-service": "healthy",
          "payment-api": "healthy"
        },
        "result": "ok",
        "check_ms": 9
      }
    },
    {
      "ts": 1792487549.7039084,
      "at": "2026-10-20T09:12:29.703+00:00",
      "state": "verifying",
      "event": "verification:integrity",
      "detail": {
        "status": 200,
        "checks": {
          "ledger_sum_is_zero": true,
          "balances_match_ledger": true,
          "transfers_balanced": true,
          "no_negative_balance": true
        },
        "result": "ok",
        "check_ms": 10
      }
    },
    {
      "ts": 1792487549.7126467,
      "at": "2026-10-20T09:12:29.712+00:00",
      "state": "verifying",
      "event": "verification:probes",
      "detail": {
        "probes": {
          "auth": 1.0,
          "frontend": 1.0,
          "payments": 1.0
        },
        "result": "ok",
        "check_ms": 1
      }
    },
    {
      "ts": 1792487550.0529912,
      "at": "2026-10-20T09:12:30.052+00:00",
      "state": "verifying",
      "event": "verification:witness",
      "detail": {
        "transfer_id": "transfer-12",
        "duration_ms": 333,
        "steps": [
          {
            "step": "inscription emetteur",
            "ok": true,
            "status": 201
          },
          {
            "step": "connexion emetteur",
            "ok": true,
            "status": 200
          },
          {
            "step": "compte emetteur",
            "ok": true,
            "status": 200
          },
          {
            "step": "inscription beneficiaire",
            "ok": true,
            "status": 201
          },
          {
            "step": "connexion beneficiaire",
            "ok": true,
            "status": 200
          },
          {
            "step": "compte beneficiaire",
            "ok": true,
            "status": 200
          },
          {
            "step": "virement",
            "ok": true,
            "status": 201,
            "transfer_id": "transfer-13"
          },
          {
            "step": "soldes",
            "ok": true,
            "status": 200,
            "balances": {
              "emetteur": 99900,
              "beneficiaire": 100100
            }
          }
        ],
        "result": "ok",
        "check_ms": 333
      }
    },
    {
      "ts": 1792487550.0610604,
      "at": "2026-10-20T09:12:30.061+00:00",
      "state": "recovered",
      "event": "state:recovered",
      "detail": {
        "reason": "vérification réussie"
      }
    },
    {
      "ts": 1792487568.0742996,
      "at": "2026-10-20T09:12:48.074+00:00",
      "state": "recovered",
      "event": "alert:resolved",
      "detail": {
        "alertname": "LedgerIntegrityBroken"
      }
    },
    {
      "ts": 1792487692.515792,
      "at": "2026-10-20T09:14:52.515+00:00",
      "state": "recovered",
      "event": "alert:resolved",
      "detail": {
        "alertname": "LedgerIntegrityViolationLogged"
      }
    },
    {
      "ts": 1792487692.5159385,
      "at": "2026-10-20T09:14:52.515+00:00",
      "state": "recovered",
      "event": "closed",
      "detail": {
        "outcome": "recovered"
      }
    }
  ]
};

export const bruteForceIncident: IncidentDetail = {
  "id": "inc-20261020-090552-34f895",
  "key": "ip:172.25.0.3",
  "alertname": "AuthBruteForce",
  "rule": "AuthBruteForce",
  "strategy": "block_alert_ip",
  "nature": "compromise",
  "domain": "security",
  "severity": "warning",
  "service": "auth-service",
  "state": "recovered",
  "open": false,
  "outcome": "recovered",
  "attempts": 1,
  "created_at": "2026-10-20T09:05:52.508+00:00",
  "updated_at": "2026-10-20T09:06:52.509+00:00",
  "closed_at": "2026-10-20T09:06:52.509+00:00",
  "recovered_at": "2026-10-20T09:05:53.508+00:00",
  "alert_started_at": "2026-10-20T09:05:45.442+00:00",
  "duration_s": 1.0,
  "alerts": [
    {
      "fingerprint": "fp-14",
      "status": "resolved",
      "labels": {
        "alertname": "AuthBruteForce",
        "client_ip": "172.25.0.3",
        "domain": "security",
        "service": "auth-service",
        "severity": "warning"
      },
      "annotations": {
        "summary": "Force brute probable depuis 172.25.0.3 (plus de 10 échecs en 1 min)"
      },
      "starts_at": "2026-10-20T09:05:45.442+00:00",
      "received_at": "2026-10-20T09:05:52.508+00:00",
      "last_received_at": "2026-10-20T09:05:52.508+00:00",
      "notifications": 1,
      "ends_at": "2026-10-20T09:06:45.442+00:00",
      "resolved_received_at": "2026-10-20T09:06:52.509+00:00"
    }
  ],
  "decision": {
    "kind": "act",
    "nature": "compromise",
    "reason": "IP portée par AuthBruteForce : blocage de 172.25.0.3 au WAF (90 s)",
    "action": "block_ip",
    "target": "172.25.0.3",
    "limits": "block",
    "checks": [
      "waf_block",
      "probes",
      "witness"
    ],
    "when_healthy": "restart"
  },
  "escalation": null,
  "last_action": {
    "ts": 1792487152.5613449,
    "at": "2026-10-20T09:05:52.561+00:00",
    "action": "block_ip",
    "target": "172.25.0.3",
    "result": "success",
    "duration_ms": 16,
    "expires_at": "2026-10-20T09:07:22.545+00:00",
    "ttl_s": 90
  },
  "actions": [
    {
      "ts": 1792487152.5613449,
      "at": "2026-10-20T09:05:52.561+00:00",
      "action": "block_ip",
      "target": "172.25.0.3",
      "result": "success",
      "duration_ms": 16,
      "expires_at": "2026-10-20T09:07:22.545+00:00",
      "ttl_s": 90
    }
  ],
  "timeline": [
    {
      "ts": 1792487152.5080898,
      "at": "2026-10-20T09:05:52.508+00:00",
      "state": "detected",
      "event": "state:detected",
      "detail": {
        "alertname": "AuthBruteForce",
        "labels": {
          "alertname": "AuthBruteForce",
          "client_ip": "172.25.0.3",
          "domain": "security",
          "service": "auth-service",
          "severity": "warning"
        },
        "summary": "Force brute probable depuis 172.25.0.3 (plus de 10 échecs en 1 min)"
      }
    },
    {
      "ts": 1792487152.5308096,
      "at": "2026-10-20T09:05:52.530+00:00",
      "state": "decided",
      "event": "state:decided",
      "detail": {
        "kind": "act",
        "nature": "compromise",
        "reason": "IP portée par AuthBruteForce : blocage de 172.25.0.3 au WAF (90 s)",
        "action": "block_ip",
        "target": "172.25.0.3",
        "limits": "block",
        "checks": [
          "waf_block",
          "probes",
          "witness"
        ],
        "when_healthy": "restart"
      }
    },
    {
      "ts": 1792487152.5381386,
      "at": "2026-10-20T09:05:52.538+00:00",
      "state": "acting",
      "event": "state:acting",
      "detail": {
        "action": "block_ip",
        "target": "172.25.0.3"
      }
    },
    {
      "ts": 1792487152.5613449,
      "at": "2026-10-20T09:05:52.561+00:00",
      "state": "acting",
      "event": "action:block_ip",
      "detail": {
        "target": "172.25.0.3",
        "result": "success",
        "expires_at": "2026-10-20T09:07:22.545+00:00",
        "ttl_s": 90
      }
    },
    {
      "ts": 1792487152.567848,
      "at": "2026-10-20T09:05:52.567+00:00",
      "state": "verifying",
      "event": "state:verifying",
      "detail": {
        "checks": [
          "waf_block",
          "probes",
          "witness"
        ]
      }
    },
    {
      "ts": 1792487153.0886393,
      "at": "2026-10-20T09:05:53.088+00:00",
      "state": "verifying",
      "event": "verification:waf_block",
      "detail": {
        "ip": "172.25.0.3",
        "result": "ok",
        "check_ms": 515
      }
    },
    {
      "ts": 1792487153.1101828,
      "at": "2026-10-20T09:05:53.110+00:00",
      "state": "verifying",
      "event": "verification:probes",
      "detail": {
        "probes": {
          "auth": 1.0,
          "frontend": 1.0,
          "payments": 1.0
        },
        "result": "ok",
        "check_ms": 2
      }
    },
    {
      "ts": 1792487153.502342,
      "at": "2026-10-20T09:05:53.502+00:00",
      "state": "verifying",
      "event": "verification:witness",
      "detail": {
        "transfer_id": "transfer-15",
        "duration_ms": 386,
        "steps": [
          {
            "step": "inscription emetteur",
            "ok": true,
            "status": 201
          },
          {
            "step": "connexion emetteur",
            "ok": true,
            "status": 200
          },
          {
            "step": "compte emetteur",
            "ok": true,
            "status": 200
          },
          {
            "step": "inscription beneficiaire",
            "ok": true,
            "status": 201
          },
          {
            "step": "connexion beneficiaire",
            "ok": true,
            "status": 200
          },
          {
            "step": "compte beneficiaire",
            "ok": true,
            "status": 200
          },
          {
            "step": "virement",
            "ok": true,
            "status": 201,
            "transfer_id": "transfer-16"
          },
          {
            "step": "soldes",
            "ok": true,
            "status": 200,
            "balances": {
              "emetteur": 99900,
              "beneficiaire": 100100
            }
          }
        ],
        "result": "ok",
        "check_ms": 386
      }
    },
    {
      "ts": 1792487153.5082314,
      "at": "2026-10-20T09:05:53.508+00:00",
      "state": "recovered",
      "event": "state:recovered",
      "detail": {
        "reason": "vérification réussie"
      }
    },
    {
      "ts": 1792487212.5097415,
      "at": "2026-10-20T09:06:52.509+00:00",
      "state": "recovered",
      "event": "alert:resolved",
      "detail": {
        "alertname": "AuthBruteForce"
      }
    },
    {
      "ts": 1792487212.509915,
      "at": "2026-10-20T09:06:52.509+00:00",
      "state": "recovered",
      "event": "closed",
      "detail": {
        "outcome": "recovered"
      }
    }
  ]
};
