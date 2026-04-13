# CheckPoint Catch-All Rule Analyzer

Analizza il traffico matchato da una specifica regola firewall Check Point su un
periodo storico configurabile, producendo statistiche, report e regole candidate
per il hardening della policy — in particolare per convertire una catch-all
`ACCEPT` in una `DENY` dopo aver identificato tutte le eccezioni legittime.

---

## Requisiti

| Requisito | Versione minima |
|---|---|
| Python | 3.8+ |
| Check Point Management | R80.10+ |
| SmartLog blade | abilitato (per log query) |

### Installazione dipendenze

```bash
pip install -r requirements.txt
# oppure direttamente
pip install requests
```

---

## Utilizzo

```bash
python analyze_rule.py \
    --host      10.167.251.203 \
    --username  api_user \
    --password  api_user \
    --package   INT-FW-Policy \
    --layer-uuid  <UID-del-layer> \
    --rule-uuid   <UID-della-regola> \
    --days        30 \
    --output-dir  ./output
```

### Tutti i parametri

| Parametro | Default | Descrizione |
|---|---|---|
| `--host` | `10.167.251.203` | IP/hostname del management |
| `--username` | `api_user` | Username API |
| `--password` | `api_user` | Password API |
| `--package` | `INT-FW-Policy` | Nome del policy package |
| `--layer-uuid` | *obbligatorio* | UID del layer di accesso |
| `--rule-uuid` | *obbligatorio* | UID della regola da analizzare |
| `--days` | `30` | Giorni di storico da analizzare |
| `--output-dir` | nessuno | Directory per output (JSON/CSV/report) |
| `--quiet` | no | Sopprime output console |
| `--debug` | no | Logging verbose |

### Come ottenere layer-uuid e rule-uuid

In SmartConsole o via API:

```bash
# Lista dei layer di una policy
curl -sk -X POST https://10.167.251.203/web_api/show-access-layers \
  -H "X-chkp-sid: <SID>" \
  -H "Content-Type: application/json" \
  -d '{"package": "INT-FW-Policy"}' | python3 -m json.tool

# Lista delle regole di un layer
curl -sk -X POST https://10.167.251.203/web_api/show-access-rulebase \
  -H "X-chkp-sid: <SID>" \
  -H "Content-Type: application/json" \
  -d '{"uid": "<layer-uuid>", "details-level": "full"}' | python3 -m json.tool
```

---

## Output prodotti

Quando si specifica `--output-dir`, lo script crea i seguenti file:

| File | Contenuto |
|---|---|
| `analysis_<uid8>.json` | Dati grezzi + statistiche + regole candidate (JSON) |
| `analysis_<uid8>_logs.csv` | Dettaglio di ogni log entry recuperata |
| `analysis_<uid8>_top_sources.csv` | Top source IP con hit count e % |
| `analysis_<uid8>_top_destinations.csv` | Top destination IP |
| `analysis_<uid8>_top_services.csv` | Top servizi/porte |
| `analysis_<uid8>_top_tuples.csv` | Top src→dst→svc triple |
| `analysis_<uid8>_candidate_rules.csv` | Regole candidate proposte |
| `report_<uid8>.txt` | Report testuale completo con guidance operativa |

L'output console è sempre prodotto (a meno di `--quiet`).

---

## Esempio di output console

```
========================================================================
  CHECK POINT CATCH-ALL RULE ANALYZER — RESULTS
========================================================================

  Rule      : Catch-All-Accept (a1b2c3d4-...)
  Action    : ACCEPT
  Period    : 30 days  (2025-12-14T... → 2026-01-13T...)
  Total hits: 45,230

  ────────────────────────────────────────────────────────────────────
  TOP SOURCES
  ────────────────────────────────────────────────────────────────────
    192.168.10.50              12,340
    10.20.30.5                  8,901
    172.16.1.100                4,320
    ...

  ────────────────────────────────────────────────────────────────────
  CANDIDATE RULES FOR POLICY HARDENING
  ────────────────────────────────────────────────────────────────────

  #01  ACCEPT   [HIGH]    ALLOW-192_168_10_50-to-10_0_0_1-443
       Src : 192.168.10.50
       Dst : 10.0.0.1
       Svc : 443
       Hits: 11,200
       Why : Observed 11200 hits (24.8% of traffic) — stable pattern

  #02  ACCEPT   [HIGH]    ALLOW-PAIR-10_20_30_5-to-172_16_2_10
       ...

  #15  DENY     [HIGH]    CATCHALL-DENY
       Src : any  |  Dst : any  |  Svc : any
       Why : Deploy AFTER all ACCEPT exceptions above.
```

---

## Approccio adottato

### Gestione sessione
- Login via `POST /web_api/login` con username/password
- Session ID (`X-chkp-sid`) allegato a ogni chiamata successiva
- Logout garantito in blocco `finally` anche in caso di errore

### Fetch della regola
- Tentativo diretto con `show-access-rule` (uid + layer)
- Fallback: scan del rulebase con `show-access-rulebase` (paginato)
- Gestione sezioni/inline-layers con flattening ricorsivo

### Query dei log
- `POST /web_api/show-logs` con filtro `rule_uid:<uuid>` e time-frame
- Paginazione via `scroll-id` per risultati > PAGE_SIZE (default 500)
- Gestione risposta asincrona (task-id) con polling
- Safety cap a 100.000 log entry per evitare esaurimento memoria

### Correlazione regola-log
- **Primaria**: campo `rule_uid` nel log entry (alta affidabilità)
- **Fallback**: campo `rule_name` (se rule_uid assente nel log)
- Entrambe le modalità sono conteggiate e riportate nell'output

### Analisi statistica
- `collections.Counter` per tutte le aggregazioni
- Distribuzione temporale per ora e per giorno
- Identificazione traffico "raro" (single-hit) vs ricorrente

### Generazione regole candidate
1. Triple src/dst/svc ad alta frequenza → regole ACCEPT specifiche
2. Coppie src/dst frequenti con lista servizi aggregata
3. Pattern utente (se dati identità presenti)
4. Pattern applicazione (se AppControl attivo)
5. Traffico raro → flag MANUAL-REVIEW
6. Regola DENY catch-all finale

### Estensibilità
- `--days` configurabile da CLI (es. `--days 90`)
- Costante `MAX_LOGS` per adattare a firewall molto traffico
- `TOP_N` modificabile nel codice per più/meno risultati
- Classi separate per Session, RuleFetcher, LogFetcher, Analyzer, Generator, Output

---

## Limitazioni note

1. **SmartLog obbligatorio**: `show-logs` richiede blade SmartLog abilitato.
2. **Log Server separato**: se i log sono su un Log Server dedicato, il
   management API deve potervi accedere (configurazione interna CP).
3. **NAT**: IP osservati nei log possono essere tradotti — verificare
   post-NAT vs pre-NAT a seconda della configurazione del logging CP.
4. **AppControl**: dati applicazione solo se la blade è abilitata.
5. **Identità utente**: solo se IDFW / AD Query / Captive Portal attivi.
6. **Retention**: il periodo analizzato è limitato alla retention effettiva
   del log server, indipendentemente dal valore `--days`.
7. **Versioni**: testato su R80.40+ ; su R80.10/R80.20 verificare che
   `show-logs` sia disponibile nell'API server installato.
