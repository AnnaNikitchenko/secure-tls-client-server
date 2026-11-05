"""Підрахунок подій JSONL та створення звіту Markdown."""
import argparse, collections, json
from pathlib import Path

def analyze(path: Path) -> tuple[dict[str,int], list[str]]:
    events=[]
    if path.exists():
        for number,line in enumerate(path.read_text(encoding="utf-8").splitlines(),1):
            if not line.strip(): continue
            try: events.append(json.loads(line))
            except json.JSONDecodeError: raise ValueError(f"Некоректний JSON у рядку {number}")
    counts=collections.Counter(e.get("event") for e in events)
    failures=[e for e in events if e.get("event")=="auth.failure"]
    offenders=collections.Counter((e.get("ip") or "невідомий IP",e.get("user") or "невідомий користувач") for e in failures)
    tls_errors=sum(e.get("event")=="tls.failure" or (e.get("event")=="connection.error" and e.get("reason")=="SSLError") for e in events)
    metrics={"Успішні TLS-з'єднання":counts["connection.success"],"Невдалі підключення":counts["tls.failure"]+counts["connection.error"],
      "Успішні автентифікації":counts["auth.success"],"Невдалі автентифікації":counts["auth.failure"],
      "Спроби неавторизованого доступу":counts["access.unauthorized"],"Помилки цілісності":counts["integrity.failure"],"Спостережувані TLS-помилки":tls_errors}
    anomalies=[]
    for (ip,user),n in offenders.most_common():
        if n>=3: anomalies.append(f"- {ip}, користувач {user}: {n} невдалих спроб входу.")
    if metrics["Спроби неавторизованого доступу"]: anomalies.append(f"- Зафіксовано {metrics['Спроби неавторизованого доступу']} спроб доступу до даних без входу.")
    if metrics["Помилки цілісності"]: anomalies.append(f"- Зафіксовано {metrics['Помилки цілісності']} невідповідностей SHA-256.")
    if not anomalies: anomalies=["- За наявними записами порогових аномалій не виявлено."]
    return metrics,anomalies

def report(path: Path) -> str:
    m,a=analyze(path)
    return "# Звіт аналізу журналу\n\n| Показник | Кількість |\n|---|---:|\n"+"".join(f"| {k} | {v} |\n" for k,v in m.items())+"\n## Аномалії\n\n"+"\n".join(a)+"\n\n## Рекомендації\n\n- Розслідувати повторні помилки входу та за потреби тимчасово блокувати джерело.\n- Перевірити причини відмов TLS та оновлювати бібліотеки й сертифікати.\n- Розглядати помилки цілісності як інцидент і не обробляти відхилені дані.\n- Обмежити доступ до журналів і зберігати їх відповідно до політики організації.\n"

if __name__=="__main__":
    p=argparse.ArgumentParser(); p.add_argument("log",nargs="?",default="logs/server.jsonl"); p.add_argument("--output",default="logs/analysis.md"); a=p.parse_args()
    result=report(Path(a.log)); Path(a.output).parent.mkdir(parents=True,exist_ok=True); Path(a.output).write_text(result,encoding="utf-8"); print(result)
