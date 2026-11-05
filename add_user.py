"""Безпечне додавання користувача до локального сховища."""
import argparse, getpass, hashlib, json, os, secrets
from pathlib import Path
from server import BASE, PBKDF2_ITERATIONS

def add_user(username: str, password: str, path: Path) -> None:
    if not username or len(username) > 64 or any(c.isspace() for c in username): raise ValueError("Некоректний логін")
    if len(password) < 12: raise ValueError("Пароль має містити щонайменше 12 символів")
    path.parent.mkdir(parents=True, exist_ok=True)
    users=json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    if username in users: raise ValueError("Такий користувач уже існує")
    salt=secrets.token_bytes(16)
    users[username]={"algorithm":"pbkdf2_hmac_sha256", "iterations":PBKDF2_ITERATIONS,
                     "salt":salt.hex(), "hash":hashlib.pbkdf2_hmac("sha256",password.encode(),salt,PBKDF2_ITERATIONS).hex()}
    path.write_text(json.dumps(users,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    try: path.chmod(0o600)
    except OSError: pass

def main():
    p=argparse.ArgumentParser(description="Створення облікового запису"); p.add_argument("username"); p.add_argument("--users-file",default=str(BASE/"data"/"users.json")); a=p.parse_args()
    password=getpass.getpass("Новий пароль: "); confirm=getpass.getpass("Повторіть пароль: ")
    if password != confirm: p.error("Паролі не збігаються")
    try: add_user(a.username,password,Path(a.users_file)); print("Користувача створено.")
    except ValueError as exc: p.error(str(exc))
if __name__ == "__main__": main()
