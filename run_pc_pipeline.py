#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
One-click pipeline для локального ПК:
1) Запускает проверку прокси (vless_checker), чтобы обновить локальную папку configs/.
2) Синхронизирует configs/ в отдельный GitHub-репозиторий.
3) Коммитит и пушит изменения в целевой репозиторий.

По умолчанию целевой репозиторий: Kotlas23412/proxy
Авторизация для push: переменная окружения GITHUB_TOKEN (рекомендуется PAT с доступом к repo).
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def _run(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(cwd) if cwd else None, check=True)


def _repo_url_with_token(url: str, token: str) -> str:
    # Для GitHub HTTPS push используем безопасный формат x-access-token.
    # Пример: https://x-access-token:TOKEN@github.com/owner/repo.git
    if not token:
        return url
    if url.startswith("https://github.com/"):
        return url.replace("https://", f"https://x-access-token:{token}@")
    return url


def _sync_dir(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    # Полная синхронизация содержимого: удаляем в dst то, чего нет в src.
    src_items = {p.name for p in src.iterdir()}
    for p in dst.iterdir():
        if p.name not in src_items:
            if p.is_dir():
                shutil.rmtree(p)
            else:
                p.unlink()
    for p in src.iterdir():
        target = dst / p.name
        if p.is_dir():
            if target.exists():
                shutil.rmtree(target)
            shutil.copytree(p, target)
        else:
            shutil.copy2(p, target)


def _git_has_changes(repo_dir: Path) -> bool:
    proc = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=str(repo_dir),
        check=True,
        capture_output=True,
        text=True,
    )
    return bool(proc.stdout.strip())


def main() -> int:
    parser = argparse.ArgumentParser(description="Локальный pipeline: check -> sync configs -> push to target repo")
    parser.add_argument("--skip-check", action="store_true", help="Пропустить запуск vless_checker")
    parser.add_argument("--skip-push", action="store_true", help="Пропустить push в целевой репозиторий")
    parser.add_argument(
        "--target-repo",
        default=os.environ.get("PUSH_TARGET_REPO", "https://github.com/Kotlas23412/proxy.git"),
        help="URL целевого репозитория",
    )
    parser.add_argument(
        "--target-branch",
        default=os.environ.get("PUSH_TARGET_BRANCH", "main"),
        help="Целевая ветка",
    )
    parser.add_argument(
        "--target-subdir",
        default=os.environ.get("PUSH_TARGET_SUBDIR", "configs"),
        help="Подпапка в целевом репозитории для синхронизации",
    )
    parser.add_argument(
        "--workdir",
        default=os.environ.get("PUSH_WORKDIR", ".push_proxy_repo"),
        help="Локальная папка для clone/pull целевого репозитория",
    )
    parser.add_argument(
        "--source-dir",
        default=os.environ.get("PUSH_SOURCE_DIR", "configs"),
        help="Локальная папка с результатами (по умолчанию configs)",
    )
    parser.add_argument(
        "--commit-message",
        default=os.environ.get("PUSH_COMMIT_MESSAGE", ""),
        help="Текст коммита (по умолчанию авто-метка времени UTC)",
    )
    parser.add_argument(
        "--checker-args",
        default=os.environ.get("PC_CHECKER_ARGS", ""),
        help="Аргументы для vless_checker (строкой), например: \"--debug\"",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent
    source_dir = (repo_root / args.source_dir).resolve()
    if not source_dir.exists() or not source_dir.is_dir():
        print(f"[ERROR] Source dir not found: {source_dir}")
        return 1

    if not args.skip_check:
        checker_cmd = [sys.executable, "-m", "lib.vless_checker"]
        if args.checker_args.strip():
            checker_cmd.extend(args.checker_args.strip().split())
        print("[1/3] Запуск проверки прокси...")
        _run(checker_cmd, cwd=repo_root)
        print("[OK] Проверка завершена.")

    if args.skip_push:
        print("[INFO] --skip-push задан, пуш в целевой репозиторий пропущен.")
        return 0

    token = os.environ.get("GITHUB_TOKEN", "").strip()
    target_repo_url = _repo_url_with_token(args.target_repo, token)
    workdir = (repo_root / args.workdir).resolve()

    print("[2/3] Подготовка целевого репозитория...")
    if (workdir / ".git").exists():
        _run(["git", "fetch", "origin"], cwd=workdir)
        _run(["git", "checkout", args.target_branch], cwd=workdir)
        _run(["git", "pull", "--ff-only", "origin", args.target_branch], cwd=workdir)
    else:
        if workdir.exists():
            shutil.rmtree(workdir)
        _run(["git", "clone", "--branch", args.target_branch, target_repo_url, str(workdir)])

    target_dir = workdir / args.target_subdir
    _sync_dir(source_dir, target_dir)

    _run(["git", "add", "-A"], cwd=workdir)
    if not _git_has_changes(workdir):
        print("[OK] Изменений нет, пуш не требуется.")
        return 0

    commit_message = args.commit_message.strip()
    if not commit_message:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        commit_message = f"Update configs from local pipeline ({ts})"

    _run(["git", "commit", "-m", commit_message], cwd=workdir)
    print("[3/3] Push изменений в целевой репозиторий...")
    _run(["git", "push", "origin", args.target_branch], cwd=workdir)
    print("[OK] Готово: configs отправлены в целевой репозиторий.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Command failed with code {e.returncode}: {e.cmd}")
        raise SystemExit(e.returncode)
