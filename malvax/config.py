"""Runtime configuration from environment variables. No secrets live in code."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass(frozen=True, slots=True)
class Settings:
    database_url: str
    redis_url: str
    storage_dir: Path
    max_upload_bytes: int
    rules_dir: Path
    cors_origins: tuple[str, ...] = ("http://localhost:3000",)
    jwt_secret: str = ""
    ai_provider: str = "offline"
    anthropic_api_key: str = ""

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Settings:
        source = os.environ if env is None else env
        return cls(
            database_url=source.get("MALVAX_DATABASE_URL", "sqlite:///./malvax-api.db"),
            redis_url=source.get("MALVAX_REDIS_URL", "redis://127.0.0.1:6379/0"),
            storage_dir=Path(source.get("MALVAX_STORAGE_DIR", "./storage")),
            max_upload_bytes=int(source.get("MALVAX_MAX_UPLOAD_BYTES", str(50 * 1024 * 1024))),
            rules_dir=Path(source.get("MALVAX_RULES_DIR", str(_PROJECT_ROOT / "rules"))),
            cors_origins=tuple(
                o.strip() for o in source.get("MALVAX_CORS_ORIGINS", "http://localhost:3000").split(",")
                if o.strip()
            ),
            jwt_secret=source.get("MALVAX_JWT_SECRET", ""),
            ai_provider=source.get("MALVAX_AI_PROVIDER", "offline").strip().lower(),
            anthropic_api_key=source.get("MALVAX_ANTHROPIC_API_KEY", ""),
        )
