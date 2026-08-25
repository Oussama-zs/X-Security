# ==============================================================================
# X-SECURITY - Hybrid AI-Powered Vulnerability Scanner
# 
# Author: Oussama Elattaoui (GitHub: oussama-zs)
# Institution: Ecole des Sciences de l'Information (ESI), Rabat
# Project: Projet de Fin d'Annee (PFA) 2025/2026
# Company: CGX (Creative Generated Experience)
#
# This software is part of an academic project.
# Unauthorized copying, modification, or distribution without credit is prohibited.
# ==============================================================================

import os
import hashlib
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Set
import pathspec

from config import DEFAULT_IGNORE_PATTERNS, get_language_from_extension

@dataclass
class FileManifest:
    path: str
    language: str
    size: int
    sha256: str
    role: str

class IngestionEngine:
    def __init__(self, root_path: str):
        self.root_path = Path(root_path).absolute()
        self.ignore_spec = self._build_ignore_spec()

    def _build_ignore_spec(self) -> pathspec.PathSpec:
        """Builds a pathspec from DEFAULT_IGNORE_PATTERNS and .gitignore."""
        patterns = list(DEFAULT_IGNORE_PATTERNS)
        
        gitignore_path = self.root_path / ".gitignore"
        if gitignore_path.exists():
            try:
                with open(gitignore_path, "r", encoding="utf-8") as f:
                    patterns.extend(f.readlines())
            except Exception as e:
                print(f"Warning: Could not read .gitignore: {e}")

        # Use the gitwildmatch pattern matching syntax (standard .gitignore behavior)
        return pathspec.PathSpec.from_lines(pathspec.patterns.GitWildMatchPattern, patterns)

    def _is_ignored(self, path: Path) -> bool:
        """Checks if a given path should be ignored."""
        try:
            rel_path = path.relative_to(self.root_path)
        except ValueError:
            # If path is not relative to root for some reason, don't ignore by default
            return False
            
        # pathspec expects POSIX style paths
        posix_path = rel_path.as_posix()
        
        # If it's a directory, append a trailing slash to properly match dir rules like "node_modules/"
        if path.is_dir() and not posix_path.endswith('/'):
            posix_path += '/'
            
        return self.ignore_spec.match_file(posix_path)

    def _hash_file(self, path: Path) -> str:
        """Computes the SHA256 hash of a file."""
        sha256_hash = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                # Read and update hash string value in blocks of 4K
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception:
            return ""

    def _infer_role(self, path: Path, language: str) -> str:
        """Heuristics to infer the role of the file."""
        name = path.name.lower()
        rel_path = path.relative_to(self.root_path).as_posix().lower()
        
        if "test" in rel_path or "spec" in rel_path:
            return "test"
        if "config" in rel_path or name.endswith((".json", ".yaml", ".yml", ".ini", ".env")):
            return "config"
        if name in ("package.json", "requirements.txt", "pom.xml", "gemfile", "cargo.toml"):
            return "dependency-manifest"
        if "route" in rel_path or "controller" in rel_path or "view" in rel_path or name in ("main.py", "app.py", "index.js", "server.js"):
            return "entrypoint"
        if "model" in rel_path or "entity" in rel_path:
            return "model"
            
        return "source"

    def scan(self) -> List[FileManifest]:
        """Scans the repository and returns a manifest of files."""
        manifest = []
        
        for root, dirs, files in os.walk(self.root_path):
            current_dir = Path(root)
            
            # Filter directories in-place to prevent os.walk from descending into ignored dirs
            # Need to iterate backwards when removing items from a list while looping over it,
            # or just build a new list of valid ones and assign back to dirs slice.
            dirs[:] = [d for d in dirs if not self._is_ignored(current_dir / d)]
            
            for file_name in files:
                file_path = current_dir / file_name
                
                if self._is_ignored(file_path):
                    continue
                    
                lang = get_language_from_extension(str(file_path))
                
                # If language is unknown, we record it as metadata but it might not be parsed deeply later
                size = file_path.stat().st_size
                sha256 = self._hash_file(file_path)
                role = self._infer_role(file_path, lang)
                
                manifest.append(
                    FileManifest(
                        path=file_path.relative_to(self.root_path).as_posix(),
                        language=lang,
                        size=size,
                        sha256=sha256,
                        role=role
                    )
                )
                
        return manifest

if __name__ == "__main__":
    # Simple test to run ingestion on the current directory
    engine = IngestionEngine(".")
    files = engine.scan()
    print(f"Discovered {len(files)} valid files.")
    for f in files:
        print(f" - {f.path} ({f.language}) [Role: {f.role}]")
