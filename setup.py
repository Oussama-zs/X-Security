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

from setuptools import setup, find_packages

setup(
    name="xsecurity",
    version="1.0.0",
    description="Hybrid AI Vulnerability Scanner (SAST + DAST)",
    author="Oussama Elattaoui",
    packages=find_packages(),
    py_modules=["main", "ingestion", "static_analyzer", "dynamic_analyzer", "ai_supervisor", "reporter", "config"],
    install_requires=[
        "fpdf",
        "requests",
        "Flask",
        "wapiti3"
    ],
    entry_points={
        "console_scripts": [
            "xsecurity=main:main",
        ],
    },
)
