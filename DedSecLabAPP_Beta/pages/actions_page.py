from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QScrollArea, QSizePolicy
)


class ChangeEntry(QFrame):
    """One changelog card."""

    def __init__(self, date, title, tag, tag_color, body_lines):
        super().__init__()
        self.setObjectName("ChangeCard")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(8)

        # Header row: date + tag
        header = QHBoxLayout()
        header.setSpacing(10)

        date_label = QLabel(date)
        date_label.setObjectName("ChangeDate")

        title_label = QLabel(title)
        title_label.setObjectName("ChangeTitle")
        title_label.setWordWrap(True)

        tag_label = QLabel(tag)
        tag_label.setObjectName("ChangeTag")
        tag_label.setStyleSheet(
            f"color: {tag_color}; border: 1px solid {tag_color}; "
            f"border-radius: 6px; padding: 2px 10px; font-size: 11px; font-weight: 700;"
        )

        header.addWidget(date_label)
        header.addWidget(title_label, 1)
        header.addWidget(tag_label)
        layout.addLayout(header)

        # Divider
        line = QFrame()
        line.setFixedHeight(1)
        line.setStyleSheet("background: rgba(85, 199, 255, 0.12);")
        layout.addWidget(line)

        # Body bullets
        for line_text in body_lines:
            row = QHBoxLayout()
            row.setSpacing(8)
            row.setContentsMargins(0, 0, 0, 0)

            bullet = QLabel("●")
            bullet.setStyleSheet("color: #50ff85; font-size: 11px;")
            bullet.setFixedWidth(14)

            text = QLabel(line_text)
            text.setObjectName("ChangeBody")
            text.setWordWrap(True)

            row.addWidget(bullet, 0, Qt.AlignmentFlag.AlignTop)
            row.addWidget(text, 1)
            layout.addLayout(row)


class ActionsPage(QWidget):
    """Changelog page (replaces old Actions Center)."""

    def __init__(self, app_window):
        super().__init__()
        self.app_window = app_window

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 14, 18, 12)
        root.setSpacing(10)

        # ── Header ──────────────────────────────────────────
        header = QHBoxLayout()
        title_box = QVBoxLayout()
        title_box.setSpacing(3)

        title = QLabel("Changelog")
        title.setObjectName("PageTitle")

        subtitle = QLabel("App patches · Website updates · Security · Bug fixes")
        subtitle.setObjectName("StatusLine")

        title_box.addWidget(title)
        title_box.addWidget(subtitle)

        badge = QLabel("● Live Log")
        badge.setObjectName("ActionsLiveBadge")
        badge.setStyleSheet(
            "color: #50ff85; font-weight: 700; font-size: 13px; "
            "padding: 6px 12px; border: 1px solid rgba(80,255,133,0.35); "
            "border-radius: 8px; background: rgba(80,255,133,0.08);"
        )

        header.addLayout(title_box)
        header.addStretch()
        header.addWidget(badge)
        root.addLayout(header)

        # ── Scroll area ─────────────────────────────────────
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")

        container = QWidget()
        container.setStyleSheet("background: transparent;")
        list_layout = QVBoxLayout(container)
        list_layout.setContentsMargins(0, 4, 6, 8)
        list_layout.setSpacing(12)

        # ── Entries (newest first) ──────────────────────────
        entries = [
            ChangeEntry(
                "2026-07-29",
                "Terminal Security Patch - One-time Token Layer",
                "SECURITY",
                "#ff4d5f",
                [
                    "Reviewed /ws/terminal WebSocket used by the PyQt client.",
                    "Auth previously relied only on VPN source IP (access_rules.json).",
                    "Risk: any valid VPN assignment could open a full terminal into access_wrapper.py / menu.py.",
                    "Added in-memory short-lived (90s) one-time token store, bound to the exact VPN IP.",
                    "New endpoint: POST /api/terminal-token (requires valid enabled non-expired VPN IP).",
                    "Updated /ws/terminal: still checks VPN IP first, then requires a valid unused token for that IP.",
                    "PTY env vars unchanged (DEDSEC_USER, DEDSEC_SSH_USER, DEDSEC_SOURCE_IP, DEDSEC_ROLE, SSH_CONNECTION).",
                    "Client now requests a token before opening the WebSocket (?token=...).",
                    "Token masked in UI logs (***). Bare /ws/terminal connections are rejected.",
                    "Verified: VPS self-request denied; real VPN client token issued; app connects and menu works.",
                    "Server backup: app_api.py.2026-07-29.bak - service restarted: dedsec-api.service.",
                ],
            ),
            ChangeEntry(
                "2026-07-29",
                "Login Page Cleanup",
                "UI",
                "#55c7ff",
                [
                    "Removed QMainWindow status bar (Connected / Ready / Disconnected).",
                    "Removed top-left status pills (Client / VPN / API badges).",
                    "Replaced Visit Website button with plain clickable text link.",
                    "Stage footer icons switched to green circles (VPN Protected · API Secured · Terminal Ready).",
                    "Overall login screen much cleaner and less cluttered.",
                ],
            ),
            ChangeEntry(
                "2026-07-29",
                "App Branding - Logo & Icon",
                "APP",
                "#55c7ff",
                [
                    "Converted logo PNG to multi-size Windows ICO (16-256px) for exe / taskbar.",
                    "dedsec_logo.ico ready for Nuitka --windows-icon-from-ico.",
                    "Sidebar brand uses applogo asset with consistent cyan neon DedSec mark.",
                ],
            ),
            ChangeEntry(
                "2026-07-28",
                "Website Image Carousel Cache Bust",
                "WEBSITE",
                "#50ff85",
                [
                    "Carousel images renamed to website1_v4.png ... website5_v4.png.",
                    "index.html static paths updated so browsers/phones fetch fresh assets.",
                    "Hard refresh no longer required on every device after deploy.",
                ],
            ),
            ChangeEntry(
                "2026-07-28",
                "Website Dark Glass Redesign",
                "WEBSITE",
                "#50ff85",
                [
                    "Full site restyle to match app: deep black, cyan #55c7ff, green #50ff85.",
                    "Glassmorphism nav, hero, cards, and footer (backdrop-filter + soft borders).",
                    "Pages updated: index, features, pricing, docs, support, login, dashboard.",
                    "Pricing page: £10/month VPN, all other tools free, strict no-logs messaging.",
                    "Hero carousel with arrows, dots, and auto-play.",
                ],
            ),
            ChangeEntry(
                "2026-07-22",
                "VPN / Xbox Page SSL Fix",
                "BUGFIX",
                "#ffcc33",
                [
                    "Fixed SSL CERTIFICATE_VERIFY_FAILED against Xbox Live APIs.",
                    "certifi upgrade + session handling; stable token capture and party tools.",
                    "Works in source and after Nuitka build when certifi data is included.",
                ],
            ),
            ChangeEntry(
                "2026-07-22",
                "Dashboard & Networking UI Pass",
                "UI",
                "#55c7ff",
                [
                    "Dashboard compacted so key widgets fit on one screen.",
                    "Live graphs / status rings kept where useful.",
                    "Networking page structure cleaned; WinDivert assets handled in builder.",
                ],
            ),
            ChangeEntry(
                "2026-07-21",
                "Nuitka Builder & WinDivert Packaging",
                "BUILD",
                "#b86cff",
                [
                    "Standalone build menu: clean, release, debug, install tools.",
                    "PyQt6 platforms + certifi + pydivert data included.",
                    "WinDivert DLL/SYS copied next to DedSecLab.exe for admin networking tools.",
                ],
            ),
        ]

        for entry in entries:
            list_layout.addWidget(entry)

        list_layout.addStretch()
        scroll.setWidget(container)
        root.addWidget(scroll, 1)

        # Light stylesheet so cards match the rest of the app if global QSS is thin
        self.setStyleSheet("""
            QFrame#ChangeCard {
                background: rgba(18, 18, 22, 0.72);
                border: 1px solid rgba(85, 199, 255, 0.12);
                border-radius: 14px;
            }
            QLabel#ChangeDate {
                color: #55c7ff;
                font-size: 12px;
                font-weight: 700;
                min-width: 88px;
            }
            QLabel#ChangeTitle {
                color: #e8f0ff;
                font-size: 15px;
                font-weight: 800;
            }
            QLabel#ChangeBody {
                color: #9aa8bc;
                font-size: 13px;
                line-height: 1.35;
            }
        """)