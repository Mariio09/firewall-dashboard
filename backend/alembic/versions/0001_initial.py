"""Esquema inicial: users, rules, packet_logs, alerts, audit_events.

Bloque A1. Escrita a mano y no autogenerada, para que sea revisable linea a
linea: es la migracion que define la forma de la base de datos y la unica que
se ejecuta sobre una base vacia.

Se crean tambien las tablas de las fases 2 y 4 (`packet_logs`, `alerts`) aunque
permanezcan vacias durante el MVP. Crear una tabla vacia hoy cuesta cero;
migrar el esquema con datos dentro, no.

Revision ID: 0001_initial
Revises:
Create Date: 2026-08-16
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: None = None
depends_on: None = None

#: 45 caracteres cubren el peor caso de IPv6 con prefijo.
ADDRESS_LEN = 45


def _enum(*valores: str, name: str) -> sa.Enum:
    """Enum como VARCHAR + CHECK, igual que `app.db.base.str_enum`.

    Los valores se repiten aqui a proposito en vez de importarlos de la
    aplicacion: una migracion debe seguir describiendo el esquema del momento en
    que se escribio aunque el codigo evolucione. Si mañana se añade un valor al
    enum, esta migracion no debe cambiar: se añade otra.
    """
    return sa.Enum(*valores, name=name, native_enum=False, create_constraint=True)


def upgrade() -> None:
    # ----------------------------------------------------------------------- #
    # users
    # ----------------------------------------------------------------------- #
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=50), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=True),
        sa.Column("hashed_password", sa.String(length=255), nullable=False),
        sa.Column("role", _enum("admin", "operator", "viewer", name="role"), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("email", name=op.f("uq_users_email")),
    )
    op.create_index(op.f("ix_users_username"), "users", ["username"], unique=True)

    # ----------------------------------------------------------------------- #
    # rules — la entidad central
    # ----------------------------------------------------------------------- #
    op.create_table(
        "rules",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("uuid", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("chain", _enum("INPUT", "OUTPUT", "FORWARD", name="chain"), nullable=False),
        sa.Column("table_name", _enum("filter", name="table_name"), nullable=False),
        sa.Column("ip_version", sa.Integer(), nullable=False),
        sa.Column("action", _enum("ACCEPT", "DROP", "REJECT", name="action"), nullable=False),
        sa.Column(
            "protocol", _enum("tcp", "udp", "icmp", "all", name="protocol"), nullable=False
        ),
        sa.Column("src_ip", sa.String(length=ADDRESS_LEN), nullable=True),
        sa.Column("dst_ip", sa.String(length=ADDRESS_LEN), nullable=True),
        sa.Column("src_port", sa.String(length=11), nullable=True),
        sa.Column("dst_port", sa.String(length=11), nullable=True),
        sa.Column("in_interface", sa.String(length=16), nullable=True),
        sa.Column("out_interface", sa.String(length=16), nullable=True),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("log_enabled", sa.Boolean(), nullable=False),
        sa.Column("log_prefix", sa.String(length=29), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "sync_state",
            _enum("pending", "applied", "failed", "drift", name="sync_state"),
            nullable=False,
        ),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("hit_count", sa.BigInteger(), nullable=False),
        sa.Column("bytes_count", sa.BigInteger(), nullable=False),
        sa.Column("created_by_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("ip_version IN (4, 6)", name=op.f("ck_rules_ip_version_valida")),
        sa.CheckConstraint("position >= 0", name=op.f("ck_rules_position_no_negativa")),
        sa.CheckConstraint(
            "log_enabled = 0 OR log_prefix IS NOT NULL",
            name=op.f("ck_rules_log_requiere_prefijo"),
        ),
        # SET NULL y no CASCADE: borrar a un usuario no puede borrar la politica
        # de firewall que dejo escrita.
        sa.ForeignKeyConstraint(
            ["created_by_id"],
            ["users.id"],
            name=op.f("fk_rules_created_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_rules")),
        sa.UniqueConstraint("chain", "position", name="uq_rules_chain_position"),
    )
    op.create_index(op.f("ix_rules_uuid"), "rules", ["uuid"], unique=True)
    op.create_index("ix_rules_chain_position", "rules", ["chain", "position"], unique=False)
    op.create_index("ix_rules_sync_state", "rules", ["sync_state"], unique=False)
    op.create_index("ix_rules_expires_at", "rules", ["expires_at"], unique=False)

    # ----------------------------------------------------------------------- #
    # packet_logs — fase 2
    # ----------------------------------------------------------------------- #
    op.create_table(
        "packet_logs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("src_ip", sa.String(length=ADDRESS_LEN), nullable=True),
        sa.Column("dst_ip", sa.String(length=ADDRESS_LEN), nullable=True),
        sa.Column("src_port", sa.Integer(), nullable=True),
        sa.Column("dst_port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(length=10), nullable=True),
        sa.Column("in_interface", sa.String(length=16), nullable=True),
        # Sin ForeignKeyConstraint a proposito: un log es un hecho historico y
        # debe sobrevivir al borrado de la regla que lo genero.
        sa.Column("rule_uuid", sa.String(length=36), nullable=True),
        sa.Column("raw", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_packet_logs")),
    )
    op.create_index(op.f("ix_packet_logs_ts"), "packet_logs", ["ts"], unique=False)
    op.create_index(op.f("ix_packet_logs_rule_uuid"), "packet_logs", ["rule_uuid"], unique=False)
    # Estos dos son exactamente las consultas de las graficas de la fase 3.
    op.create_index("ix_packet_logs_src_ip_ts", "packet_logs", ["src_ip", "ts"], unique=False)
    op.create_index("ix_packet_logs_dst_port_ts", "packet_logs", ["dst_port", "ts"], unique=False)

    # ----------------------------------------------------------------------- #
    # alerts — fase 4
    # ----------------------------------------------------------------------- #
    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "kind",
            _enum("brute_force", "port_scan", "rate_limit", name="alert_kind"),
            nullable=False,
        ),
        sa.Column(
            "severity",
            _enum("low", "medium", "high", "critical", name="severity"),
            nullable=False,
        ),
        sa.Column("src_ip", sa.String(length=ADDRESS_LEN), nullable=True),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("related_rule_uuid", sa.String(length=36), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_by_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(
            ["acknowledged_by_id"],
            ["users.id"],
            name=op.f("fk_alerts_acknowledged_by_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_alerts")),
    )
    op.create_index(op.f("ix_alerts_ts"), "alerts", ["ts"], unique=False)
    op.create_index("ix_alerts_kind_ts", "alerts", ["kind", "ts"], unique=False)

    # ----------------------------------------------------------------------- #
    # audit_events — transversal, activo desde el primer dia
    # ----------------------------------------------------------------------- #
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("username", sa.String(length=50), nullable=True),
        sa.Column(
            "action",
            _enum(
                "rule.create",
                "rule.update",
                "rule.delete",
                "rule.toggle",
                "rule.reorder",
                "firewall.apply",
                "firewall.preview",
                "firewall.teardown",
                "auth.login",
                "auth.login_failed",
                "auth.logout",
                "user.create",
                "user.update",
                "user.delete",
                name="audit_action",
            ),
            nullable=False,
        ),
        sa.Column("entity_type", sa.String(length=50), nullable=True),
        sa.Column("entity_id", sa.String(length=36), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("result", _enum("success", "failure", name="audit_result"), nullable=False),
        sa.Column("client_ip", sa.String(length=ADDRESS_LEN), nullable=True),
        sa.Column("request_id", sa.String(length=26), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_audit_events_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_events")),
    )
    op.create_index(op.f("ix_audit_events_ts"), "audit_events", ["ts"], unique=False)
    op.create_index("ix_audit_events_action_ts", "audit_events", ["action", "ts"], unique=False)
    op.create_index("ix_audit_events_user_id_ts", "audit_events", ["user_id", "ts"], unique=False)


def downgrade() -> None:
    # Orden inverso: primero las tablas que apuntan a `users`.
    op.drop_table("audit_events")
    op.drop_table("alerts")
    op.drop_table("packet_logs")
    op.drop_table("rules")
    op.drop_table("users")
