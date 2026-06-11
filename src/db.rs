use anyhow::{Context, Result};
use rusqlite::{Connection, params, Row};
use serde::Serialize;
use std::path::Path;

pub struct Database {
    conn: Connection,
}

#[derive(Debug, Clone, Serialize)]
pub struct AssetRow {
    pub ip_address: String,
    pub role: String,
    pub protocols: String,
    pub posture_score: f64,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FlowRow {
    pub src_ip: String,
    pub dst_ip: String,
    pub protocol: String,
    pub packet_count: i64,
    pub byte_volume: i64,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FindingRow {
    pub severity: String,
    pub category: String,
    pub description: String,
    pub evidence: String,
    pub first_seen: String,
    pub count: i64,
}

impl Database {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("opening database: {}", path.display()))?;

        let db = Self { conn };
        db.init()?;
        Ok(db)
    }

    fn init(&self) -> Result<()> {
        self.conn.execute_batch("
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            PRAGMA foreign_keys=ON;

            CREATE TABLE IF NOT EXISTS assets (
                id          TEXT PRIMARY KEY,
                ip_address  TEXT NOT NULL UNIQUE,
                mac_address TEXT,
                vendor      TEXT,
                role        TEXT NOT NULL DEFAULT 'Unknown',
                protocols   TEXT NOT NULL DEFAULT '[]',
                purdue_level INTEGER,
                first_seen  TEXT NOT NULL,
                last_seen   TEXT NOT NULL,
                posture_score REAL NOT NULL DEFAULT 0.0
            );

            CREATE TABLE IF NOT EXISTS flows (
                id           TEXT PRIMARY KEY,
                src_ip       TEXT NOT NULL,
                dst_ip       TEXT NOT NULL,
                protocol     TEXT NOT NULL,
                first_seen   TEXT NOT NULL,
                last_seen    TEXT NOT NULL,
                packet_count INTEGER NOT NULL DEFAULT 0,
                byte_volume  INTEGER NOT NULL DEFAULT 0,
                UNIQUE(src_ip, dst_ip, protocol)
            );

            CREATE TABLE IF NOT EXISTS findings (
                id          TEXT PRIMARY KEY,
                asset_id    TEXT REFERENCES assets(id),
                flow_id     TEXT REFERENCES flows(id),
                severity    TEXT NOT NULL,
                category    TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence    TEXT NOT NULL,
                first_seen  TEXT NOT NULL,
                count       INTEGER NOT NULL DEFAULT 1
            );

            CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip_address);
            CREATE INDEX IF NOT EXISTS idx_flows_src_dst ON flows(src_ip, dst_ip);
            CREATE INDEX IF NOT EXISTS idx_findings_flow ON findings(flow_id);
        ").context("initialising database schema")
    }

    pub fn upsert_flow(&self, src: &str, dst: &str, protocol: &str, bytes: u64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO flows (id, src_ip, dst_ip, protocol, first_seen, last_seen, packet_count, byte_volume)
             VALUES (lower(hex(randomblob(16))), ?1, ?2, ?3, datetime('now'), datetime('now'), 1, ?4)
             ON CONFLICT(src_ip, dst_ip, protocol) DO UPDATE SET
               last_seen = datetime('now'),
               packet_count = packet_count + 1,
               byte_volume = byte_volume + excluded.byte_volume",
            params![src, dst, protocol, bytes],
        ).context("upserting flow")?;
        Ok(())
    }

    pub fn upsert_asset(&self, ip: &str, protocol: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO assets (id, ip_address, protocols, first_seen, last_seen)
             VALUES (lower(hex(randomblob(16))), ?1, json_array(?2), datetime('now'), datetime('now'))
             ON CONFLICT(ip_address) DO UPDATE SET
               last_seen = datetime('now'),
               protocols = CASE
                 WHEN json_array_length(protocols) = 0 OR instr(protocols, ?2) = 0
                 THEN json_insert(protocols, '$[#]', ?2)
                 ELSE protocols
               END",
            params![ip, protocol],
        ).context("upserting asset")?;
        Ok(())
    }

    pub fn list_assets(&self, top: Option<usize>) -> Result<Vec<AssetRow>> {
        let limit = top.map(|n| n as i64).unwrap_or(-1);
        let mut stmt = self.conn.prepare(
            "SELECT ip_address, role, protocols, posture_score, first_seen, last_seen
             FROM assets
             ORDER BY posture_score DESC, last_seen DESC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], row_to_asset)?;
        rows.collect::<Result<Vec<_>, _>>().context("listing assets")
    }

    pub fn list_flows(&self) -> Result<Vec<FlowRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT src_ip, dst_ip, protocol, packet_count, byte_volume, first_seen, last_seen
             FROM flows
             ORDER BY last_seen DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(FlowRow {
                src_ip: row.get(0)?,
                dst_ip: row.get(1)?,
                protocol: row.get(2)?,
                packet_count: row.get(3)?,
                byte_volume: row.get(4)?,
                first_seen: row.get(5)?,
                last_seen: row.get(6)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().context("listing flows")
    }

    pub fn list_findings(&self) -> Result<Vec<FindingRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT severity, category, description, evidence, first_seen, count
             FROM findings
             ORDER BY first_seen DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(FindingRow {
                severity: row.get(0)?,
                category: row.get(1)?,
                description: row.get(2)?,
                evidence: row.get(3)?,
                first_seen: row.get(4)?,
                count: row.get(5)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().context("listing findings")
    }
}

fn row_to_asset(row: &Row) -> rusqlite::Result<AssetRow> {
    Ok(AssetRow {
        ip_address: row.get(0)?,
        role: row.get(1)?,
        protocols: row.get(2)?,
        posture_score: row.get(3)?,
        first_seen: row.get(4)?,
        last_seen: row.get(5)?,
    })
}
