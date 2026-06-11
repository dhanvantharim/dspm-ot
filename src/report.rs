use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::io::{self, Write};
use std::path::Path;
use tracing::info;

use crate::db::Database;

#[derive(Debug, Serialize)]
struct PostureReport {
    generated_at: String,
    assets: Vec<AssetRecord>,
}

#[derive(Debug, Serialize)]
struct AssetRecord {
    ip_address: String,
    role: String,
    protocols: String,
    posture_score: f64,
    first_seen: String,
    last_seen: String,
}

pub fn run(
    format: &str,
    output: Option<&Path>,
    report_type: &str,
    top: Option<usize>,
    db_path: &Path,
) -> Result<()> {
    let db = Database::open(db_path)?;

    info!(format, report_type, "generating report");

    match (format, report_type) {
        ("json", "posture") => write_json(&db, output, top)?,
        ("json", "assets") => write_assets_json(&db, output, top)?,
        ("json", "flows") => write_flows_json(&db, output)?,
        ("json", "findings") => write_findings_json(&db, output)?,
        ("csv", "assets") => write_assets_csv(&db, output, top)?,
        ("csv", "flows") => write_flows_csv(&db, output)?,
        ("csv", "findings") => write_findings_csv(&db, output)?,
        ("csv", "posture") => write_assets_csv(&db, output, top)?,
        ("stix", _) => bail!("STIX export is not implemented yet"),
        (_, _) => bail!("unsupported report format/type: {format}/{report_type}"),
    }

    Ok(())
}

fn write_output(output: Option<&Path>, content: &str) -> Result<()> {
    match output {
        Some(path) => {
            std::fs::write(path, content)
                .with_context(|| format!("writing report to {}", path.display()))?;
        }
        None => {
            io::stdout().write_all(content.as_bytes())?;
        }
    }
    Ok(())
}

fn write_json(db: &Database, output: Option<&Path>, top: Option<usize>) -> Result<()> {
    let assets = db.list_assets(top)?;
    let report = PostureReport {
        generated_at: chrono::Utc::now().to_rfc3339(),
        assets: assets
            .into_iter()
            .map(|a| AssetRecord {
                ip_address: a.ip_address,
                role: a.role,
                protocols: a.protocols,
                posture_score: a.posture_score,
                first_seen: a.first_seen,
                last_seen: a.last_seen,
            })
            .collect(),
    };

    let json = serde_json::to_string_pretty(&report)?;
    write_output(output, &format!("{json}\n"))?;
    Ok(())
}

fn write_assets_json(db: &Database, output: Option<&Path>, top: Option<usize>) -> Result<()> {
    let assets = db.list_assets(top)?;
    let json = serde_json::to_string_pretty(&assets)?;
    write_output(output, &format!("{json}\n"))?;
    Ok(())
}

fn write_flows_json(db: &Database, output: Option<&Path>) -> Result<()> {
    let flows = db.list_flows()?;
    let json = serde_json::to_string_pretty(&flows)?;
    write_output(output, &format!("{json}\n"))?;
    Ok(())
}

fn write_findings_json(db: &Database, output: Option<&Path>) -> Result<()> {
    let findings = db.list_findings()?;
    let json = serde_json::to_string_pretty(&findings)?;
    write_output(output, &format!("{json}\n"))?;
    Ok(())
}

fn write_assets_csv(db: &Database, output: Option<&Path>, top: Option<usize>) -> Result<()> {
    let assets = db.list_assets(top)?;
    let mut lines = vec![
        "ip_address,role,protocols,posture_score,first_seen,last_seen".to_string(),
    ];
    for asset in assets {
        lines.push(format!(
            "{},{},{},{},{},{}",
            csv_escape(&asset.ip_address),
            csv_escape(&asset.role),
            csv_escape(&asset.protocols),
            asset.posture_score,
            csv_escape(&asset.first_seen),
            csv_escape(&asset.last_seen),
        ));
    }
    write_output(output, &(lines.join("\n") + "\n"))?;
    Ok(())
}

fn write_flows_csv(db: &Database, output: Option<&Path>) -> Result<()> {
    let flows = db.list_flows()?;
    let mut lines = vec![
        "src_ip,dst_ip,protocol,packet_count,byte_volume,first_seen,last_seen".to_string(),
    ];
    for flow in flows {
        lines.push(format!(
            "{},{},{},{},{},{},{}",
            csv_escape(&flow.src_ip),
            csv_escape(&flow.dst_ip),
            csv_escape(&flow.protocol),
            flow.packet_count,
            flow.byte_volume,
            csv_escape(&flow.first_seen),
            csv_escape(&flow.last_seen),
        ));
    }
    write_output(output, &(lines.join("\n") + "\n"))?;
    Ok(())
}

fn write_findings_csv(db: &Database, output: Option<&Path>) -> Result<()> {
    let findings = db.list_findings()?;
    let mut lines = vec![
        "severity,category,description,evidence,first_seen,count".to_string(),
    ];
    for finding in findings {
        lines.push(format!(
            "{},{},{},{},{},{}",
            csv_escape(&finding.severity),
            csv_escape(&finding.category),
            csv_escape(&finding.description),
            csv_escape(&finding.evidence),
            csv_escape(&finding.first_seen),
            finding.count,
        ));
    }
    write_output(output, &(lines.join("\n") + "\n"))?;
    Ok(())
}

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}
