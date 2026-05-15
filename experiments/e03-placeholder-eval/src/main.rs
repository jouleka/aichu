// e03-placeholder-eval — binary entry point.
//
// Loads `.txt` fixtures from a directory, iterates over (fixture × format ×
// model), and writes JSON results. Requires $ANTHROPIC_API_KEY when running
// with --provider anthropic.
//
// Fixture format (per file):
//   First line:  SECRET_TEXT=<literal text to substitute>
//   Second line: SECRET_TYPE=<type slug, e.g. AWS_KEY>
//   Rest:        the prompt body. Must contain SECRET_TEXT somewhere.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use clap::Parser;

use e03_placeholder_eval::{
    PlaceholderFormat, evaluate, model::Model, providers::anthropic::AnthropicProvider,
};

#[derive(Debug, Parser)]
#[command(name = "e03-placeholder-eval")]
struct Args {
    /// Directory containing `.txt` fixture files.
    #[arg(long)]
    prompts: PathBuf,

    /// Provider to run against. Currently only `anthropic` is implemented.
    #[arg(long, default_value = "anthropic")]
    provider: String,

    /// Anthropic model id (e.g. `claude-opus-4-7-20250514`).
    #[arg(long, default_value = "claude-opus-4-7-20250514")]
    model: String,

    /// Comma-separated list of placeholder formats, or `all`.
    #[arg(long, default_value = "all")]
    formats: String,

    /// Output JSON path.
    #[arg(long)]
    out: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    let formats = parse_formats(&args.formats)?;
    let fixtures = load_fixtures(&args.prompts)?;
    if fixtures.is_empty() {
        anyhow::bail!("no .txt fixtures found in {}", args.prompts.display());
    }

    let model: Box<dyn Model> = match args.provider.as_str() {
        "anthropic" => {
            let api_key = std::env::var("ANTHROPIC_API_KEY")
                .context("set $ANTHROPIC_API_KEY for --provider anthropic")?;
            Box::new(AnthropicProvider::new(&args.model, api_key))
        }
        other => anyhow::bail!("unknown provider {other:?}; supported: anthropic"),
    };

    let mut results = Vec::with_capacity(fixtures.len() * formats.len());
    for (idx, fixture) in fixtures.iter().enumerate() {
        for format in &formats {
            tracing::info!(
                fixture = %fixture.name,
                format = %format,
                "evaluating"
            );
            let n = idx + 1;
            let r = evaluate(
                &fixture.name,
                &fixture.text,
                &fixture.secret_text,
                &fixture.secret_type,
                *format,
                n,
                model.as_ref(),
            )
            .await?;
            results.push(r);
        }
    }

    let json = serde_json::to_string_pretty(&results)?;
    fs::write(&args.out, json).with_context(|| format!("write {}", args.out.display()))?;
    tracing::info!(out = %args.out.display(), n = results.len(), "wrote results");
    Ok(())
}

fn parse_formats(s: &str) -> Result<Vec<PlaceholderFormat>> {
    if s == "all" {
        return Ok(PlaceholderFormat::all().to_vec());
    }
    s.split(',').map(|p| p.trim().parse()).collect()
}

struct Fixture {
    name: String,
    secret_text: String,
    secret_type: String,
    text: String,
}

fn load_fixtures(dir: &std::path::Path) -> Result<Vec<Fixture>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("read_dir {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("txt") {
            continue;
        }
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow!("non-utf8 fixture name: {}", path.display()))?
            .to_string();
        let raw = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let fixture = parse_fixture(&name, &raw)
            .with_context(|| format!("parse fixture {}", path.display()))?;
        out.push(fixture);
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

fn parse_fixture(name: &str, raw: &str) -> Result<Fixture> {
    let mut secret_text = None;
    let mut secret_type = None;
    let mut body_lines = Vec::new();
    let mut in_body = false;

    for line in raw.lines() {
        if !in_body {
            if let Some(rest) = line.strip_prefix("SECRET_TEXT=") {
                secret_text = Some(rest.to_string());
                continue;
            }
            if let Some(rest) = line.strip_prefix("SECRET_TYPE=") {
                secret_type = Some(rest.to_string());
                continue;
            }
            if line.trim().is_empty() {
                in_body = true;
                continue;
            }
            // A non-blank, non-header line means we're in the body.
            in_body = true;
        }
        body_lines.push(line);
    }

    let secret_text = secret_text.ok_or_else(|| anyhow!("missing SECRET_TEXT= header"))?;
    let secret_type = secret_type.ok_or_else(|| anyhow!("missing SECRET_TYPE= header"))?;
    let text = body_lines.join("\n");

    if !text.contains(&secret_text) {
        anyhow::bail!(
            "fixture body does not contain SECRET_TEXT={secret_text:?}; \
             the substitution would be a no-op"
        );
    }

    Ok(Fixture {
        name: name.to_string(),
        secret_text,
        secret_type,
        text,
    })
}
