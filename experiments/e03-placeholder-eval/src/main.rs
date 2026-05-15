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

use anyhow::{Context, Result};
use clap::Parser;

use e03_placeholder_eval::{
    PlaceholderFormat, evaluate, load_fixtures, model::Model,
    providers::anthropic::AnthropicProvider,
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
