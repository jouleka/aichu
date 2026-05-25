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
    PlaceholderFormat, load_fixtures, model::Model,
    providers::{anthropic::AnthropicProvider, openai::OpenAiProvider},
    run_loop,
};

#[derive(Debug, Parser)]
#[command(name = "e03-placeholder-eval")]
struct Args {
    /// Directory containing `.txt` fixture files.
    #[arg(long)]
    prompts: PathBuf,

    /// Provider to run against: `anthropic` or `openai`.
    #[arg(long, default_value = "anthropic")]
    provider: String,

    /// Anthropic model id (e.g. `claude-opus-4-7-20250514`), or an OpenAI
    /// model id (e.g. `gpt-5-mini`) when `--provider openai`.
    #[arg(long, default_value = "claude-opus-4-7-20250514")]
    model: String,

    /// Comma-separated list of placeholder formats, or `all`.
    #[arg(long, default_value = "all")]
    formats: String,

    /// Optional path to a UTF-8 text file whose contents are sent as a
    /// system-prompt prefix on every call. Omit for the zero-shot
    /// baseline (build-plan §9 option (a) is the targeted experiment).
    #[arg(long)]
    instructions: Option<PathBuf>,

    /// Output JSON path. Refreshed after every cell — a kill mid-run
    /// leaves a valid JSON array of however many cells completed.
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

    let instructions = match &args.instructions {
        Some(p) => Some(
            fs::read_to_string(p)
                .with_context(|| format!("read --instructions file {}", p.display()))?,
        ),
        None => None,
    };

    let model: Box<dyn Model> = match args.provider.as_str() {
        "anthropic" => {
            let api_key = std::env::var("ANTHROPIC_API_KEY")
                .context("set $ANTHROPIC_API_KEY for --provider anthropic")?;
            Box::new(AnthropicProvider::new(&args.model, api_key))
        }
        "openai" => {
            let api_key = std::env::var("OPENAI_API_KEY")
                .context("set $OPENAI_API_KEY for --provider openai")?;
            Box::new(OpenAiProvider::new(&args.model, api_key))
        }
        other => anyhow::bail!("unknown provider {other:?}; supported: anthropic, openai"),
    };

    let results = run_loop(
        &fixtures,
        &formats,
        model.as_ref(),
        instructions.as_deref(),
        &args.out,
    )
    .await?;

    tracing::info!(out = %args.out.display(), n = results.len(), "wrote results");
    Ok(())
}

fn parse_formats(s: &str) -> Result<Vec<PlaceholderFormat>> {
    if s == "all" {
        return Ok(PlaceholderFormat::all().to_vec());
    }
    s.split(',').map(|p| p.trim().parse()).collect()
}
