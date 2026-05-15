// The six candidate placeholder formats from build-plan §7. The point of
// this experiment is to discover which of them survive verbatim across
// frontier-model responses; this module is the parameter space.

use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlaceholderFormat {
    /// `[REDACTED]` — opaque, no type info. Models sometimes "helpfully"
    /// expand this ("please provide your actual key").
    Redacted,
    /// `***` — opaque, no instance info. Deliberate **negative control**:
    /// if our metric doesn't fail this format clearly, the metric is wrong.
    Asterisks,
    /// `{{VAR}}` — Mustache-style template. Triggers template-completion
    /// behavior in models trained on Jinja-style prompts.
    Mustache,
    /// `<SECRET_1>` — Presidio-default style. HTML-tag-shaped tokens are
    /// occasionally flagged by safety filters.
    AngleNum,
    /// `__SECRET_AWS_KEY_001__` — typed and numbered, double-underscore
    /// wrapping. Preservation-friendly; eats 6–8 BPE tokens per occurrence.
    UnderscoreType,
    /// `«SECRET_AWS_KEY_001»` — French guillemets, typed, numbered.
    /// Current top candidate per qualitative testing.
    Guillemets,
}

impl PlaceholderFormat {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Redacted => "redacted",
            Self::Asterisks => "asterisks",
            Self::Mustache => "mustache",
            Self::AngleNum => "angle_num",
            Self::UnderscoreType => "underscore_type",
            Self::Guillemets => "guillemets",
        }
    }

    /// Render the placeholder for a secret of `secret_type` with counter
    /// `n`. `secret_type` is e.g. "AWS_KEY", "ANTHROPIC_KEY", "GENERIC".
    pub fn render(&self, secret_type: &str, n: usize) -> String {
        // Uppercase normalization so callers can pass "aws_key" or "AWS_KEY".
        let t = secret_type.to_uppercase();
        match self {
            Self::Redacted => "[REDACTED]".to_string(),
            Self::Asterisks => "***".to_string(),
            Self::Mustache => format!("{{{{{t}}}}}"),
            Self::AngleNum => format!("<SECRET_{n}>"),
            Self::UnderscoreType => format!("__SECRET_{t}_{n:03}__"),
            Self::Guillemets => format!("\u{ab}SECRET_{t}_{n:03}\u{bb}"),
        }
    }

    pub fn all() -> &'static [PlaceholderFormat] {
        &[
            PlaceholderFormat::Redacted,
            PlaceholderFormat::Asterisks,
            PlaceholderFormat::Mustache,
            PlaceholderFormat::AngleNum,
            PlaceholderFormat::UnderscoreType,
            PlaceholderFormat::Guillemets,
        ]
    }
}

impl fmt::Display for PlaceholderFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for PlaceholderFormat {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> anyhow::Result<Self> {
        match s {
            "redacted" => Ok(Self::Redacted),
            "asterisks" => Ok(Self::Asterisks),
            "mustache" => Ok(Self::Mustache),
            "angle_num" => Ok(Self::AngleNum),
            "underscore_type" => Ok(Self::UnderscoreType),
            "guillemets" => Ok(Self::Guillemets),
            _ => anyhow::bail!("unknown placeholder format: {s}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_produces_expected_string_for_each_format() {
        // These exact strings are the contract — production code parses
        // them out of model responses. A future refactor that changes the
        // shape of any format must update this test in lockstep.
        assert_eq!(
            PlaceholderFormat::Redacted.render("aws_key", 1),
            "[REDACTED]"
        );
        assert_eq!(
            PlaceholderFormat::Asterisks.render("aws_key", 1),
            "***"
        );
        assert_eq!(
            PlaceholderFormat::Mustache.render("aws_key", 1),
            "{{AWS_KEY}}"
        );
        assert_eq!(
            PlaceholderFormat::AngleNum.render("aws_key", 7),
            "<SECRET_7>"
        );
        assert_eq!(
            PlaceholderFormat::UnderscoreType.render("aws_key", 1),
            "__SECRET_AWS_KEY_001__"
        );
        assert_eq!(
            PlaceholderFormat::Guillemets.render("aws_key", 42),
            "\u{ab}SECRET_AWS_KEY_042\u{bb}"
        );
    }

    #[test]
    fn typed_formats_zero_pad_counter_to_three_digits() {
        // Zero-padding ensures placeholders stay sortable and visually
        // consistent across a multi-turn conversation. Locking this in
        // catches a future refactor that drops the `:03` width spec.
        assert_eq!(
            PlaceholderFormat::UnderscoreType.render("anthropic_key", 5),
            "__SECRET_ANTHROPIC_KEY_005__"
        );
        assert_eq!(
            PlaceholderFormat::Guillemets.render("openai_key", 999),
            "\u{ab}SECRET_OPENAI_KEY_999\u{bb}"
        );
    }

    #[test]
    fn name_round_trips_through_from_str() {
        for fmt in PlaceholderFormat::all() {
            let parsed: PlaceholderFormat = fmt.name().parse().unwrap();
            assert_eq!(&parsed, fmt);
        }
    }

    #[test]
    fn from_str_rejects_unknown_format() {
        assert!("nope".parse::<PlaceholderFormat>().is_err());
    }

    #[test]
    fn all_returns_exactly_six_formats() {
        // The eval matrix is parameterized over this list. Any drift here
        // changes the experiment's parameter space.
        assert_eq!(PlaceholderFormat::all().len(), 6);
    }
}
