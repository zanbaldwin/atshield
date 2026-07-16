use crate::de_via_fromstr;
use serde::Serialize;
use serde::de::{Deserialize, Deserializer};
use std::fmt;
use std::str::FromStr;

/// A syntactically valid ATProto handle (a domain name), held in bare normalised
/// form: no leading `@`, lowercased, no trailing dot. [`Display`](fmt::Display)
/// and [`Serialize`] expose that same bare form (no wire shape uses the `@`);
/// [`protocol`](Self::protocol) and [`handle`](Self::handle) build the decorated
/// `at://`/`@` forms. Construct via [`FromStr`], which normalises any of the
/// accepted spellings; `Deserialize` routes through it, so a corrupt or
/// hand-edited persisted handle fails at load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handle(String);
impl Handle {
    /// The bare domain form (no `@`, lowercased) — the same string
    /// [`Display`](fmt::Display) and [`AsRef`] expose.
    pub fn domain(&self) -> &str {
        &self.0
    }

    /// The `at://` alias form, as published in a PLC operation's `alsoKnownAs`.
    pub fn protocol(&self) -> String {
        format!("at://{}", self.0)
    }

    /// The `@`-prefixed form — UI decoration, used on no wire shape.
    pub fn handle(&self) -> String {
        format!("@{}", self.0)
    }

    /// Check `domain` against the subset of ATProto handle syntax atshield accepts:
    /// a domain of two or more LDH labels (ASCII letters, digits, hyphens), each
    /// label 1-63 bytes with no leading or trailing hyphen, total length 1-253 bytes,
    /// and a top-level label that starts with a letter (which rejects bare IPs
    /// and numeric TLDs). Returns
    ///
    /// # Errors
    /// Returns a string naming the first rule that fails.
    fn validate(domain: impl AsRef<str>) -> Result<(), &'static str> {
        let domain = domain.as_ref();
        if domain.is_empty() || domain.len() > 253 {
            return Err("handle length out of range (1-253)");
        }
        let labels: Vec<&str> = domain.split('.').collect();
        if labels.len() < 2 {
            return Err("handle must be a domain with at least two labels");
        }
        for label in &labels {
            let bytes = label.as_bytes();
            if bytes.is_empty() || bytes.len() > 63 {
                return Err("invalid label length (1-63)");
            }
            if bytes.first() == Some(&b'-') || bytes.last() == Some(&b'-') {
                return Err("label has a leading/trailing hyphen");
            }
            if !bytes.iter().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-')) {
                return Err("invalid characters in handle");
            }
        }
        // The top-level label must start with a letter (rejects IPs and numeric TLDs).
        let tld_ok = labels.last().and_then(|t| t.as_bytes().first()).is_some_and(u8::is_ascii_lowercase);
        if !tld_ok {
            return Err("top-level label must start with a letter");
        }
        Ok(())
    }
}
impl Serialize for Handle {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_ref())
    }
}
impl<'de> Deserialize<'de> for Handle {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        de_via_fromstr(deserializer)
    }
}
impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl FromStr for Handle {
    type Err = String;
    /// Trim, strip an optional leading `@` or `at://` scheme (case-insensitive),
    /// strip a trailing dot, lowercase, then validate the domain syntax.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let s = s
            .strip_prefix('@')
            .or_else(|| {
                // We already allocate when lowercasing below, avoid it here.
                s.split_at_checked(5).filter(|(scheme, _)| scheme.eq_ignore_ascii_case("at://")).map(|(_, rest)| rest)
            })
            .unwrap_or(s);
        let s = s.strip_suffix('.').unwrap_or(s).to_lowercase();
        Self::validate(&s)?;
        Ok(Self(s))
    }
}
impl TryFrom<String> for Handle {
    type Error = String;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}
impl AsRef<str> for Handle {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_normalises_and_optional_at() {
        // The `@` is optional now (the old crate required it); a trailing dot and
        // mixed case are both folded away.
        assert_eq!("alice.bsky.social".parse::<Handle>().unwrap().domain(), "alice.bsky.social");
        assert_eq!("@Alice.BSKY.social.".parse::<Handle>().unwrap().domain(), "alice.bsky.social");
        assert_eq!("@zanbaldwin.com".parse::<Handle>().unwrap().domain(), "zanbaldwin.com");
    }

    #[test]
    fn parse_rejects_junk_and_ips() {
        // Since core's `Handle` replaced the local wrapper, an invalid handle
        // errs at clap's arg parse (its usage error), no longer `CliError::Usage`.
        let rejects = |s: &str| s.parse::<Handle>().is_err();
        assert!(rejects("@nodot"));
        assert!(rejects("nodot"));
        assert!(rejects("1.2.3.4"));
        assert!(rejects("@1.2.3.4"));
        assert!(rejects("@-bad.example"));
        assert!(rejects("a_b.example"));
    }

    // The wire and display forms are the bare domain — the `@` is UI
    // decoration, not part of any ATProto wire shape. (This deliberately
    // changed the `--json` output contract: pre-@-stripping consumers beware.)
    #[test]
    fn display_and_serialize_are_bare() {
        let handle: Handle = "@alice.bsky.social".parse().unwrap();
        assert_eq!(handle.to_string(), "alice.bsky.social");
        assert_eq!(serde_json::to_string(&handle).unwrap(), "\"alice.bsky.social\"");
    }

    // One spelling per normalisation rule: trim, scheme case-insensitivity,
    // optional `@`, trailing dot, lowercasing.
    #[test]
    fn deserialize_normalises_like_fromstr() {
        let handle: Handle = serde_json::from_str(r#"" AT://Alice.BSKY.social. ""#).unwrap();
        assert_eq!(handle.as_ref(), "alice.bsky.social");
    }

    // Deserialize routes through `validate`, so a corrupt persisted handle
    // fails at load rather than flowing onwards.
    #[test]
    fn deserialize_rejects_invalid_at_load() {
        assert!(serde_json::from_str::<Handle>(r#""not_a_handle""#).is_err());
        assert!(serde_json::from_str::<Handle>(r#""1.2.3.4""#).is_err());
        assert!(serde_json::from_str::<Handle>(r#""at://@double.example""#).is_err());
    }

    // The wire form is the bare domain; `@`/`at://` are opt-in decoration.
    #[test]
    fn serialize_is_the_bare_string() {
        let handle: Handle = "@alice.bsky.social".parse().unwrap();
        assert_eq!(serde_json::to_string(&handle).unwrap(), r#""alice.bsky.social""#);
        assert_eq!(handle.protocol(), "at://alice.bsky.social");
        assert_eq!(handle.handle(), "@alice.bsky.social");
    }
}
