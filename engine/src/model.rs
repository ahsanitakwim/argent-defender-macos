//! Shared data model. Every finding carries severity and confidence as
//! independent dimensions (risk severity ≠ detection confidence).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    NotAccessible,
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Points deducted from a 100-point security score at full confidence.
    pub fn weight(self) -> f64 {
        match self {
            Severity::Critical => 40.0,
            Severity::High => 20.0,
            Severity::Medium => 8.0,
            Severity::Low => 3.0,
            Severity::Informational | Severity::NotAccessible => 0.0,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Confidence {
    Low,
    Medium,
    High,
    Confirmed,
}

impl Confidence {
    pub fn factor(self) -> f64 {
        match self {
            Confidence::Confirmed => 1.0,
            Confidence::High => 0.8,
            Confidence::Medium => 0.5,
            Confidence::Low => 0.25,
        }
    }
    pub fn from_percent(p: i64) -> Self {
        match p {
            p if p >= 95 => Confidence::Confirmed,
            p if p >= 75 => Confidence::High,
            p if p >= 50 => Confidence::Medium,
            _ => Confidence::Low,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Malware,
    Spyware,
    Stalkerware,
    Ransomware,
    BankingTrojan,
    Rat,
    Adware,
    Pua,
    Phishing,
    Gambling,
    NetworkThreat,
    Permission,
    Configuration,
    Jailbreak,
    Root,
    Anomaly,
    Integrity,
    Limitation,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Subject {
    /// file | package | app | domain | url | device | backup | process | setting
    pub kind: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub category: Category,
    pub severity: Severity,
    pub confidence: Confidence,
    /// Detection engine that produced the finding (yara-x, intel, permission-audit, ...)
    pub engine: String,
    /// Rule / indicator / heuristic name
    pub rule: String,
    pub subject: Subject,
    /// Human-readable, verifiable evidence lines.
    pub evidence: Vec<String>,
    pub recommendation: String,
}

impl Finding {
    pub fn new(
        engine: &str,
        rule: &str,
        title: impl Into<String>,
        category: Category,
        severity: Severity,
        confidence: Confidence,
        subject: Subject,
    ) -> Self {
        let title = title.into();
        let id = crate::hashing::sha256_hex(
            format!("{engine}|{rule}|{}|{}|{}", subject.kind, subject.name, subject.path.clone().unwrap_or_default()).as_bytes(),
        )[..16]
            .to_string();
        Finding {
            id,
            title,
            category,
            severity,
            confidence,
            engine: engine.into(),
            rule: rule.into(),
            subject,
            evidence: vec![],
            recommendation: String::new(),
        }
    }
    pub fn evidence(mut self, e: impl Into<String>) -> Self {
        self.evidence.push(e.into());
        self
    }
    pub fn recommend(mut self, r: impl Into<String>) -> Self {
        self.recommendation = r.into();
        self
    }
}

pub fn subject(kind: &str, name: impl Into<String>) -> Subject {
    Subject { kind: kind.into(), name: name.into(), path: None, sha256: None }
}

/// A declared limitation: something that could not be examined, shown transparently.
pub fn limitation(engine: &str, rule: &str, text: &str, subj: Subject) -> Finding {
    Finding::new(engine, rule, text, Category::Limitation, Severity::NotAccessible, Confidence::Confirmed, subj)
}
