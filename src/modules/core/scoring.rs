use std::collections::HashMap;

use crate::modules::core::models::*;

/// Combines the findings emitted by every rule into ranked `SuspectedCause`s.
///
/// The previous scoring was a hand-picked constant per rule (75.0, 60.0, 90.0)
/// with no model behind it, and two rules describing the same underlying fault
/// produced two unrelated entries. This does three things instead:
///
/// 1. **Corroboration.** Findings sharing a `RootCause` merge into one cause.
///    WHEA events plus a `0x124` bugcheck plus an overclocking driver become a
///    single high-confidence hardware verdict.
/// 2. **Combination by noisy-OR.** Independent evidence for the same cause
///    accumulates without ever exceeding certainty:
///    `combined = 1 - Π(1 - wᵢ)`. Two 60% signals give 84%, not 120%.
/// 3. **Recency.** Evidence is weighted by where it falls in the scan window,
///    so a crash yesterday outranks the same crash three weeks ago.
pub fn combine(findings: Vec<Finding>, window: &ScanWindow) -> Vec<SuspectedCause> {
    let mut buckets: HashMap<String, Vec<Finding>> = HashMap::new();
    let mut order: Vec<String> = Vec::new();

    for finding in findings {
        let key = finding.root_cause.key();
        if !buckets.contains_key(&key) {
            order.push(key.clone());
        }
        buckets.entry(key).or_default().push(finding);
    }

    let mut causes: Vec<SuspectedCause> = order
        .into_iter()
        .filter_map(|key| {
            buckets
                .remove(&key)
                .map(|group| merge_group(key, group, window))
        })
        .collect();

    // The README's headline promise: ranked by confidence, then by score.
    causes.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then(
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
            .then(a.title.cmp(&b.title))
    });

    causes
}

fn merge_group(key: String, mut group: Vec<Finding>, window: &ScanWindow) -> SuspectedCause {
    // Strongest finding leads: it supplies the title and headline prose.
    group.sort_by(|a, b| {
        b.weight
            .partial_cmp(&a.weight)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut inverse = 1.0f32;
    for finding in &group {
        let recency = finding
            .last_seen
            .map(|t| window.recency_weight(t))
            .unwrap_or(1.0);
        let effective = (finding.weight.clamp(0.0, 99.0) / 100.0) * recency;
        inverse *= 1.0 - effective;
    }
    let score = ((1.0 - inverse) * 100.0).clamp(0.0, 99.5);

    let mut contributing_rules: Vec<String> = Vec::new();
    for finding in &group {
        let rule = finding.rule.to_string();
        if !contributing_rules.contains(&rule) {
            contributing_rules.push(rule);
        }
    }

    let confidence = ConfidenceLevel::derive(score, contributing_rules.len());

    let lead = &group[0];
    let title = lead.title.clone();
    let recommendation = lead.recommendation.clone();

    // Every distinct explanation, in strength order, so a merged cause reads as
    // one argument rather than a truncated one.
    let mut explanations: Vec<String> = Vec::new();
    for finding in &group {
        if !finding.explanation.is_empty() && !explanations.contains(&finding.explanation) {
            explanations.push(finding.explanation.clone());
        }
    }

    let mut evidence: Vec<Evidence> = Vec::new();
    let mut seen_evidence: Vec<String> = Vec::new();
    for finding in &group {
        for item in &finding.evidence {
            if !seen_evidence.contains(&item.detail) {
                seen_evidence.push(item.detail.clone());
                evidence.push(item.clone());
            }
        }
    }
    // Newest evidence first; undated evidence sinks below dated evidence.
    evidence.sort_by(|a, b| match (b.timestamp, a.timestamp) {
        (Some(x), Some(y)) => x.cmp(&y),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });

    let mut commands: Vec<RemediationCommand> = Vec::new();
    for finding in &group {
        for cmd in &finding.commands {
            if !commands.iter().any(|c| c.command == cmd.command) {
                commands.push(cmd.clone());
            }
        }
    }

    SuspectedCause {
        id: key,
        title,
        score,
        confidence,
        evidence,
        explanation: explanations.join(" "),
        recommendation,
        commands,
        contributing_rules,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn finding(rule: &'static str, cause: RootCause, weight: f32) -> Finding {
        Finding::new(rule, cause, format!("{rule} finding"), weight)
            .explain("because")
            .recommend("do the thing")
    }

    #[test]
    fn corroborating_findings_merge_into_one_cause() {
        let window = ScanWindow::last_days(7);
        let causes = combine(
            vec![
                finding("WheaRule", RootCause::HardwareError, 70.0),
                finding("BugCheckRule", RootCause::HardwareError, 60.0),
                finding("DiskRule", RootCause::StorageFailure, 80.0),
            ],
            &window,
        );
        assert_eq!(causes.len(), 2, "two root causes, not three findings");
        let hardware = causes.iter().find(|c| c.id == "hardware-error").unwrap();
        assert_eq!(hardware.contributing_rules.len(), 2);
        // Noisy-OR: 1 - (0.30 * 0.40) = 0.88
        assert!(
            hardware.score > 85.0 && hardware.score < 90.0,
            "got {}",
            hardware.score
        );
    }

    #[test]
    fn combined_score_never_exceeds_certainty() {
        let window = ScanWindow::last_days(7);
        let findings: Vec<Finding> = (0..12)
            .map(|_| finding("R", RootCause::HardwareError, 95.0))
            .collect();
        let causes = combine(findings, &window);
        assert!(causes[0].score <= 99.5);
    }

    #[test]
    fn causes_are_ranked_by_confidence_then_score() {
        let window = ScanWindow::last_days(7);
        let causes = combine(
            vec![
                finding("Weak", RootCause::UnsignedDriver, 20.0),
                finding("Strong", RootCause::HardwareError, 95.0),
                finding("Middling", RootCause::ServiceFailure, 55.0),
            ],
            &window,
        );
        let ordering: Vec<&str> = causes.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(
            ordering,
            vec!["hardware-error", "service-failure", "unsigned-driver"]
        );
        assert!(causes[0].confidence >= causes[1].confidence);
        assert!(causes[1].confidence >= causes[2].confidence);
    }

    #[test]
    fn recent_evidence_outranks_identical_stale_evidence() {
        let window = ScanWindow::last_days(30);
        let fresh = combine(
            vec![finding("R", RootCause::HardwareError, 80.0).seen_at(Some(window.until))],
            &window,
        );
        let stale = combine(
            vec![finding("R", RootCause::HardwareError, 80.0).seen_at(Some(window.since))],
            &window,
        );
        assert!(
            fresh[0].score > stale[0].score,
            "fresh {} should beat stale {}",
            fresh[0].score,
            stale[0].score
        );
    }

    #[test]
    fn driver_faults_for_different_modules_stay_separate() {
        let window = ScanWindow::last_days(7);
        let causes = combine(
            vec![
                finding(
                    "R",
                    RootCause::DriverFault {
                        module: "a.sys".into(),
                    },
                    80.0,
                ),
                finding(
                    "R",
                    RootCause::DriverFault {
                        module: "b.sys".into(),
                    },
                    80.0,
                ),
                finding(
                    "R",
                    RootCause::DriverFault {
                        module: "A.SYS".into(),
                    },
                    50.0,
                ),
            ],
            &window,
        );
        // a.sys and A.SYS are the same module; b.sys is not.
        assert_eq!(causes.len(), 2);
    }

    #[test]
    fn evidence_and_commands_are_deduplicated() {
        let window = ScanWindow::last_days(7);
        let now = Utc::now();
        let a = finding("R1", RootCause::StorageFailure, 60.0)
            .evidence(Evidence::at("disk 0 bad block", now))
            .command("chkdsk", "chkdsk /f C:");
        let b = finding("R2", RootCause::StorageFailure, 50.0)
            .evidence(Evidence::at("disk 0 bad block", now - Duration::hours(1)))
            .evidence(Evidence::at("disk 1 controller error", now))
            .command("chkdsk", "chkdsk /f C:");
        let causes = combine(vec![a, b], &window);
        assert_eq!(causes[0].evidence.len(), 2);
        assert_eq!(causes[0].commands.len(), 1);
    }

    #[test]
    fn no_findings_produces_no_causes() {
        assert!(combine(Vec::new(), &ScanWindow::last_days(7)).is_empty());
    }

    use chrono::Utc;
}
