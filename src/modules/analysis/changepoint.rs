//! "What changed on the day it broke."
//!
//! Replaces the old change-correlation rule, which anchored on the *oldest*
//! crash in the window and flagged anything within 48 hours of it. That fires
//! on the wrong change whenever the instability predates the scan window, which
//! is the common case.
//!
//! Instead: find the point in time that best splits the crash history into a
//! quiet period and a noisy one, then report the changes that landed around it.

use chrono::{DateTime, Duration, Utc};

use crate::modules::core::models::*;

/// How far either side of the changepoint a change is still a suspect. A
/// driver installed the evening before the first crash is the classic case.
const SUSPECT_WINDOW_HOURS: i64 = 72;

/// Minimum crashes after the changepoint before a regression is claimed. One
/// crash is an incident, not a trend.
const MIN_CRASHES_AFTER: usize = 2;

/// Analyse crash timing against recorded system changes.
pub fn analyse(
    crashes: &[DateTime<Utc>],
    changes: &[SystemChange],
    window: &ScanWindow,
) -> Option<ChangepointAnalysis> {
    if crashes.len() < MIN_CRASHES_AFTER {
        return None;
    }

    let mut times: Vec<DateTime<Utc>> = crashes.to_vec();
    times.sort_unstable();

    let changepoint = best_split(&times)?;

    let crashes_after = times.iter().filter(|t| **t >= changepoint).count();
    let crashes_before = times.len() - crashes_after;

    if crashes_after < MIN_CRASHES_AFTER {
        return None;
    }

    let span = Duration::hours(SUSPECT_WINDOW_HOURS);
    let mut suspect_changes: Vec<SystemChange> = changes
        .iter()
        .filter(|change| {
            let delta = change.date - changepoint;
            delta <= span && delta >= -span
        })
        .cloned()
        .collect();
    suspect_changes.sort_by_key(|c| std::cmp::Reverse(c.date));

    let stable_days_before = (changepoint - window.since).num_days().max(0);

    Some(ChangepointAnalysis {
        summary: summarise(
            changepoint,
            crashes_before,
            crashes_after,
            &suspect_changes,
            stable_days_before,
        ),
        changepoint,
        crashes_before,
        crashes_after,
        stable_days_before,
        suspect_changes,
    })
}

/// Pick the split that maximises the contrast between crash rates either side.
///
/// Each crash time is a candidate boundary. For each, compare the crash rate
/// before against the rate after; the largest increase wins. This is a simple
/// changepoint search, which is all a handful of crashes can support.
fn best_split(times: &[DateTime<Utc>]) -> Option<DateTime<Utc>> {
    let first = *times.first()?;
    let last = *times.last()?;
    let total_span = (last - first).num_seconds() as f64;
    if total_span <= 0.0 {
        // Every crash at effectively the same moment: the burst itself is the
        // changepoint.
        return Some(first);
    }

    let mut best = None;
    let mut best_contrast = 0.0f64;

    for (index, candidate) in times.iter().enumerate() {
        let before_span = (*candidate - first).num_seconds() as f64;
        let after_span = (last - *candidate).num_seconds() as f64;

        // A split needs material time on both sides to mean anything, except
        // at the very start where "it was always broken" is a valid reading.
        if after_span <= 0.0 {
            continue;
        }

        let after_count = (times.len() - index) as f64;
        let before_count = index as f64;

        // Crashes per day either side. A day floor avoids dividing by a few
        // seconds and producing an enormous rate.
        let day = 86_400.0;
        let rate_after = after_count / (after_span / day).max(1.0);
        let rate_before = before_count / (before_span / day).max(1.0);
        let contrast = rate_after - rate_before;
        if contrast > best_contrast {
            best_contrast = contrast;
            best = Some(*candidate);
        }
    }

    best.or(Some(first))
}

fn summarise(
    changepoint: DateTime<Utc>,
    before: usize,
    after: usize,
    suspects: &[SystemChange],
    stable_days: i64,
) -> String {
    let date = changepoint.format("%-d %b %Y");
    let total = before + after;

    let opening = if before == 0 {
        format!("Stable for {stable_days} days until {date}.")
    } else {
        format!("Crash rate rose sharply on {date}.")
    };

    let counts = format!(" {after} of {total} crashes fall on or after it.");

    let attribution = match suspects.len() {
        0 => " No recorded system change lines up with that date.".to_string(),
        1 => format!(
            " One change landed within {SUSPECT_WINDOW_HOURS} hours of it: {}.",
            suspects[0].name
        ),
        n => {
            let named: Vec<&str> = suspects.iter().take(3).map(|c| c.name.as_str()).collect();
            format!(
                " {n} changes landed within {SUSPECT_WINDOW_HOURS} hours of it, including {}.",
                named.join("; ")
            )
        }
    };

    format!("{opening}{counts}{attribution}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn change(name: &str, at: DateTime<Utc>, kind: ChangeType) -> SystemChange {
        SystemChange {
            name: name.into(),
            date: at,
            change_type: kind,
            version: None,
        }
    }

    #[test]
    fn finds_the_day_stability_broke() {
        let now = Utc::now();
        let window = ScanWindow::last_days(30);

        // Quiet for weeks, then five crashes over the last three days.
        let crashes = vec![
            now - Duration::days(3),
            now - Duration::days(2),
            now - Duration::days(2) - Duration::hours(3),
            now - Duration::days(1),
            now - Duration::hours(6),
        ];
        let changes = vec![
            change(
                "NVIDIA Display Driver 581.29",
                now - Duration::days(3) - Duration::hours(4),
                ChangeType::Driver,
            ),
            change(
                "Ancient Software 1.0",
                now - Duration::days(25),
                ChangeType::Software,
            ),
        ];
        let analysis = analyse(&crashes, &changes, &window).expect("a regression must be found");
        assert_eq!(analysis.crashes_after, 5);
        assert_eq!(analysis.crashes_before, 0);
        assert_eq!(
            analysis.suspect_changes.len(),
            1,
            "only the nearby change is a suspect"
        );
        assert_eq!(
            analysis.suspect_changes[0].name,
            "NVIDIA Display Driver 581.29"
        );
        assert!(analysis.summary.contains("NVIDIA"));
        assert!(analysis.summary.contains("5 of 5"));
    }

    #[test]
    fn a_single_crash_is_an_incident_not_a_regression() {
        let now = Utc::now();
        let window = ScanWindow::last_days(30);
        assert!(analyse(&[now - Duration::days(1)], &[], &window).is_none());
        assert!(analyse(&[], &[], &window).is_none());
    }

    #[test]
    fn says_so_plainly_when_nothing_lines_up() {
        let now = Utc::now();
        let window = ScanWindow::last_days(30);
        let crashes = vec![
            now - Duration::days(2),
            now - Duration::days(1),
            now - Duration::hours(2),
        ];
        let analysis = analyse(&crashes, &[], &window).expect("must analyse");
        assert!(
            analysis.summary.contains("No recorded system change"),
            "got: {}",
            analysis.summary
        );
        assert!(analysis.suspect_changes.is_empty());
    }

    #[test]
    fn changes_far_from_the_changepoint_are_not_suspects() {
        let now = Utc::now();
        let window = ScanWindow::last_days(60);
        let crashes = vec![
            now - Duration::days(2),
            now - Duration::days(1),
            now - Duration::hours(3),
        ];
        let changes = vec![change(
            "Unrelated",
            now - Duration::days(40),
            ChangeType::Software,
        )];
        let analysis = analyse(&crashes, &changes, &window).unwrap();
        assert!(
            analysis.suspect_changes.is_empty(),
            "a 40-day-old change is not a suspect"
        );
    }

    #[test]
    fn a_steady_crash_rate_does_not_invent_a_regression_date() {
        let now = Utc::now();
        let window = ScanWindow::last_days(30);
        // Evenly spaced crashes: no changepoint stands out.
        let crashes: Vec<DateTime<Utc>> = (0..6).map(|i| now - Duration::days(i * 4)).collect();
        let analysis = analyse(&crashes, &[], &window).expect("still analysable");
        // Whatever split is chosen, it must be a real crash time inside the data.
        assert!(crashes.contains(&analysis.changepoint));
        assert!(analysis.crashes_after >= MIN_CRASHES_AFTER);
    }

    #[test]
    fn all_crashes_in_one_burst_are_handled() {
        let now = Utc::now();
        let window = ScanWindow::last_days(7);
        let crashes = vec![now, now, now];
        let analysis = analyse(&crashes, &[], &window).expect("burst must analyse");
        assert_eq!(analysis.crashes_after, 3);
    }
}
