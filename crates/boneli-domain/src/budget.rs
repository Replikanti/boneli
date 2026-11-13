//! Budget accounting in integer units (ADR-002).
//!
//! Two dimensions: cost in micro-USD and the sum of reported job durations in
//! milliseconds. The domain has no clock; the application measures each job
//! and reports its [`Usage`] with the job's result. Limits are inclusive: a
//! limit is exceeded when the total is greater than it.

/// The limits of one run. Both must be greater than zero
/// ([`crate::Run::new`] rejects a zero).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    /// Cost limit in micro-USD.
    pub cost_micro_usd: u64,
    /// Limit on the sum of job durations, in milliseconds.
    pub duration_ms: u64,
}

/// Consumption: one job's usage, or the running total of a run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    /// Cost in micro-USD.
    pub cost_micro_usd: u64,
    /// Duration in milliseconds.
    pub duration_ms: u64,
}

/// One budget dimension. When one event exceeds both, `Cost` is reported:
/// the fixed order is cost, then duration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BudgetDimension {
    /// [`Budget::cost_micro_usd`].
    Cost,
    /// [`Budget::duration_ms`].
    Duration,
}

/// A crossed limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Overrun {
    /// The first exceeded dimension (cost before duration).
    pub dimension: BudgetDimension,
    /// The total after the crossing event, saturated at `u64::MAX`.
    pub spent: Usage,
    /// The limits.
    pub budget: Budget,
}

/// Adds one job's `usage` to the running total `spent`.
///
/// Returns the new total, or the [`Overrun`] when a limit is exceeded.
/// An overflowing sum counts as exceeded even against a `u64::MAX` limit,
/// and the total in the overrun saturates at `u64::MAX`.
///
/// `crossed` is the dimension an earlier charge of the same run exceeded, if
/// any. A crossing is sticky: a saturated total can equal a `u64::MAX` limit
/// and would read as within it again, so once a limit is crossed every later
/// charge reports that first dimension, with the new total (ADR-002).
pub fn charge(
    spent: Usage,
    usage: Usage,
    budget: &Budget,
    crossed: Option<BudgetDimension>,
) -> Result<Usage, Overrun> {
    let cost = spent.cost_micro_usd.checked_add(usage.cost_micro_usd);
    let duration = spent.duration_ms.checked_add(usage.duration_ms);
    let total = Usage {
        cost_micro_usd: cost.unwrap_or(u64::MAX),
        duration_ms: duration.unwrap_or(u64::MAX),
    };
    let over = |sum: Option<u64>, limit: u64| sum.is_none_or(|value| value > limit);
    let dimension = if let Some(dimension) = crossed {
        dimension
    } else if over(cost, budget.cost_micro_usd) {
        BudgetDimension::Cost
    } else if over(duration, budget.duration_ms) {
        BudgetDimension::Duration
    } else {
        return Ok(total);
    };
    Err(Overrun {
        dimension,
        spent: total,
        budget: *budget,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMIT: Budget = Budget {
        cost_micro_usd: 100,
        duration_ms: 1_000,
    };

    fn usage(cost_micro_usd: u64, duration_ms: u64) -> Usage {
        Usage {
            cost_micro_usd,
            duration_ms,
        }
    }

    fn overrun(dimension: BudgetDimension, spent: Usage, budget: Budget) -> Overrun {
        Overrun {
            dimension,
            spent,
            budget,
        }
    }

    #[test]
    fn charge_boundaries() {
        let zero = Usage::default();
        assert_eq!(charge(zero, zero, &LIMIT, None), Ok(zero));
        assert_eq!(
            charge(usage(60, 10), usage(39, 10), &LIMIT, None),
            Ok(usage(99, 20))
        );
        assert_eq!(
            charge(usage(60, 10), usage(40, 10), &LIMIT, None),
            Ok(usage(100, 20))
        );
        assert_eq!(
            charge(usage(60, 10), usage(41, 10), &LIMIT, None),
            Err(overrun(BudgetDimension::Cost, usage(101, 20), LIMIT))
        );
        assert_eq!(
            charge(usage(0, 999), usage(0, 1), &LIMIT, None),
            Ok(usage(0, 1_000))
        );
        assert_eq!(
            charge(usage(0, 999), usage(0, 2), &LIMIT, None),
            Err(overrun(BudgetDimension::Duration, usage(0, 1_001), LIMIT))
        );
        // Both at once: cost is reported.
        assert_eq!(
            charge(zero, usage(101, 1_001), &LIMIT, None),
            Err(overrun(BudgetDimension::Cost, usage(101, 1_001), LIMIT))
        );
        // Overflow counts as exceeded even against u64::MAX, and saturates.
        let max = Budget {
            cost_micro_usd: u64::MAX,
            duration_ms: u64::MAX,
        };
        assert_eq!(
            charge(usage(u64::MAX - 1, 0), usage(1, 0), &max, None),
            Ok(usage(u64::MAX, 0))
        );
        assert_eq!(
            charge(usage(u64::MAX - 1, 0), usage(2, 0), &max, None),
            Err(overrun(BudgetDimension::Cost, usage(u64::MAX, 0), max))
        );
        assert_eq!(
            charge(usage(0, u64::MAX), usage(0, 1), &max, None),
            Err(overrun(BudgetDimension::Duration, usage(0, u64::MAX), max))
        );
    }

    #[test]
    fn a_crossing_is_sticky() {
        let max = Budget {
            cost_micro_usd: u64::MAX,
            duration_ms: u64::MAX,
        };
        // An overflow saturates the total at the limit itself ...
        let first = charge(usage(u64::MAX - 1, 0), usage(2, 0), &max, None);
        assert_eq!(
            first,
            Err(overrun(BudgetDimension::Cost, usage(u64::MAX, 0), max))
        );
        // ... which alone would read as within the limit again:
        assert_eq!(
            charge(usage(u64::MAX, 0), usage(0, 0), &max, None),
            Ok(usage(u64::MAX, 0))
        );
        // so the run passes the crossed dimension, and it stays exceeded.
        let crossed = Some(BudgetDimension::Cost);
        assert_eq!(
            charge(usage(u64::MAX, 0), usage(0, 0), &max, crossed),
            Err(overrun(BudgetDimension::Cost, usage(u64::MAX, 0), max))
        );
        // The first crossed dimension is kept, with the new total.
        assert_eq!(
            charge(
                usage(0, 1_001),
                usage(500, 5),
                &LIMIT,
                Some(BudgetDimension::Duration)
            ),
            Err(overrun(BudgetDimension::Duration, usage(500, 1_006), LIMIT))
        );
    }
}
