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
/// Returns the new total, or the [`Overrun`] when a limit is now exceeded.
/// An overflowing sum counts as exceeded even against a `u64::MAX` limit,
/// and the total in the overrun saturates at `u64::MAX`.
pub fn charge(spent: Usage, usage: Usage, budget: &Budget) -> Result<Usage, Overrun> {
    let cost = spent.cost_micro_usd.checked_add(usage.cost_micro_usd);
    let duration = spent.duration_ms.checked_add(usage.duration_ms);
    let total = Usage {
        cost_micro_usd: cost.unwrap_or(u64::MAX),
        duration_ms: duration.unwrap_or(u64::MAX),
    };
    let over = |sum: Option<u64>, limit: u64| sum.is_none_or(|value| value > limit);
    let dimension = if over(cost, budget.cost_micro_usd) {
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
        assert_eq!(charge(zero, zero, &LIMIT), Ok(zero));
        assert_eq!(
            charge(usage(60, 10), usage(39, 10), &LIMIT),
            Ok(usage(99, 20))
        );
        assert_eq!(
            charge(usage(60, 10), usage(40, 10), &LIMIT),
            Ok(usage(100, 20))
        );
        assert_eq!(
            charge(usage(60, 10), usage(41, 10), &LIMIT),
            Err(overrun(BudgetDimension::Cost, usage(101, 20), LIMIT))
        );
        assert_eq!(
            charge(usage(0, 999), usage(0, 1), &LIMIT),
            Ok(usage(0, 1_000))
        );
        assert_eq!(
            charge(usage(0, 999), usage(0, 2), &LIMIT),
            Err(overrun(BudgetDimension::Duration, usage(0, 1_001), LIMIT))
        );
        // Both at once: cost is reported.
        assert_eq!(
            charge(zero, usage(101, 1_001), &LIMIT),
            Err(overrun(BudgetDimension::Cost, usage(101, 1_001), LIMIT))
        );
        // Overflow counts as exceeded even against u64::MAX, and saturates.
        let max = Budget {
            cost_micro_usd: u64::MAX,
            duration_ms: u64::MAX,
        };
        assert_eq!(
            charge(usage(u64::MAX - 1, 0), usage(1, 0), &max),
            Ok(usage(u64::MAX, 0))
        );
        assert_eq!(
            charge(usage(u64::MAX - 1, 0), usage(2, 0), &max),
            Err(overrun(BudgetDimension::Cost, usage(u64::MAX, 0), max))
        );
        assert_eq!(
            charge(usage(0, u64::MAX), usage(0, 1), &max),
            Err(overrun(BudgetDimension::Duration, usage(0, u64::MAX), max))
        );
    }
}
