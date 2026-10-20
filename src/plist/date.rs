//! Dates: Core Foundation's absolute time (seconds since 2001-01-01T00:00:00Z) and the civil
//! dates XML plists write. Core Foundation normalises out-of-range fields instead of refusing
//! them (`2026-13-02` is 2027-01-02, hour 25 the next day, 29 February 2025 is 1 March), which
//! [`absolute_from_civil`] reproduces: months carry into the year, days, hours, minutes and
//! seconds count on linearly. The calendar is the proleptic Gregorian one, with a year 0.

const SECONDS_PER_DAY: i64 = 86_400;
/// Days from 1970-01-01 to 2001-01-01.
const EPOCH_2001_DAYS: i64 = 11_323;

/// A civil date and time in UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CivilTime {
    pub year: i64,
    pub month: i64,
    pub day: i64,
    pub hour: i64,
    pub minute: i64,
    pub second: i64,
}

/// Days since 1970-01-01 of a proleptic Gregorian date with `month` in 1..=12 (Howard
/// Hinnant's `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// `(year, month, day)` of a day count since 1970-01-01 (Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Absolute time of a civil time whose fields may be out of range, normalised as Core
/// Foundation normalises them. `None` when the result does not fit.
pub(crate) fn absolute_from_civil(time: CivilTime) -> Option<f64> {
    let month_offset = time.month.checked_sub(1)?;
    let year = time.year.checked_add(month_offset.div_euclid(12))?;
    let month = month_offset.rem_euclid(12) + 1;
    // Hinnant's formulas are exact far beyond any year a date field can hold here.
    if year.unsigned_abs() > 100_000_000_000 {
        return None;
    }
    let days = days_from_civil(year, month, 1)
        .checked_add(time.day.checked_sub(1)?)?
        .checked_sub(EPOCH_2001_DAYS)?;
    let seconds = days
        .checked_mul(SECONDS_PER_DAY)?
        .checked_add(time.hour.checked_mul(3600)?)?
        .checked_add(time.minute.checked_mul(60)?)?
        .checked_add(time.second)?;
    Some(seconds as f64)
}

/// The civil time of an absolute time, seconds rounded down. `None` for values no civil
/// date can show (not finite, or beyond the 64-bit range).
pub(crate) fn civil_from_absolute(absolute: f64) -> Option<CivilTime> {
    let seconds = absolute.floor();
    if !seconds.is_finite() || seconds.abs() > 9.0e15 {
        return None;
    }
    let seconds = seconds as i64;
    let days = seconds.div_euclid(SECONDS_PER_DAY);
    let in_day = seconds.rem_euclid(SECONDS_PER_DAY);
    let (year, month, day) = civil_from_days(days + EPOCH_2001_DAYS);
    Some(CivilTime {
        year,
        month,
        day,
        hour: in_day / 3600,
        minute: in_day % 3600 / 60,
        second: in_day % 60,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn time(year: i64, month: i64, day: i64, hour: i64, minute: i64, second: i64) -> CivilTime {
        CivilTime {
            year,
            month,
            day,
            hour,
            minute,
            second,
        }
    }

    /// The normalisations `plutil` showed (tests/fixtures/plist/xml/date-*.xml).
    #[test]
    fn out_of_range_fields_carry_like_core_foundation() {
        let round_trip =
            |input: CivilTime| civil_from_absolute(absolute_from_civil(input).unwrap()).unwrap();
        assert_eq!(absolute_from_civil(time(2001, 1, 1, 0, 0, 0)), Some(0.0));
        assert_eq!(
            round_trip(time(2026, 13, 2, 3, 4, 5)),
            time(2027, 1, 2, 3, 4, 5)
        );
        assert_eq!(
            round_trip(time(2026, 1, 2, 25, 4, 5)),
            time(2026, 1, 3, 1, 4, 5)
        );
        assert_eq!(
            round_trip(time(2025, 2, 29, 3, 4, 5)),
            time(2025, 3, 1, 3, 4, 5)
        );
        assert_eq!(round_trip(time(0, 1, 1, 0, 0, 0)), time(0, 1, 1, 0, 0, 0));
        assert_eq!(round_trip(time(-1, 1, 1, 0, 0, 0)), time(-1, 1, 1, 0, 0, 0));
        assert_eq!(
            round_trip(time(12026, 1, 2, 3, 4, 5)),
            time(12026, 1, 2, 3, 4, 5)
        );
        assert_eq!(civil_from_absolute(f64::NAN), None);
    }
}
