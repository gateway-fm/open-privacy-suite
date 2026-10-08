//! Startup configuration for producer enforcement.
//!
//! Kept free of node dependencies so the enable switch can be tested in isolation.

/// Parses `OPS_APPROVALS`.
///
/// `1` enables approval enforcement. `0` runs the stock, unenforced block builder and exists
/// only for benchmark baselines. Anything else, including an absent variable, refuses startup.
pub fn approvals_enabled(value: Result<String, std::env::VarError>) -> Result<bool, String> {
    match value.as_deref() {
        Ok("1") => Ok(true),
        Ok("0") => Ok(false),
        Err(std::env::VarError::NotPresent) => {
            Err("OPS_APPROVALS is not set: set 1 to enforce OPS approvals, \
             or 0 to run the unenforced stock block builder (benchmarks only)"
                .into())
        }
        _ => Err("OPS_APPROVALS must be 1 (enabled) or 0 (disabled)".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::approvals_enabled;
    use std::env::VarError;

    #[test]
    fn explicit_values_select_the_mode() {
        assert_eq!(approvals_enabled(Ok("1".into())), Ok(true));
        assert_eq!(approvals_enabled(Ok("0".into())), Ok(false));
    }

    #[test]
    fn a_missing_flag_refuses_startup_instead_of_disabling_enforcement() {
        let err = approvals_enabled(Err(VarError::NotPresent)).unwrap_err();
        assert!(err.contains("OPS_APPROVALS"), "{err}");
        assert!(err.contains("not set"), "{err}");
    }

    #[test]
    fn a_malformed_flag_refuses_startup() {
        for value in ["true", "yes", "", " 1", "1 ", "2", "on"] {
            assert!(approvals_enabled(Ok(value.into())).is_err(), "{value:?}");
        }
        assert!(approvals_enabled(Err(VarError::NotUnicode("bad".into()))).is_err());
    }
}
