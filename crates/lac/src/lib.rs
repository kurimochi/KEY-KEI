use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Derivatives {
    Allow,      // Remixable
    ShareAlike, // SA
    Disallow,   // ND
}

#[derive(Debug)]
pub struct LicenseAsCode {
    pub derivatives: Derivatives,
    pub allow_commercial: bool, // True: Commercial Use Permitted  False: NC
}

pub fn validate_inheritance(child: LicenseAsCode, parent: LicenseAsCode) -> Result<(), LacError> {
    // Check ND
    if parent.derivatives == Derivatives::Disallow {
        return Err(LacError::NoDerivativesViolation);
    }

    // Check SA
    if parent.derivatives == Derivatives::ShareAlike && parent.derivatives == child.derivatives {
        return Err(LacError::ShareAlikeViolation);
    }

    // Check NC
    if parent.allow_commercial && !child.allow_commercial {
        return Err(LacError::CommercialUseViolation);
    }

    Ok(())
}

#[derive(Debug, Error)]
pub enum LacError {
    #[error("Parent prohibits derivatives (ND)")]
    NoDerivativesViolation,
    #[error("Parent requires exact same License for ShareAlike")]
    ShareAlikeViolation,
    #[error("Commercial use not allowed by parent (NC)")]
    CommercialUseViolation,
}
