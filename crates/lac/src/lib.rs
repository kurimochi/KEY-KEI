use std::fmt;

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

#[derive(Debug)]
pub enum LacError {
    NoDerivativesViolation,
    ShareAlikeViolation,
    CommercialUseViolation,
}

impl fmt::Display for LacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                LacError::NoDerivativesViolation => "Parent prohibits derivatives (ND)",
                LacError::ShareAlikeViolation =>
                    "Parent requires exact same License for ShareAlike",
                LacError::CommercialUseViolation => "Commercial use not allowed by parent (NC)",
            }
        )
    }
}

impl std::error::Error for LacError {}
