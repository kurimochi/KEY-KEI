pub enum Derivatives {
    Allow,      // Remixable
    ShareAlike, // SA
    Disallow,   // ND
}

pub struct LicenseAsCode {
    pub derivatives: Derivatives,
    pub allow_commercial: bool, // True: Commercial Use Permitted  False: NC
}
