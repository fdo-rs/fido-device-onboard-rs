use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter, Result as FmtResult};

/// Encodes all of the parameters that can go into the Set-Cookie header
#[derive(Default, Serialize, Deserialize, Clone)]
pub struct CookieOptions {
    pub cookie_name: &'static str,
    pub cookie_value: Option<String>,
    pub max_age: Option<u64>,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<SameSiteCookieOption>,
}

impl Display for CookieOptions {
    /// Outputs a string compatible with the Set-Cookie header
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let cookie_value = match &self.cookie_value {
            Some(cv) => cv,
            None => "",
        };
        let mut header_str = format!("{}={}", self.cookie_name, cookie_value);
        if let Some(max_age) = &self.max_age {
            header_str += &format!("; Max-Age={}", max_age);
        }
        if let Some(domain) = &self.domain {
            header_str += &format!("; Domain={}", domain);
        }
        if let Some(path) = &self.path {
            header_str += &format!("; Path={}", path);
        }
        if self.secure {
            header_str += "; Secure";
        }
        if self.http_only {
            header_str += "; HttpOnly";
        }
        if let Some(same_site) = &self.same_site {
            header_str = match same_site {
                SameSiteCookieOption::None => header_str + "; SameSite=None",
                SameSiteCookieOption::Lax => header_str + "; SameSite=Lax",
                SameSiteCookieOption::Strict => header_str + "; SameSite=Strict",
            }
        }

        write!(f, "{}", header_str)
    }
}

/// Encodes the SameSite cookie option, which can be either
/// None, Lax, Strict, or not provided at all. If not provided,
/// browsers will typically default to Lax. This behavior, however,
/// is vendor-dependent.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum SameSiteCookieOption {
    None,
    Lax,
    Strict,
}

/// Default SameSite option is Lax
impl Default for SameSiteCookieOption {
    fn default() -> Self {
        SameSiteCookieOption::Lax
    }
}

#[cfg(test)]
mod tests {
    use super::{CookieOptions, SameSiteCookieOption};

    #[test]
    fn test_default_cookie_options_are_correct() {
        let default_cookie = CookieOptions::default();
        assert_eq!(default_cookie.cookie_name, "");
        assert_eq!(default_cookie.cookie_value, None);
        assert_eq!(default_cookie.max_age, None);
        assert_eq!(default_cookie.domain, None);
        assert_eq!(default_cookie.path, None);
        assert_eq!(default_cookie.secure, false);
        assert_eq!(default_cookie.http_only, false);
        assert_eq!(default_cookie.same_site, None);
    }

    #[test]
    fn test_default_samesite_cookie_option_is_correct() {
        let same_site_option = SameSiteCookieOption::default();
        assert_eq!(same_site_option, SameSiteCookieOption::Lax);
    }

    #[test]
    fn test_default_cookie_string_is_correct() {
        let default_cookie = CookieOptions::default();
        let cookie_string: String = default_cookie.to_string();
        assert_eq!(cookie_string, "=");
    }

    #[test]
    fn test_cookie_name_string_is_added() {
        let cookie = CookieOptions {
            cookie_name: "key",
            cookie_value: None,
            max_age: None,
            domain: None,
            path: None,
            secure: false,
            http_only: false,
            same_site: None,
        };
        assert_eq!(cookie.to_string(), "key=");
    }

    #[test]
    fn test_cookie_value_string_is_added() {
        let cookie = CookieOptions {
            cookie_name: "",
            cookie_value: Some("value".to_string()),
            max_age: None,
            domain: None,
            path: None,
            secure: false,
            http_only: false,
            same_site: None,
        };
        assert_eq!(cookie.to_string(), "=value");
    }

    #[test]
    fn test_cookie_age_string_is_added() {
        let cookie = CookieOptions {
            cookie_name: "",
            cookie_value: None,
            max_age: Some(100),
            domain: None,
            path: None,
            secure: false,
            http_only: false,
            same_site: None,
        };
        assert_eq!(cookie.to_string(), "=; Max-Age=100");
    }

    #[test]
    fn test_cookie_domain_string_is_added() {
        let cookie = CookieOptions {
            cookie_name: "",
            cookie_value: None,
            max_age: None,
            domain: Some("domain.com".to_string()),
            path: None,
            secure: false,
            http_only: false,
            same_site: None,
        };
        assert_eq!(cookie.to_string(), "=; Domain=domain.com");
    }

    #[test]
    fn test_cookie_path_string_is_added() {
        let cookie = CookieOptions {
            cookie_name: "",
            cookie_value: None,
            max_age: None,
            domain: None,
            path: Some("/some/path".to_string()),
            secure: false,
            http_only: false,
            same_site: None,
        };
        assert_eq!(cookie.to_string(), "=; Path=/some/path");
    }

    #[test]
    fn test_cookie_secure_string_is_added() {
        let cookie = CookieOptions {
            cookie_name: "",
            cookie_value: None,
            max_age: None,
            domain: None,
            path: None,
            secure: true,
            http_only: false,
            same_site: None,
        };
        assert_eq!(cookie.to_string(), "=; Secure");
    }

    #[test]
    fn test_cookie_httponly_string_is_added() {
        let cookie = CookieOptions {
            cookie_name: "",
            cookie_value: None,
            max_age: None,
            domain: None,
            path: None,
            secure: false,
            http_only: true,
            same_site: None,
        };
        assert_eq!(cookie.to_string(), "=; HttpOnly");
    }

    #[test]
    fn test_cookie_samesite_strict_string_is_added() {
        let cookie = CookieOptions {
            cookie_name: "",
            cookie_value: None,
            max_age: None,
            domain: None,
            path: None,
            secure: false,
            http_only: false,
            same_site: Some(SameSiteCookieOption::Strict),
        };
        assert_eq!(cookie.to_string(), "=; SameSite=Strict");
    }

    #[test]
    fn test_cookie_samesite_lax_string_is_added() {
        let cookie = CookieOptions {
            cookie_name: "",
            cookie_value: None,
            max_age: None,
            domain: None,
            path: None,
            secure: false,
            http_only: false,
            same_site: Some(SameSiteCookieOption::Lax),
        };
        assert_eq!(cookie.to_string(), "=; SameSite=Lax");
    }

    #[test]
    fn test_cookie_samesite_none_string_is_added() {
        let cookie = CookieOptions {
            cookie_name: "",
            cookie_value: None,
            max_age: None,
            domain: None,
            path: None,
            secure: false,
            http_only: false,
            same_site: Some(SameSiteCookieOption::None),
        };
        assert_eq!(cookie.to_string(), "=; SameSite=None");
    }

    #[test]
    fn test_cookie_with_mixed_options_string_is_correct() {
        let cookie = CookieOptions {
            cookie_name: "sid",
            cookie_value: Some("abc123".to_string()),
            max_age: Some(100),
            domain: None,
            path: None,
            secure: false,
            http_only: true,
            same_site: Some(SameSiteCookieOption::Strict),
        };
        assert_eq!(
            cookie.to_string(),
            "sid=abc123; Max-Age=100; HttpOnly; SameSite=Strict"
        );
    }
}
