//! Macros for asserting of multiline strings [`String`] and [`&str`].
//! The API is very similar to the API provided by the stdlib's own assert_eq!
//! or assert_ne!. Left and right expression could be different types.
//!
//! # Examples
//!
//! Some examples are provided in the docs for
//! [each individual macro](#macros).
//!
//! [`String`]: https://doc.rust-lang.org/std/string/struct.String.html
//! [`&str`]: https://doc.rust-lang.org/std/str/index.html

/// Asserts that multiline strings([`&str`] or [`String`]) are identical. It
/// ignores different new line characters for different OSes: `\n` or `\r\n`.
///
/// # Examples
///
/// Test on equality of two strings generated on different OSes:
///
/// ```
/// use assert_str::assert_str_eq;
/// assert_str_eq!("This string\nEnd", "This string\r\nEnd", "Responces should be equal");
/// ```
///
#[macro_export]
macro_rules! assert_str_eq {
    ($left:expr, $right:expr) => ({
        match (&$left, &$right) {
            (left_val, right_val) => {
                let left_lines = left_val.lines().collect::<Vec<_>>();
                let right_lines = right_val.lines().collect::<Vec<_>>();
                if !(left_lines == right_lines) {
                    panic!(r#"assertion failed: `(left == right)`
  left: `{}`,
 right: `{}`"#, left_lines.join("\n"), right_lines.join("\n"))
                }
            }
        }
    });
    ($left:expr, $right:expr,) => ({
        $crate::assert_str_eq!($left, $right)
    });
    ($left:expr, $right:expr, $($arg:tt)+) => ({
        match (&$left, &$right) {
            (left_val, right_val) => {
                let left_lines = left_val.lines().collect::<Vec<_>>();
                let right_lines = right_val.lines().collect::<Vec<_>>();
                if !(left_lines == right_lines) {
                    panic!(r#"assertion failed: `(left == right)`
  left: `{}`,
 right: `{}`: {}"#, left_lines.join("\n"), right_lines.join("\n"),
                    format_args!($($arg)+))
                }
            }
        }
    });
}

/// Asserts that multiline strings(`&str` or `String`) are not identical. It
/// ignores different new line characters for different OSes: `\n` or `\r\n`.
///
/// # Examples
///
/// Test on inequality of two strings generated on different OSes:
///
/// ```
/// use assert_str::assert_str_ne;
/// assert_str_ne!("This string\nEnd", "This string\r\nFinalEnd", "Responces should not be equal");
/// ```
///
#[macro_export]
macro_rules! assert_str_ne {
    ($left:expr, $right:expr) => ({
        match (&$left, &$right) {
            (left_val, right_val) => {
                let left_lines = left_val.lines().collect::<Vec<_>>();
                let right_lines = right_val.lines().collect::<Vec<_>>();
                if (left_lines == right_lines) {
                    panic!(r#"assertion failed: `(left != right)`
  left: `{}`,
 right: `{}`"#, left_lines.join("\n"), right_lines.join("\n"))
                }
            }
        }
    });
    ($left:expr, $right:expr,) => ({
        $crate::assert_str_ne!($left, $right)
    });
    ($left:expr, $right:expr, $($arg:tt)+) => ({
        match (&$left, &$right) {
            (left_val, right_val) => {
                let left_lines = left_val.lines().collect::<Vec<_>>();
                let right_lines = right_val.lines().collect::<Vec<_>>();
                if (left_lines == right_lines) {
                    panic!(r#"assertion failed: `(left != right)`
  left: `{}`,
  right: `{}`: {}"#, left_lines.join("\n"), right_lines.join("\n"),
                    format_args!($($arg)+))
                }
            }
        }
    });
}

/// Asserts that multiline strings(`&str` or `String`) are identical when
/// every line is trimmed and empty lines are removed. It ignores different
/// new line characters for different OSes: `\n` or `\r\n`.
///
/// # Examples
///
/// Test on equality of two trimmed strings generated on different OSes:
///
/// ```
/// use assert_str::assert_str_trim_eq;
/// assert_str_trim_eq!("<html>\t \n\t<head> \n\t</head></html>",
///     "<html>\r\n<head>\r\n</head></html>", "Responces should be equal");
/// ```
///
#[macro_export]
macro_rules! assert_str_trim_eq {
    ($left:expr, $right:expr) => ({
        match (&$left, &$right) {
            (left_val, right_val) => {
                let left_lines = left_val
                    .lines()
                    .map(|line| line.trim())
                    .filter(|line| !line.is_empty())
                    .collect::<Vec<_>>();

                let right_lines = right_val
                    .lines()
                    .map(|line| line.trim())
                    .filter(|line| !line.is_empty())
                    .collect::<Vec<_>>();

                if !(left_lines == right_lines) {
                    panic!(r#"assertion failed: `(left == right)`
  left: `{}`,
 right: `{}`"#, left_lines.join("\n"), right_lines.join("\n"))
                }
            }
        }
    });
    ($left:expr, $right:expr,) => ({
        $crate::assert_str_trim_eq!($left, $right)
    });
    ($left:expr, $right:expr, $($arg:tt)+) => ({
        match (&$left, &$right) {
            (left_val, right_val) => {
                let left_lines = left_val
                    .lines()
                    .map(|line| line.trim())
                    .filter(|line| !line.is_empty())
                    .collect::<Vec<_>>();

                let right_lines = right_val
                    .lines()
                    .map(|line| line.trim())
                    .filter(|line| !line.is_empty())
                    .collect::<Vec<_>>();

                if !(left_lines == right_lines) {
                    panic!(r#"assertion failed: `(left == right)`
  left: `{}`,
 right: `{}`: {}"#, left_lines.join("\n"), right_lines.join("\n"),
                    format_args!($($arg)+))
                }
            }
        }
    });
}

/// Asserts that multiline strings([&str] or [String]) are identical. It
/// ignores different new line characters for different OSes: `\n` or `\r\n`
///
/// # Examples
///
/// Test on equality of two trimmed strings:
///
/// ```
/// use assert_str::assert_str_trim_ne;
/// assert_str_trim_ne!("<html>\t \n\t<head> \n\t</head></html>",
///     "<HTML><head></head></html>", "Responces should not be equal");
/// ```
///
#[macro_export]
macro_rules! assert_str_trim_ne {
    ($left:expr, $right:expr) => ({
        match (&$left, &$right) {
            (left_val, right_val) => {
                let left_lines = left_val
                    .lines()
                    .map(|x| x.trim())
                    .filter(|line| !line.is_empty())
                    .collect::<Vec<_>>();

                let right_lines = right_val
                    .lines()
                    .map(|x| x.trim())
                    .filter(|line| !line.is_empty())
                    .collect::<Vec<_>>();

                if (left_lines == right_lines) {
                    panic!(r#"assertion failed: `(left != right)`
  left: `{}`,
 right: `{}`"#, left_lines.join("\n"), right_lines.join("\n"))
                }
            }
        }
    });
    ($left:expr, $right:expr,) => ({
        $crate::assert_str_trim_ne!($left, $right)
    });
    ($left:expr, $right:expr, $($arg:tt)+) => ({
        match (&$left, &$right) {
            (left_val, right_val) => {
                let left_lines = left_val
                    .lines()
                    .map(|x| x.trim())
                    .filter(|line| !line.is_empty())
                    .collect::<Vec<_>>();

                let right_lines = right_val
                    .lines()
                    .map(|x| x.trim())
                    .filter(|line| !line.is_empty())
                    .collect::<Vec<_>>();

                if (left_lines == right_lines) {
                    panic!(r#"assertion failed: `(left != right)`
  left: `{}`,
 right: `{}`: {}"#, left_lines.join("\n"), right_lines.join("\n"),
                    format_args!($($arg)+))
                }
            }
        }
    });
}

/// Asserts that multiline strings(`&str` or `String`) are identical when
/// every line is trimmed and new lines are removed.
///
/// # Examples
///
/// Test on equality of two trimmed strings:
///
/// ```
/// use assert_str::assert_str_trim_all_eq;
/// assert_str_trim_all_eq!("<html>\t \n\t<head> \n\t</head></html>",
///     "<html><head></head></html>", "Responces should be equal");
/// ```
///
#[macro_export]
macro_rules! assert_str_trim_all_eq {
    ($left:expr, $right:expr) => ({
        match (&$left, &$right) {
            (left_val, right_val) => {
                let left_lines = left_val
                    .lines()
                    .map(|line| line.trim())
                    .filter(|line| !line.is_empty())
                    .collect::<Vec<_>>();

                let right_lines = right_val
                    .lines()
                    .map(|line| line.trim())
                    .filter(|line| !line.is_empty())
                    .collect::<Vec<_>>();

                if !(left_lines == right_lines) {
                    panic!(r#"assertion failed: `(left == right)`
  left: `{}`,
 right: `{}`"#, left_lines.join("\n"), right_lines.join("\n"))
                }
            }
        }
    });
    ($left:expr, $right:expr,) => ({
        $crate::assert_str_trim_eq!($left, $right)
    });
    ($left:expr, $right:expr, $($arg:tt)+) => ({
        match (&$left, &$right) {
            (left_val, right_val) => {
                let left_lines = left_val
                    .lines()
                    .map(|line| line.trim())
                    .fold(String::new(), |acc, x| acc + x);

                let right_lines = right_val
                    .lines()
                    .map(|line| line.trim())
                    .fold(String::new(), |acc, x| acc + x);

                if !(left_lines == right_lines) {
                    panic!(r#"assertion failed: `(left == right)`
  left: `{}`,
 right: `{}`: {}"#, left_lines, right_lines,
                    format_args!($($arg)+))
                }
            }
        }
    });
}

/// Asserts that multiline strings([&str] or [String]) are identical when
/// every line is trimmed and new lines are removed.
///
/// # Examples
///
/// Test on inequality of two trimmed strings:
///
/// ```
/// use assert_str::assert_str_trim_all_ne;
/// assert_str_trim_all_ne!("<html>\t \n\t<head> \n\t</head></html>",
///     "<HTML><head></head></html>", "Responces should not be equal");
/// ```
///
#[macro_export]
macro_rules! assert_str_trim_all_ne {
    ($left:expr, $right:expr) => ({
        match (&$left, &$right) {
            (left_val, right_val) => {
                let left_lines = left_val
                    .lines()
                    .map(|x| x.trim())
                    .fold(String::new(), |acc, x| acc + x);

                let right_lines = right_val
                    .lines()
                    .map(|x| x.trim())
                    .fold(String::new(), |acc, x| acc + x);

                if (left_lines == right_lines) {
                    panic!(r#"assertion failed: `(left != right)`
  left: `{}`,
 right: `{}`"#, left_lines, right_lines)
                }
            }
        }
    });
    ($left:expr, $right:expr,) => ({
        $crate::assert_str_trim_ne!($left, $right)
    });
    ($left:expr, $right:expr, $($arg:tt)+) => ({
        match (&$left, &$right) {
            (left_val, right_val) => {
                let left_lines = left_val
                    .lines()
                    .map(|x| x.trim())
                    .fold(String::new(), |acc, x| acc + x);

                let right_lines = right_val
                    .lines()
                    .map(|x| x.trim())
                    .fold(String::new(), |acc, x| acc + x);

                if (left_lines == right_lines) {
                    panic!(r#"assertion failed: `(left != right)`
  left: `{}`,
 right: `{}`: {}"#, left_lines, right_lines,
                    format_args!($($arg)+))
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn cross_str_equal_simple() {
        assert_str_eq!("Line\nLine2", "Line\r\nLine2");
        assert_str_eq!("Line\nLine2".to_owned(), "Line\r\nLine2");
        assert_str_eq!("Line\nLine2", "Line\r\nLine2".to_owned());
        assert_str_eq!("Line\nLine2".to_owned(), "Line\r\nLine2".to_owned());
        assert_str_eq!("Line\nLine2", "Line\r\nLine2",);
    }

    #[test]
    fn cross_str_equal_message() {
        assert_str_eq!("Line\nLine2".to_owned(), "Line\r\nLine2", "Message");
        assert_str_eq!("Line\nLine2", "Line\r\nLine2".to_owned(), "Message");
        assert_str_eq!("L\nLine2".to_owned(), "L\r\nLine2".to_owned(), "Message");
        assert_str_eq!("Line\nLine2", "Line\r\nLine2", "Message");
    }

    #[test]
    fn cross_str_not_equal_simple() {
        assert_str_ne!("Line\nLine2", "Line\r\nLine");
        assert_str_ne!("Line\nLine2".to_owned(), "Line\r\nLine");
        assert_str_ne!("Line\nLine2", "Line\r\nLine".to_owned());
        assert_str_ne!("Line\nLine2", "Line\r\nLine",);
    }

    #[test]
    fn cross_str_not_equal_message() {
        assert_str_ne!("Line\nLine2".to_owned(), "Line\r\nLine", "Message");
        assert_str_ne!("Line\nLine2", "Line\r\nLine".to_owned(), "Message");
        assert_str_ne!("L\nLine2".to_owned(), "L\r\nLine".to_owned(), "Message");
        assert_str_ne!("Line\nLine2", "Line\r\nLine", "Message");
    }

    #[test]
    fn cross_str_trim_equal() {
        let left = "String  \n Line ".to_owned();
        let right = "String\r\nLine".to_owned();
        assert_str_trim_eq!(left, right);
        assert_str_trim_eq!(&left, right);
        assert_str_trim_eq!(left, &right);
        assert_str_trim_eq!(&left, &right);
        assert_str_trim_eq!(left, right,);
    }

    #[test]
    fn cross_str_trim_equal_message() {
        let left = "String  \n Line ".to_owned();
        let right = "String\r\nLine".to_owned();
        assert_str_trim_eq!(&left, right, "Message");
        assert_str_trim_eq!(left, &right, "Message");
        assert_str_trim_eq!(left, right, "Message");
        assert_str_trim_eq!(&left, &right, "Message");
    }

    #[test]
    fn cross_str_trim_not_equal() {
        let left = "String  \n Line ".to_owned();
        let right = "String\r\n12".to_owned();
        assert_str_trim_ne!(left, right);
        assert_str_trim_ne!(&left, right);
        assert_str_trim_ne!(left, &right);
        assert_str_trim_ne!(&left, &right);
        assert_str_trim_ne!(left, right,);
    }

    #[test]
    fn cross_str_trim_not_equal_message() {
        let left = "String  \n Line ".to_owned();
        let right = "String\r\n12".to_owned();
        assert_str_trim_ne!(left, right, "Message");
        assert_str_trim_ne!(&left, right, "Message");
        assert_str_trim_ne!(left, &right, "Message");
        assert_str_trim_ne!(&left, &right, "Message");
    }

    #[test]
    fn cross_str_trim_all_equal() {
        let left = "String  \n Line ".to_owned();
        let right = "String\r\nLine".to_owned();
        assert_str_trim_all_eq!(left, right);
        assert_str_trim_all_eq!(&left, right);
        assert_str_trim_all_eq!(left, &right);
        assert_str_trim_all_eq!(&left, &right);
        assert_str_trim_all_eq!(left, right,);
    }

    #[test]
    fn cross_str_trim_all_equal_message() {
        let left = "String  \n Line ".to_owned();
        let right = "StringLine".to_owned();
        assert_str_trim_all_eq!(&left, right, "Message");
        assert_str_trim_all_eq!(left, &right, "Message");
        assert_str_trim_all_eq!(left, right, "Message");
        assert_str_trim_all_eq!(&left, &right, "Message");
    }

    #[test]
    fn cross_str_trim_all_not_equal() {
        let left = "String  \n Line ".to_owned();
        let right = "Stringline".to_owned();
        assert_str_trim_all_ne!(left, right);
        assert_str_trim_all_ne!(&left, right);
        assert_str_trim_all_ne!(left, &right);
        assert_str_trim_all_ne!(&left, &right);
        assert_str_trim_all_ne!(left, right,);
    }

    #[test]
    fn cross_str_trim_all_not_equal_message() {
        let left = "String  \n Line ".to_owned();
        let right = "String12".to_owned();
        assert_str_trim_all_ne!(left, right, "Message");
        assert_str_trim_all_ne!(&left, right, "Message");
        assert_str_trim_all_ne!(left, &right, "Message");
        assert_str_trim_all_ne!(&left, &right, "Message");
    }
}
