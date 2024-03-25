use std::fmt::Debug;
use std::str::FromStr;

use async_trait::async_trait;

use crate::error::Result;
use crate::map::Map;
use crate::path;
use crate::value::{Value, ValueKind};

/// Describes a generic _source_ of configuration properties.
pub trait Source: Debug {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync>;

    /// Collect all configuration properties available from this source and return
    /// a Map.
    fn collect(&self) -> Result<Map<String, Value>>;

    /// Collects all configuration properties to a provided cache.
    fn collect_to(&self, cache: &mut Value) -> Result<()> {
        self.collect()?
            .iter()
            .for_each(|(key, val)| set_value(cache, key, val));

        Ok(())
    }
}

fn set_value(cache: &mut Value, key: &str, value: &Value) {
    match path::Expression::from_str(key) {
        // Set using the path
        Ok(expr) => expr.set(cache, value.clone()),

        // Set diretly anyway
        _ => path::Expression::Identifier(key.to_string()).set(cache, value.clone()),
    }
}

/// Describes a generic _source_ of configuration properties capable of using an async runtime.
///
/// At the moment this library does not implement it, although it allows using its implementations
/// within builders.  Due to the scattered landscape of asynchronous runtimes, it is impossible to
/// cater to all needs with one implementation.  Also, this trait might be most useful with remote
/// configuration sources, reachable via the network, probably using HTTP protocol.  Numerous HTTP
/// libraries exist, making it even harder to find one implementation that rules them all.
///
/// For those reasons, it is left to other crates to implement runtime-specific or proprietary
/// details.
///
/// It is advised to use `async_trait` crate while implementing this trait.
///
/// See examples for sample implementation.
#[async_trait]
pub trait AsyncSource: Debug + Sync {
    // Sync is supertrait due to https://docs.rs/async-trait/0.1.50/async_trait/index.html#dyn-traits

    /// Collects all configuration properties available from this source and return
    /// a Map as an async operations.
    async fn collect(&self) -> Result<Map<String, Value>>;

    /// Collects all configuration properties to a provided cache.
    async fn collect_to(&self, cache: &mut Value) -> Result<()> {
        self.collect()
            .await?
            .iter()
            .for_each(|(key, val)| set_value(cache, key, val));

        Ok(())
    }
}

impl Clone for Box<dyn AsyncSource + Send + Sync> {
    fn clone(&self) -> Self {
        self.to_owned()
    }
}

impl Clone for Box<dyn Source + Send + Sync> {
    fn clone(&self) -> Self {
        self.clone_into_box()
    }
}

impl Source for Vec<Box<dyn Source + Send + Sync>> {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new((*self).clone())
    }

    fn collect(&self) -> Result<Map<String, Value>> {
        let mut cache: Value = Map::<String, Value>::new().into();

        for source in self {
            source.collect_to(&mut cache)?;
        }

        if let ValueKind::Table(table) = cache.kind {
            Ok(table)
        } else {
            unreachable!();
        }
    }
}

impl Source for [Box<dyn Source + Send + Sync>] {
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new(self.to_owned())
    }

    fn collect(&self) -> Result<Map<String, Value>> {
        let mut cache: Value = Map::<String, Value>::new().into();

        for source in self {
            source.collect_to(&mut cache)?;
        }

        if let ValueKind::Table(table) = cache.kind {
            Ok(table)
        } else {
            unreachable!();
        }
    }
}

impl<T> Source for Vec<T>
where
    T: Source + Sync + Send + Clone + 'static,
{
    fn clone_into_box(&self) -> Box<dyn Source + Send + Sync> {
        Box::new((*self).clone())
    }

    fn collect(&self) -> Result<Map<String, Value>> {
        let mut cache: Value = Map::<String, Value>::new().into();

        for source in self {
            source.collect_to(&mut cache)?;
        }

        if let ValueKind::Table(table) = cache.kind {
            Ok(table)
        } else {
            unreachable!();
        }
    }
}
