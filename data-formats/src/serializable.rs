use crate::Error;

pub trait Serializable {
    fn deserialize_data(data: &[u8]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Self::deserialize_from_reader(data)
    }

    fn serialize_data(&self) -> Result<Vec<u8>, Error> {
        let mut output = Vec::new();
        self.serialize_to_writer(&mut output)?;
        Ok(output)
    }

    fn deserialize_from_reader<R>(reader: R) -> Result<Self, Error>
    where
        Self: Sized,
        R: std::io::Read;

    fn serialize_to_writer<W>(&self, writer: W) -> Result<(), Error>
    where
        W: std::io::Write;
}

/// Some traits that are currently private, as we don't want to commit ourselves to them
pub(crate) mod private {
    pub trait MaybeSerializable: super::Serializable {
        fn is_nodata_error(err: &super::Error) -> bool;

        fn maybe_deserialize_from_reader<R>(reader: R) -> Result<Option<Self>, super::Error>
        where
            Self: Sized,
            R: std::io::Read,
        {
            match Self::deserialize_from_reader(reader) {
                Ok(value) => Ok(Some(value)),
                Err(err) => {
                    if Self::is_nodata_error(&err) {
                        Ok(None)
                    } else {
                        Err(err)
                    }
                }
            }
        }
    }
}

pub trait DeserializableMany: private::MaybeSerializable {
    fn deserialize_many_from_reader<R>(mut reader: R) -> Result<Vec<Self>, Error>
    where
        Self: Sized,
        R: std::io::Read,
    {
        let mut output = Vec::new();

        while let Some(item) = Self::maybe_deserialize_from_reader(&mut reader)? {
            output.push(item);
        }

        Ok(output)
    }
}

impl<T> Serializable for T
where
    T: serde::Serialize,
    T: serde::de::DeserializeOwned,
{
    fn deserialize_data(data: &[u8]) -> Result<Self, Error> {
        serde_cbor::from_slice(data).map_err(Error::from)
    }

    fn deserialize_from_reader<R>(mut reader: R) -> Result<Self, Error>
    where
        Self: Sized,
        R: std::io::Read,
    {
        serde_cbor::from_reader(&mut reader).map_err(Error::from)
    }

    fn serialize_to_writer<W>(&self, mut writer: W) -> Result<(), Error>
    where
        W: std::io::Write,
    {
        ciborium::ser::into_writer(self, &mut writer).map_err(Error::from)
    }
}

/// A structure that wraps a Vec<u8>, which (de)serializes its contents without
/// any data format. Can be used when some data needs to be read from a file
/// without expecting a CBOR array.
/// Note that the deserialize methods will read the entire contents of the buffer/reader.
/// Do *not* expect to be able to read any other data after using this on a reader.
#[derive(Debug, Clone)]
pub struct PlainBytes(pub Vec<u8>);

impl Serializable for PlainBytes {
    fn deserialize_data(data: &[u8]) -> Result<Self, Error> {
        Ok(PlainBytes(Vec::from(data)))
    }

    fn deserialize_from_reader<R>(mut reader: R) -> Result<Self, Error>
    where
        Self: Sized,
        R: std::io::Read,
    {
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).map_err(Error::from)?;
        Ok(PlainBytes(buffer))
    }

    fn serialize_to_writer<W>(&self, mut writer: W) -> Result<(), Error>
    where
        W: std::io::Write,
    {
        writer.write_all(&self.0).map_err(Error::from)
    }
}
