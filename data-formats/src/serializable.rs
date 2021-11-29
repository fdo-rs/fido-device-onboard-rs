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
