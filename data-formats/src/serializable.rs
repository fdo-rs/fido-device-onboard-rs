use crate::Error;

pub trait Serializable {
    fn deserialize_data(data: &[u8]) -> Result<Self, Error>
    where
        Self: Sized;
    fn serialize_data(&self) -> Result<Vec<u8>, Error>;

    fn deserialize_from_reader<R>(mut reader: R) -> Result<Self, Error>
    where
        Self: Sized,
        R: std::io::Read,
    {
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer)?;
        Self::deserialize_data(&buffer)
    }

    fn serialize_to_writer<W>(&self, mut writer: W) -> Result<(), Error>
    where
        W: std::io::Write,
    {
        let serialized = self.serialize_data()?;
        writer.write_all(&serialized).map_err(Error::from)
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

    fn serialize_data(&self) -> Result<Vec<u8>, Error> {
        serde_cbor::to_vec(self).map_err(Error::from)
    }

    fn serialize_to_writer<W>(&self, mut writer: W) -> Result<(), Error>
    where
        W: std::io::Write,
    {
        serde_cbor::to_writer(&mut writer, self).map_err(Error::from)
    }
}
