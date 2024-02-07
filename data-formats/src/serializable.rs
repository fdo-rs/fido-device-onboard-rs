use crate::cborparser::{ParsedArray, ParsedArrayBuilder, ParsedArraySize2};
use crate::publickey::PublicKey;
use crate::types::COSESign;
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

pub trait MaybeSerializable: Serializable {
    fn is_nodata_error(err: &Error) -> bool;

    fn maybe_deserialize_from_reader<R>(reader: R) -> Result<Option<Self>, Error>
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

pub trait DeserializableMany: MaybeSerializable {
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

#[derive(Clone, Debug)]
pub struct StoredItem {
    pub public_key: PublicKey,
    pub to1d: COSESign,
}

impl Serializable for StoredItem {
    fn deserialize_from_reader<R>(reader: R) -> Result<Self, Error>
    where
        R: std::io::Read,
    {
        let contents: ParsedArray<ParsedArraySize2> = ParsedArray::deserialize_from_reader(reader)?;

        let public_key = contents.get(0)?;
        let to1d = contents.get(1)?;

        Ok(StoredItem { public_key, to1d })
    }

    fn serialize_to_writer<W>(&self, writer: W) -> Result<(), Error>
    where
        W: std::io::Write,
    {
        let mut contents: ParsedArrayBuilder<ParsedArraySize2> = ParsedArrayBuilder::new();
        contents.set(0, &self.public_key)?;
        contents.set(1, &self.to1d)?;
        let contents = contents.build();

        contents.serialize_to_writer(writer)
    }
}
