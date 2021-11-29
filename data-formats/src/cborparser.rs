use std::slice::SliceIndex;

use thiserror::Error;

use paste::paste;

use crate::{constants::HashType, types::Hash, Error, Serializable};

mod private {
    pub trait Sealed {}
    impl Sealed for super::ParsedArraySizeDynamic {}
    impl Sealed for super::ParsedArraySize1 {}
    impl Sealed for super::ParsedArraySize2 {}
    impl Sealed for super::ParsedArraySize3 {}
    impl Sealed for super::ParsedArraySize4 {}
    impl Sealed for super::ParsedArraySize5 {}
    impl Sealed for super::ParsedArraySize6 {}
}

macro_rules! parsed_array_size {
    ($size:literal) => {
        paste! {
            #[derive(Debug, Clone)]
            pub struct [<ParsedArraySize $size>] {}
            impl ParsedArraySize for [<ParsedArraySize $size>] {
                const SIZE: Option<usize> = Some($size);
            }
            impl ParsedArraySizeStatic for [<ParsedArraySize $size>] {}
        }
    };
}

macro_rules! check_bounds {
    ($n:ident) => {
        if let Some(expected_len) = N::SIZE {
            if $n > expected_len {
                panic!("Out of bounds");
            }
        }
    };
}

pub trait ParsedArraySize: private::Sealed {
    const SIZE: Option<usize>;
}
pub trait ParsedArraySizeStatic: ParsedArraySize {}

#[derive(Debug, Clone)]
pub struct ParsedArraySizeDynamic {}
impl ParsedArraySize for ParsedArraySizeDynamic {
    const SIZE: Option<usize> = None;
}

parsed_array_size!(1);
parsed_array_size!(2);
parsed_array_size!(3);
parsed_array_size!(4);
parsed_array_size!(5);
parsed_array_size!(6);

#[derive(Clone)]
pub struct ParsedArray<N: ParsedArraySize> {
    tag: Option<u64>,
    contents: Vec<Vec<u8>>,

    _marker: std::marker::PhantomData<N>,
}

impl<N: ParsedArraySize> std::fmt::Debug for ParsedArray<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedArray")
            .field("tag", &self.tag)
            .field(
                "contents",
                &self.contents.iter().map(hex::encode).collect::<Vec<_>>(),
            )
            .finish()
    }
}

#[derive(Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum ArrayParseError {
    #[error("Invalid top level type encountered: must be array")]
    InvalidTopLevelType,
    #[error("Invalid array length")]
    LengthParseFailure,
    #[error("Invalid major type encountered: {0}")]
    InvalidMajorType(u8),
    #[error("Parse failure: {0}")]
    ParseFailure(&'static str),
    #[error("Unsupported major type: {0}")]
    UnsupportedMajorType(u8),
    #[error("Invalid number of elements encountered: {0} received, {1} expected")]
    InvalidNumberOfElements(usize, usize),
    #[error("Insufficient data to decode")]
    InsufficientData,
}

const MASK_TYPE: u8 = 0b1110_0000;
const MASK_VAL: u8 = 0b0001_1111;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum MajorType {
    Unsigned = 0,
    Negative = 1,
    ByteString = 2,
    TextString = 3,
    Array = 4,
    Map = 5,
    Tag = 6,
    Special = 7,
}

impl MajorType {
    fn maybe_from_u8(val: u8) -> Result<Self, ArrayParseError> {
        match val >> 5 {
            0 => Ok(MajorType::Unsigned),
            1 => Ok(MajorType::Negative),
            2 => Ok(MajorType::ByteString),
            3 => Ok(MajorType::TextString),
            4 => Ok(MajorType::Array),
            5 => Ok(MajorType::Map),
            6 => Ok(MajorType::Tag),
            7 => Ok(MajorType::Special),
            n => Err(ArrayParseError::InvalidMajorType(n)),
        }
    }
}

fn length_size(minor: u8) -> Result<usize, ArrayParseError> {
    match minor {
        0..=23 => Ok(0),
        24 => Ok(1), // uint8_t
        25 => Ok(2), // uint16_t
        26 => Ok(4), // uint32_t
        27 => Ok(8), // uint64_t
        _ => Err(ArrayParseError::LengthParseFailure),
    }
}

fn parse_length(data: &[u8]) -> Result<usize, ArrayParseError> {
    match data[0] & MASK_VAL {
        0..=23 => Ok((data[0] & MASK_VAL) as usize),
        24 => Ok(data[1] as usize),
        25 => Ok(u16::from_be_bytes([data[1], data[2]]) as usize),
        26 => Ok(u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize),
        27 => Ok(u64::from_be_bytes([
            data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
        ]) as usize),
        _ => Err(ArrayParseError::LengthParseFailure),
    }
}

fn encode_item_start(major_type: MajorType, val: u64) -> Vec<u8> {
    // We currently only support arrays that fit in a single byte
    // TODO: support arrays that are larger than 24
    // (This is only a possible problem for ownership voucher entries)
    assert!(val <= 24);

    vec![((major_type as u8) << 5) | ((val as u8) & MASK_VAL)]
}

#[derive(Debug)]
struct SafeData<'a>(&'a [u8]);

impl<'a> SafeData<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self(data)
    }

    fn get<I>(&self, index: I) -> Result<&<I as SliceIndex<[u8]>>::Output, Error>
    where
        I: SliceIndex<[u8]>,
    {
        self.0
            .get(index)
            .ok_or_else(|| Error::from(ArrayParseError::InsufficientData))
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

impl<N: ParsedArraySize> Serializable for ParsedArray<N> {
    fn deserialize_from_reader<R>(mut reader: R) -> Result<Self, Error>
    where
        R: std::io::Read,
    {
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        Self::deserialize_data(&data)
    }

    fn serialize_to_writer<W>(&self, mut writer: W) -> Result<(), Error>
    where
        W: std::io::Write,
    {
        let output = self.serialize_data()?;
        writer.write_all(&output)?;
        Ok(())
    }

    fn serialize_data(&self) -> Result<Vec<u8>, Error> {
        let result_len: usize = self.contents.iter().map(|v| v.len()).sum::<usize>();

        let mut result = Vec::new();
        if let Some(tag) = self.tag {
            result.extend_from_slice(&encode_item_start(MajorType::Tag, tag));
        }
        result.extend_from_slice(&encode_item_start(
            MajorType::Array,
            self.contents.len() as u64,
        ));

        result.reserve_exact(result_len);

        for item in &self.contents {
            result.extend_from_slice(item);
        }

        Ok(result)
    }

    fn deserialize_data(data: &[u8]) -> Result<Self, Error> {
        let data = SafeData::new(data);

        // Parse JUST the top-level array, leave everything else as raw binary things
        let mut parsed_items = Vec::new();

        let first_major_type = MajorType::maybe_from_u8(data.get(0)? & MASK_TYPE)?;
        let (data, tag) = match first_major_type {
            MajorType::Tag => {
                let tag_val_size = length_size(data.get(0)? & MASK_VAL)?;
                let tag_val = parse_length(data.get(..=tag_val_size)?)?;

                (
                    SafeData::new(data.get(1 + tag_val_size..)?),
                    Some(tag_val as u64),
                )
            }
            MajorType::Array => (data, None),
            _ => return Err(Error::from(ArrayParseError::InvalidTopLevelType)),
        };

        let first_major_type = MajorType::maybe_from_u8(data.get(0)? & MASK_TYPE)?;
        if first_major_type != MajorType::Array {
            return Err(Error::from(ArrayParseError::InvalidTopLevelType));
        }

        let map_len_size = length_size(data.get(0)? & MASK_VAL)?;
        let map_len = parse_length(data.get(0..=map_len_size)?)?;

        let start_index = map_len_size + 1;

        if let Some(expected_len) = N::SIZE {
            if map_len != expected_len {
                log::warn!("Expected {} elements, but found {}", expected_len, map_len);
                return Err(ArrayParseError::InvalidNumberOfElements(map_len, expected_len).into());
            }
        } else if map_len == 0 {
            return Ok(ParsedArray {
                tag,
                contents: Vec::new(),

                _marker: std::marker::PhantomData,
            });
        }

        let mut left_at_depth = vec![map_len];
        let mut current_top_level_index = start_index;
        let mut index = 1;
        while index < data.len() {
            if left_at_depth.is_empty() {
                return Err(ArrayParseError::ParseFailure("Too many items in array").into());
            }

            let major_type = MajorType::maybe_from_u8(data.get(index)? & MASK_TYPE)?;
            let minor = data.get(index)? & MASK_VAL;

            let (tag_len, major_type, minor) = if major_type == MajorType::Tag {
                let tag_val_size = length_size(minor)?;
                let major_type =
                    MajorType::maybe_from_u8(data.get(index + tag_val_size + 1)? & MASK_TYPE)?;
                let minor = data.get(index + tag_val_size + 1)? & MASK_VAL;
                (tag_val_size + 1, major_type, minor)
            } else {
                (0, major_type, minor)
            };
            index += tag_len;

            let value_len: usize;

            match major_type {
                MajorType::Unsigned | MajorType::Negative => {
                    let len_size = length_size(minor)?;
                    value_len = 1 + len_size;
                }
                MajorType::ByteString | MajorType::TextString => {
                    let len_size = length_size(minor)?;
                    let length = parse_length(data.get(index..=index + len_size)?)?;
                    value_len = 1 + len_size + length;
                }
                MajorType::Array => {
                    let len_size = length_size(minor)?;
                    let length = parse_length(data.get(index..=index + len_size)?)?;
                    value_len = 1 + len_size;
                    if length != 0 {
                        left_at_depth.insert(0, length);
                    }
                }
                MajorType::Map => {
                    let len_size = length_size(minor)?;
                    let length = parse_length(data.get(index..=index + len_size)?)?;
                    value_len = 1 + len_size;
                    if length != 0 {
                        // With a map, "length" is the number of key-value pairs, so there are 2 * length items.
                        // We do not actually need to parse the values in the Map, as long as we determine the correct
                        // stop position.
                        left_at_depth.insert(0, length * 2);
                    }
                }
                n => return Err(ArrayParseError::UnsupportedMajorType(n as u8).into()),
            }

            let index_end = index + value_len;

            if left_at_depth.len() == 1 {
                // This was the end of an item at the top level
                parsed_items.push(data.get(current_top_level_index..index_end)?.to_vec());
                current_top_level_index = index_end;
            }
            if left_at_depth[0] == 1 {
                // This was the last item, we're now back in the higher level array
                left_at_depth.remove(0);
            } else if left_at_depth[0] == 0 {
                // This should not happen, but let's check
                return Err(
                    ArrayParseError::ParseFailure("Array parse encountered 0 items left").into(),
                );
            } else {
                left_at_depth[0] -= 1;
            }

            index = index_end;
        }

        if !left_at_depth.is_empty() {
            return Err(ArrayParseError::ParseFailure("Too few items in array").into());
        }
        if let Some(expected_size) = N::SIZE {
            if parsed_items.len() != expected_size {
                return Err(ArrayParseError::ParseFailure("Too many items in array").into());
            }
        }

        Ok(ParsedArray {
            tag,
            contents: parsed_items,

            _marker: std::marker::PhantomData,
        })
    }
}

impl ParsedArray<ParsedArraySizeDynamic> {
    pub fn new_empty() -> Self {
        Self {
            tag: None,
            contents: Vec::new(),

            _marker: std::marker::PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        self.contents.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn push<T>(&mut self, item: &T) -> Result<(), Error>
    where
        T: Serializable,
    {
        self.contents.push(item.serialize_data()?);
        Ok(())
    }
}

impl<N: ParsedArraySize> ParsedArray<N>
where
    N: ParsedArraySizeStatic,
{
    /// This creates a new ParsedArray
    ///
    /// # Safety
    /// This is unsafe because the caller needs to make sure that the entries
    /// are filled directly after the array.
    /// This means that between the call to this new and the update entries, the
    /// state of the contents of this array is undefined.
    // TODO: Turn this into a builder perhaps?
    pub unsafe fn new() -> Self {
        let new = vec![vec![]; N::SIZE.unwrap()];
        Self {
            tag: None,
            contents: new,

            _marker: std::marker::PhantomData,
        }
    }

    pub fn set<T>(&mut self, n: usize, value: &T) -> Result<(), Error>
    where
        T: Serializable,
    {
        check_bounds!(n);
        self.contents[n] = value.serialize_data()?;
        Ok(())
    }

    pub fn get_hash_two_items(
        &self,
        a: usize,
        b: usize,
        hash_type: HashType,
    ) -> Result<Hash, Error> {
        check_bounds!(a);
        check_bounds!(b);

        let mut data = Vec::with_capacity(self.contents[a].len() + self.contents[b].len());
        data.extend_from_slice(&self.contents[a]);
        data.extend_from_slice(&self.contents[b]);

        Hash::from_data(hash_type, &data)
    }
}

impl<N: ParsedArraySize> ParsedArray<N> {
    pub fn get<T>(&self, n: usize) -> Result<T, Error>
    where
        T: Serializable,
    {
        check_bounds!(n);
        T::deserialize_data(&self.contents[n])
    }

    pub fn get_hash(&self, n: usize, hash_type: HashType) -> Result<Hash, Error> {
        check_bounds!(n);
        Hash::from_data(hash_type, &self.contents[n])
    }

    pub fn tag(&self) -> Option<u64> {
        self.tag
    }

    pub fn set_tag(&mut self, new_tag: Option<u64>) {
        self.tag = new_tag;
    }

    // This is only used for tests: in production, we use the `nth_item` method
    // to ensure that bounds are checked and explicit data is requested, and the
    // to_vec method for serializing.
    #[cfg(test)]
    fn raw_values(&self) -> Vec<Vec<u8>> {
        self.contents.clone()
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use super::ParsedArray;
    use crate::Serializable;

    #[test]
    fn test_empty_array_static() {
        let data = vec![0x80];
        let parsed: Result<ParsedArray<super::ParsedArraySize1>, _> =
            ParsedArray::deserialize_data(&data);
        if let Err(crate::Error::ArrayParseError(
            super::ArrayParseError::InvalidNumberOfElements(0, 1),
        )) = parsed
        {
            assert!(true);
        } else {
            panic!("Received: {:?}", parsed);
        }
    }

    #[test]
    fn test_empty_array_dynamic() {
        let data = vec![0x80];
        let parsed: ParsedArray<super::ParsedArraySizeDynamic> =
            ParsedArray::deserialize_data(&data).expect("Failed to parse");
        assert_eq!(parsed.len(), 0);
        let serialized = parsed.serialize_data().expect("Failed to serialize");
        assert_eq!(serialized, data);
    }

    #[test]
    fn test_nested_empty_array_dynamic() {
        let data = vec![0x81, 0x80];
        let parsed: ParsedArray<super::ParsedArraySize1> =
            ParsedArray::deserialize_data(&data).expect("Failed to parse");
        let nested: ParsedArray<super::ParsedArraySizeDynamic> =
            parsed.get(0).expect("Failed to get nested array");
        assert_eq!(nested.len(), 0);
        let serialized = parsed.serialize_data().expect("Failed to serialize");
        assert_eq!(serialized, data);
    }

    #[test]
    fn test_dynamic_array_push() {
        let data = vec![0x82, 0x01, 0x02];
        let mut parsed: ParsedArray<super::ParsedArraySizeDynamic> =
            ParsedArray::deserialize_data(&data).expect("Failed to parse");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed.get::<u8>(0).unwrap(), 1);
        assert_eq!(parsed.get::<u8>(1).unwrap(), 2);
        let serialized = parsed.serialize_data().expect("Failed to serialize");
        assert_eq!(serialized, data);

        parsed.push(&3).expect("Failed to push");
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed.get::<u8>(0).unwrap(), 1);
        assert_eq!(parsed.get::<u8>(1).unwrap(), 2);
        assert_eq!(parsed.get::<u8>(2).unwrap(), 3);
        let serialized = parsed.serialize_data().expect("Failed to serialize");
        assert_eq!(serialized, vec![0x83, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_array_with_two_integers() {
        let data = vec![0x82, 0x01, 0x02];
        let parsed: ParsedArray<super::ParsedArraySize2> =
            ParsedArray::deserialize_data(&data).expect("Failed to parse");
        assert_eq!(parsed.raw_values(), vec![vec![0x01], vec![0x02]]);
        assert_eq!(parsed.get::<u8>(0).unwrap(), 1);
        assert_eq!(parsed.get::<u8>(1).unwrap(), 2);
        assert_eq!(parsed.tag(), None);
        let serialized = parsed.serialize_data().expect("Failed to serialize");
        assert_eq!(serialized, data);
    }

    #[test]
    fn test_array_with_two_integers_and_tag() {
        let data = vec![0xc6, 0x82, 0x01, 0x02];
        let parsed: ParsedArray<super::ParsedArraySize2> =
            ParsedArray::deserialize_data(&data).expect("Failed to parse");
        assert_eq!(parsed.raw_values(), vec![vec![0x01], vec![0x02]]);
        assert_eq!(parsed.get::<u8>(0).unwrap(), 1);
        assert_eq!(parsed.get::<u8>(1).unwrap(), 2);
        assert_eq!(parsed.tag(), Some(6));
        let serialized = parsed.serialize_data().expect("Failed to serialize");
        assert_eq!(serialized, data);
    }

    #[test]
    fn test_array_with_two_integers_and_nested_tag() {
        let data = vec![0x82, 0xc6, 0x01, 0x02];
        let parsed: ParsedArray<super::ParsedArraySize2> =
            ParsedArray::deserialize_data(&data).expect("Failed to parse");
        assert_eq!(parsed.raw_values(), vec![vec![0xc6, 0x01], vec![0x02]]);
        let item_0: serde_cbor::tags::Tagged<u8> = parsed.get(0).unwrap();
        assert_eq!(item_0.tag, Some(6));
        assert_eq!(item_0.value, 1);
        assert_eq!(parsed.get::<u8>(1).unwrap(), 2);
        assert_eq!(parsed.tag(), None);
        let serialized = parsed.serialize_data().expect("Failed to serialize");
        assert_eq!(serialized, data);
    }

    #[test]
    fn test_update_array_with_two_integers() {
        let data = vec![0x82, 0x01, 0x02];
        let mut parsed: ParsedArray<super::ParsedArraySize2> =
            ParsedArray::deserialize_data(&data).expect("Failed to parse");
        assert_eq!(parsed.raw_values(), vec![vec![0x01], vec![0x02]]);
        assert_eq!(parsed.get::<u8>(0).unwrap(), 1);
        assert_eq!(parsed.get::<u8>(1).unwrap(), 2);
        let new = 3;
        parsed.set(1, &new).expect("Failed to update");
        assert_eq!(parsed.get::<u8>(1).unwrap(), 3);
        let serialized = parsed.serialize_data().expect("Failed to serialize");
        assert_eq!(serialized, vec![0x82, 0x01, 0x03]);
    }

    #[test]
    #[should_panic]
    fn test_panic_with_nth_larger() {
        let data = vec![0x82, 0x01, 0x02];
        let parsed: ParsedArray<super::ParsedArraySize3> =
            ParsedArray::deserialize_data(&data).expect("Failed to parse");
        assert_eq!(parsed.raw_values(), vec![vec![0x01], vec![0x02]]);
        // This panics, since 3 > 2
        let _ = parsed.get::<u32>(3);
    }

    #[test]
    fn test_array_with_empty_map() {
        let data = vec![0x81, 0xA0];
        let parsed: ParsedArray<super::ParsedArraySize1> =
            ParsedArray::deserialize_data(&data).expect("Failed to parse");
        assert_eq!(parsed.raw_values(), vec![vec![0xA0]]);
        assert_eq!(
            parsed.get::<HashMap<u8, u8>>(0).unwrap(),
            maplit::hashmap! {}
        );
        assert_eq!(parsed.tag(), None);
        let serialized = parsed.serialize_data().expect("Failed to serialize");
        assert_eq!(serialized, data);
    }

    #[test]
    fn test_array_with_integer_map() {
        let data = vec![0x81, 0xA1, 0x01, 0x02];
        let parsed: ParsedArray<super::ParsedArraySize1> =
            ParsedArray::deserialize_data(&data).expect("Failed to parse");
        assert_eq!(parsed.raw_values(), vec![vec![0xA1, 0x01, 0x02]]);
        assert_eq!(
            parsed.get::<HashMap<u8, u8>>(0).unwrap(),
            maplit::hashmap! {1 => 2}
        );
        assert_eq!(parsed.tag(), None);
        let serialized = parsed.serialize_data().expect("Failed to serialize");
        assert_eq!(serialized, data);
    }

    #[test]
    fn test_array_with_tagged_integer_map() {
        let data = vec![0x81, 0xC6, 0xA1, 0x01, 0x02];
        let parsed: ParsedArray<super::ParsedArraySize1> =
            ParsedArray::deserialize_data(&data).expect("Failed to parse");
        assert_eq!(parsed.raw_values(), vec![vec![0xC6, 0xA1, 0x01, 0x02]]);
        if let serde_cbor::Value::Tag(6, value) = parsed.get(0).unwrap() {
            if let serde_cbor::Value::Map(values) = *value {
                assert_eq!(values.len(), 1);
                if let serde_cbor::Value::Integer(2) =
                    values.get(&serde_cbor::Value::Integer(1)).unwrap()
                {
                    // Correct
                } else {
                    panic!("Invalid value");
                }
            } else {
                panic!("Not a map found");
            }
        } else {
            panic!("Not a tag found");
        }
        assert_eq!(parsed.tag(), None);
        let serialized = parsed.serialize_data().expect("Failed to serialize");
        assert_eq!(serialized, data);
    }

    #[test]
    fn test_array_with_nested_integer_map() {
        let data = vec![0x81, 0xA1, 0x01, 0xA1, 0x02, 0x03];
        let parsed: ParsedArray<super::ParsedArraySize1> =
            ParsedArray::deserialize_data(&data).expect("Failed to parse");
        assert_eq!(
            parsed.raw_values(),
            vec![vec![0xA1, 0x01, 0xA1, 0x02, 0x03]]
        );
        assert_eq!(
            parsed.get::<HashMap<u8, HashMap<u8, u8>>>(0).unwrap(),
            maplit::hashmap! {1 => maplit::hashmap! {2 => 3}}
        );
        assert_eq!(parsed.tag(), None);
        let serialized = parsed.serialize_data().expect("Failed to serialize");
        assert_eq!(serialized, data);
    }

    #[test]
    fn test_array_with_nested_integers() {
        let data = vec![0x83, 0x01, 0x82, 0x03, 0x04, 0x02];
        let parsed: ParsedArray<super::ParsedArraySize3> =
            ParsedArray::deserialize_data(&data).expect("Failed to parse");
        assert_eq!(
            parsed.raw_values(),
            vec![vec![0x01], vec![0x82, 0x03, 0x04], vec![0x02]]
        );
        assert_eq!(parsed.get::<u8>(0).unwrap(), 1);
        assert_eq!(parsed.get::<Vec<u8>>(1).unwrap(), vec![3, 4]);
        assert_eq!(parsed.get::<u8>(2).unwrap(), 2);
        let serialized = parsed.serialize_data().expect("Failed to serialize");
        assert_eq!(serialized, data);
    }

    #[test]
    fn test_array_with_string() {
        let data = vec![0x83, 0x01, 0x64, 0x74, 0x65, 0x73, 0x74, 0x03];
        let parsed: ParsedArray<super::ParsedArraySize3> =
            ParsedArray::deserialize_data(&data).expect("Failed to parse");
        assert_eq!(
            parsed.raw_values(),
            vec![vec![0x01], vec![0x64, 0x74, 0x65, 0x73, 0x74], vec![0x03]]
        );
        assert_eq!(parsed.get::<u8>(0).unwrap(), 1);
        assert_eq!(parsed.get::<String>(1).unwrap(), "test");
        assert_eq!(parsed.get::<u8>(2).unwrap(), 3);
        let serialized = parsed.serialize_data().expect("Failed to serialize");
        assert_eq!(serialized, data);
    }

    #[test]
    fn complicated_message() {
        let data = hex::decode("8550cbf6ca589001016cafa4e5c15fb6b2885045c751c1c96532c81ca670028d9903e16745434448333834674132353647434d82382240").unwrap();
        let parsed: ParsedArray<super::ParsedArraySize5> =
            ParsedArray::deserialize_data(&data).expect("Failed to parse");
        assert_eq!(
            parsed.raw_values(),
            vec![
                hex::decode("50CBF6CA589001016CAFA4E5C15FB6B288").unwrap(),
                hex::decode("5045C751C1C96532C81CA670028D9903E1").unwrap(),
                hex::decode("6745434448333834").unwrap(),
                hex::decode("674132353647434D").unwrap(),
                hex::decode("82382240").unwrap(),
            ]
        );
        let serialized = parsed.serialize_data().expect("Failed to serialize");
        assert_eq!(serialized, data);
    }

    #[test]
    fn complicated_message_with_nested_tag() {
        let data = hex::decode("8550cbf6ca589001016cafa4e5c15fb6b2885045c751c1c96532c81ca670028d9903e16745434448333834674132353647434dc682382240").unwrap();
        let parsed: ParsedArray<super::ParsedArraySize5> =
            ParsedArray::deserialize_data(&data).expect("Failed to parse");
        assert_eq!(
            parsed.raw_values(),
            vec![
                hex::decode("50CBF6CA589001016CAFA4E5C15FB6B288").unwrap(),
                hex::decode("5045C751C1C96532C81CA670028D9903E1").unwrap(),
                hex::decode("6745434448333834").unwrap(),
                hex::decode("674132353647434D").unwrap(),
                hex::decode("C682382240").unwrap(),
            ]
        );
        let serialized = parsed.serialize_data().expect("Failed to serialize");
        assert_eq!(serialized, data);
    }

    #[test]
    fn complicated_message_with_deeply_nested_tag() {
        let data = hex::decode("8550cbf6ca589001016cafa4e5c15fb6b2885045c751c1c96532c81ca670028d9903e16745434448333834674132353647434d82c6382240").unwrap();
        let parsed: ParsedArray<super::ParsedArraySize5> =
            ParsedArray::deserialize_data(&data).expect("Failed to parse");
        assert_eq!(
            parsed.raw_values(),
            vec![
                hex::decode("50CBF6CA589001016CAFA4E5C15FB6B288").unwrap(),
                hex::decode("5045C751C1C96532C81CA670028D9903E1").unwrap(),
                hex::decode("6745434448333834").unwrap(),
                hex::decode("674132353647434D").unwrap(),
                hex::decode("82C6382240").unwrap(),
            ]
        );
        let serialized = parsed.serialize_data().expect("Failed to serialize");
        assert_eq!(serialized, data);
    }

    #[test]
    fn complicated_message_with_u8_string() {
        let data = hex::decode("8650CBF6CA589001016CAFA4E5C15FB6B2885045C751C1C96532C81CA670028D9903E16745434448333834674132353647434D7830736F6D652D737472696E672D77686963682D73686F756C642D62652D6C6F6E6765722D7468616E2D32342D627974657382382240").unwrap();
        let parsed: ParsedArray<super::ParsedArraySize6> =
            ParsedArray::deserialize_data(&data).expect("Failed to parse");
        assert_eq!(
            parsed.raw_values(), vec![
                hex::decode("50CBF6CA589001016CAFA4E5C15FB6B288").unwrap(),
                hex::decode("5045C751C1C96532C81CA670028D9903E1").unwrap(),
                hex::decode("6745434448333834").unwrap(),
                hex::decode("674132353647434D").unwrap(),
                hex::decode("7830736F6D652D737472696E672D77686963682D73686F756C642D62652D6C6F6E6765722D7468616E2D32342D6279746573").unwrap(),
                hex::decode("82382240").unwrap(),
            ]
        );
        let serialized = parsed.serialize_data().expect("Failed to serialize");
        assert_eq!(serialized, data);
    }

    #[test]
    fn complicated_message_with_u16_string() {
        let data = hex::decode("8650CBF6CA589001016CAFA4E5C15FB6B2885045C751C1C96532C81CA670028D9903E16745434448333834674132353647434D790102736F6D652D737472696E672D77686963682D73686F756C642D62652D6C6F6E6765722D7468616E2D3235352D62797465732D737563682D746861742D69742D676F65732D6F6E2D666F722D6C6F6E6765722D7468616E2D666974732D696E2D612D75696E74385F743A20566573746962756C756D2061742073656D206E657175652E204E756C6C616D206120616C697175616D206E756C6C612C206120696163756C697320616E74652E20436C61737320617074656E742074616369746920736F63696F737175206164206C69746F726120746F727175656E742070657220636F6E75626961206E6F737472612C2070657220696E636570746F732070726F696E2E82382240").unwrap();
        let parsed: ParsedArray<super::ParsedArraySize6> =
            ParsedArray::deserialize_data(&data).expect("Failed to parse");
        assert_eq!(
            parsed.raw_values(), vec![
                hex::decode("50CBF6CA589001016CAFA4E5C15FB6B288").unwrap(),
                hex::decode("5045C751C1C96532C81CA670028D9903E1").unwrap(),
                hex::decode("6745434448333834").unwrap(),
                hex::decode("674132353647434D").unwrap(),
                hex::decode("790102736F6D652D737472696E672D77686963682D73686F756C642D62652D6C6F6E6765722D7468616E2D3235352D62797465732D737563682D746861742D69742D676F65732D6F6E2D666F722D6C6F6E6765722D7468616E2D666974732D696E2D612D75696E74385F743A20566573746962756C756D2061742073656D206E657175652E204E756C6C616D206120616C697175616D206E756C6C612C206120696163756C697320616E74652E20436C61737320617074656E742074616369746920736F63696F737175206164206C69746F726120746F727175656E742070657220636F6E75626961206E6F737472612C2070657220696E636570746F732070726F696E2E").unwrap(),
                hex::decode("82382240").unwrap(),
            ]
        );
        let serialized = parsed.serialize_data().expect("Failed to serialize");
        assert_eq!(serialized, data);
    }

    #[test]
    fn complicated_message_with_u16_string_and_tag() {
        let data = hex::decode("8650CBF6CA589001016CAFA4E5C15FB6B2885045C751C1C96532C81CA670028D9903E16745434448333834674132353647434DC6790102736F6D652D737472696E672D77686963682D73686F756C642D62652D6C6F6E6765722D7468616E2D3235352D62797465732D737563682D746861742D69742D676F65732D6F6E2D666F722D6C6F6E6765722D7468616E2D666974732D696E2D612D75696E74385F743A20566573746962756C756D2061742073656D206E657175652E204E756C6C616D206120616C697175616D206E756C6C612C206120696163756C697320616E74652E20436C61737320617074656E742074616369746920736F63696F737175206164206C69746F726120746F727175656E742070657220636F6E75626961206E6F737472612C2070657220696E636570746F732070726F696E2E82382240").unwrap();
        let parsed: ParsedArray<super::ParsedArraySize6> =
            ParsedArray::deserialize_data(&data).expect("Failed to parse");
        assert_eq!(
            parsed.raw_values(), vec![
                hex::decode("50CBF6CA589001016CAFA4E5C15FB6B288").unwrap(),
                hex::decode("5045C751C1C96532C81CA670028D9903E1").unwrap(),
                hex::decode("6745434448333834").unwrap(),
                hex::decode("674132353647434D").unwrap(),
                hex::decode("C6790102736F6D652D737472696E672D77686963682D73686F756C642D62652D6C6F6E6765722D7468616E2D3235352D62797465732D737563682D746861742D69742D676F65732D6F6E2D666F722D6C6F6E6765722D7468616E2D666974732D696E2D612D75696E74385F743A20566573746962756C756D2061742073656D206E657175652E204E756C6C616D206120616C697175616D206E756C6C612C206120696163756C697320616E74652E20436C61737320617074656E742074616369746920736F63696F737175206164206C69746F726120746F727175656E742070657220636F6E75626961206E6F737472612C2070657220696E636570746F732070726F696E2E").unwrap(),
                hex::decode("82382240").unwrap(),
            ]
        );
        let serialized = parsed.serialize_data().expect("Failed to serialize");
        assert_eq!(serialized, data);
    }
}
