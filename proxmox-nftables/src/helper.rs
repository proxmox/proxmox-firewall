use std::fmt;
use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug)]
pub struct Null;

impl<'de> Deserialize<'de> for Null {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        match Option::<()>::deserialize(deserializer)? {
            None => Ok(Self),
            Some(_) => Err(D::Error::custom("expected null")),
        }
    }
}

impl Serialize for Null {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_none()
    }
}

impl fmt::Display for Null {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("null")
    }
}

#[derive(Clone, Debug)]
pub struct NfVec<T>(pub(crate) Vec<T>);

impl<T> Default for NfVec<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> NfVec<T> {
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    pub fn one(value: T) -> Self {
        Self(vec![value])
    }
}

impl<T> From<Vec<T>> for NfVec<T> {
    fn from(v: Vec<T>) -> Self {
        Self(v)
    }
}

impl<T> From<NfVec<T>> for Vec<T> {
    fn from(v: NfVec<T>) -> Self {
        v.0
    }
}

impl<T> FromIterator<T> for NfVec<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl<T> std::ops::Deref for NfVec<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> std::ops::DerefMut for NfVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T: Serialize> Serialize for NfVec<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.len() == 1 {
            self[0].serialize(serializer)
        } else {
            self.0.serialize(serializer)
        }
    }
}

macro_rules! visit_value {
    ($( ($visit:ident, $($ty:tt)+), )+) => {
        $(
            fn $visit<E>(self, value: $($ty)+) -> Result<Self::Value, E>
            where
                E: Error,
            {
                T::deserialize(value.into_deserializer()).map(NfVec::one)
            }
        )+
    };
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for NfVec<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{Error, IntoDeserializer};

        struct V<T>(PhantomData<T>);

        impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for V<T> {
            type Value = NfVec<T>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an array or single element")
            }

            fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                Vec::<T>::deserialize(serde::de::value::SeqAccessDeserializer::new(seq)).map(NfVec)
            }

            fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                T::deserialize(serde::de::value::MapAccessDeserializer::new(map)).map(NfVec::one)
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(NfVec::new())
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Ok(NfVec::new())
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                deserializer.deserialize_any(self)
            }

            visit_value! {
                (visit_bool, bool),
                (visit_borrowed_bytes, &'de [u8]),
                (visit_borrowed_str, &'de str),
                (visit_byte_buf, Vec<u8>),
                (visit_bytes, &[u8]),
                (visit_char, char),
                (visit_f32, f32),
                (visit_f64, f64),
                (visit_i8, i8),
                (visit_i16, i16),
                (visit_i32, i32),
                (visit_i64, i64),
                (visit_u8, u8),
                (visit_u16, u16),
                (visit_u32, u32),
                (visit_u64, u64),
                (visit_str, &str),
                (visit_string, String),
            }
        }

        deserializer.deserialize_any(V::<T>(PhantomData))
    }
}
