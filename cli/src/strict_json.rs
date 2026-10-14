use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::fmt;

struct StrictValue(Value);
impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("bounded JSON with unique keys and integer numbers")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut result = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if result.contains_key(&key) || result.len() >= 1024 {
                        return Err(de::Error::custom("duplicate key or too many keys"));
                    }
                    result.insert(key, map.next_value::<StrictValue>()?.0);
                }
                Ok(StrictValue(Value::Object(result)))
            }
            fn visit_seq<S: SeqAccess<'de>>(
                self,
                mut sequence: S,
            ) -> Result<Self::Value, S::Error> {
                let mut result = Vec::new();
                while let Some(value) = sequence.next_element::<StrictValue>()? {
                    if result.len() >= 1024 {
                        return Err(de::Error::custom("array too long"));
                    }
                    result.push(value.0);
                }
                Ok(StrictValue(Value::Array(result)))
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictValue(value.into()))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(StrictValue(value.into()))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                if value > i64::MAX as u64 {
                    return Err(de::Error::custom("integer out of range"));
                }
                Ok(StrictValue(value.into()))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(StrictValue(value.into()))
            }
            fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
                Ok(StrictValue(value.into()))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
        }
        deserializer.deserialize_any(StrictVisitor)
    }
}
pub fn parse(bytes: &[u8]) -> std::io::Result<Value> {
    let StrictValue(value) = serde_json::from_slice::<StrictValue>(bytes)?;
    fn depth(value: &Value, level: usize) -> bool {
        level <= 16
            && match value {
                Value::Object(fields) => fields.values().all(|child| depth(child, level + 1)),
                Value::Array(items) => items.iter().all(|child| depth(child, level + 1)),
                _ => true,
            }
    }
    if !value.is_object() || !depth(&value, 0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid JSON object/depth",
        ));
    }
    Ok(value)
}
