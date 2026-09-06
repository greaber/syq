//! Conservative, process-wide accounting for framed input and owned decoded
//! values. Reservations travel with queued messages and are released on drop.
use serde::de::{self, DeserializeSeed, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor};
use serde::Deserialize;
use std::fmt;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, OnceLock};

pub(crate) const MEMORY_LIMIT: usize = 512 << 20;
const RESERVATION_GRANULE: usize = 64 << 10;

#[derive(Debug)]
struct Budget {
    used: AtomicUsize,
    limit: usize,
}

#[derive(Debug)]
pub(crate) struct Hold {
    budget: Arc<Budget>,
    used: usize,
    reserved: usize,
    exhausted: bool,
}

impl Hold {
    pub(crate) fn new() -> Self {
        static BUDGET: OnceLock<Arc<Budget>> = OnceLock::new();
        Self {
            budget: BUDGET
                .get_or_init(|| {
                    Arc::new(Budget {
                        used: AtomicUsize::new(0),
                        limit: MEMORY_LIMIT,
                    })
                })
                .clone(),
            used: 0,
            reserved: 0,
            exhausted: false,
        }
    }

    pub(crate) fn grow(&mut self, bytes: usize) -> io::Result<()> {
        let result = self.try_grow(bytes);
        self.exhausted |= result.is_err();
        result
    }

    fn try_grow(&mut self, bytes: usize) -> io::Result<()> {
        let exhausted = || {
            io::Error::other(
                "framed input memory budget exhausted; reduce connections or pipeline depth",
            )
        };
        let used = self.used.checked_add(bytes).ok_or_else(exhausted)?;
        if used > self.reserved {
            let wanted = used
                .checked_add(RESERVATION_GRANULE - 1)
                .ok_or_else(exhausted)?
                / RESERVATION_GRANULE
                * RESERVATION_GRANULE;
            let extra = wanted - self.reserved;
            self.budget
                .used
                .fetch_update(Relaxed, Relaxed, |current| {
                    current
                        .checked_add(extra)
                        .filter(|total| *total <= self.budget.limit)
                })
                .map_err(|_| exhausted())?;
            self.reserved = wanted;
        }
        self.used = used;
        Ok(())
    }

    fn charge<E: de::Error>(&mut self, bytes: usize) -> Result<(), E> {
        self.grow(bytes).map_err(E::custom)
    }
}

impl Drop for Hold {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.reserved, Relaxed);
    }
}

#[derive(Debug)]
pub(crate) struct Budgeted<T> {
    pub(crate) value: T,
    pub(crate) hold: Hold,
}
impl<T> Budgeted<T> {
    pub(crate) fn into_inner(self) -> T {
        self.value
    }
    pub(crate) fn into_parts(self) -> (T, Hold) {
        (self.value, self.hold)
    }
}

// Postcard's sequence length comes from the peer. Hide size hints to prevent
// eager Vec/HashMap allocation, then charge conservative capacity before each
// element. Eight times element size covers Vec growth (including its minimum
// capacity) and map buckets; strings and byte buffers charge their own storage.
// This is deliberately an upper bound, not an allocator/RSS measurement.
struct Limited<'a, D> {
    inner: D,
    hold: &'a mut Hold,
}
struct LimitedVisitor<'a, V> {
    inner: V,
    hold: &'a mut Hold,
}
struct LimitedSeed<'a, S> {
    inner: S,
    hold: &'a mut Hold,
}
struct LimitedSeq<'a, S> {
    inner: S,
    hold: &'a mut Hold,
}
struct LimitedMap<'a, M> {
    inner: M,
    hold: &'a mut Hold,
}
struct LimitedEnum<'a, E> {
    inner: E,
    hold: &'a mut Hold,
}
struct LimitedVariant<'a, V> {
    inner: V,
    hold: &'a mut Hold,
}

impl<'de, S: DeserializeSeed<'de>> DeserializeSeed<'de> for LimitedSeed<'_, S> {
    type Value = S::Value;
    fn deserialize<D: de::Deserializer<'de>>(self, inner: D) -> Result<Self::Value, D::Error> {
        self.inner.deserialize(Limited {
            inner,
            hold: self.hold,
        })
    }
}
impl<'de, S: SeqAccess<'de>> SeqAccess<'de> for LimitedSeq<'_, S> {
    type Error = S::Error;
    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Self::Error> {
        self.hold
            .charge::<Self::Error>(std::mem::size_of::<T::Value>().max(1).saturating_mul(8))?;
        self.inner.next_element_seed(LimitedSeed {
            inner: seed,
            hold: self.hold,
        })
    }
    fn size_hint(&self) -> Option<usize> {
        None
    }
}
impl<'de, M: MapAccess<'de>> MapAccess<'de> for LimitedMap<'_, M> {
    type Error = M::Error;
    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Self::Error> {
        self.hold
            .charge::<Self::Error>(std::mem::size_of::<K::Value>().max(1).saturating_mul(8))?;
        self.inner.next_key_seed(LimitedSeed {
            inner: seed,
            hold: self.hold,
        })
    }
    fn next_value_seed<V: DeserializeSeed<'de>>(
        &mut self,
        seed: V,
    ) -> Result<V::Value, Self::Error> {
        self.hold
            .charge::<Self::Error>(std::mem::size_of::<V::Value>().max(1).saturating_mul(8))?;
        self.inner.next_value_seed(LimitedSeed {
            inner: seed,
            hold: self.hold,
        })
    }
    fn size_hint(&self) -> Option<usize> {
        None
    }
}
impl<'a, 'de, E: EnumAccess<'de>> EnumAccess<'de> for LimitedEnum<'a, E> {
    type Error = E::Error;
    type Variant = LimitedVariant<'a, E::Variant>;
    fn variant_seed<V: DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, Self::Variant), Self::Error> {
        let (value, inner) = self.inner.variant_seed(LimitedSeed {
            inner: seed,
            hold: self.hold,
        })?;
        Ok((
            value,
            LimitedVariant {
                inner,
                hold: self.hold,
            },
        ))
    }
}
impl<'de, V: VariantAccess<'de>> VariantAccess<'de> for LimitedVariant<'_, V> {
    type Error = V::Error;
    fn unit_variant(self) -> Result<(), Self::Error> {
        self.inner.unit_variant()
    }
    fn newtype_variant_seed<T: DeserializeSeed<'de>>(
        self,
        seed: T,
    ) -> Result<T::Value, Self::Error> {
        self.inner.newtype_variant_seed(LimitedSeed {
            inner: seed,
            hold: self.hold,
        })
    }
    fn tuple_variant<T: Visitor<'de>>(
        self,
        len: usize,
        visitor: T,
    ) -> Result<T::Value, Self::Error> {
        self.inner.tuple_variant(
            len,
            LimitedVisitor {
                inner: visitor,
                hold: self.hold,
            },
        )
    }
    fn struct_variant<T: Visitor<'de>>(
        self,
        fields: &'static [&'static str],
        visitor: T,
    ) -> Result<T::Value, Self::Error> {
        self.inner.struct_variant(
            fields,
            LimitedVisitor {
                inner: visitor,
                hold: self.hold,
            },
        )
    }
}

macro_rules! scalar_visits {
    ($($method:ident: $ty:ty),* $(,)?) => {$(
        fn $method<E: de::Error>(self, value: $ty) -> Result<Self::Value, E> { self.inner.$method(value) }
    )*};
}
impl<'de, V: Visitor<'de>> Visitor<'de> for LimitedVisitor<'_, V> {
    type Value = V::Value;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.inner.expecting(f)
    }
    scalar_visits! { visit_bool: bool, visit_i8: i8, visit_i16: i16, visit_i32: i32, visit_i64: i64,
    visit_i128: i128, visit_u8: u8, visit_u16: u16, visit_u32: u32, visit_u64: u64,
    visit_u128: u128, visit_f32: f32, visit_f64: f64, visit_char: char }
    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        self.inner.visit_unit()
    }
    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        self.inner.visit_none()
    }
    fn visit_some<D: de::Deserializer<'de>>(self, inner: D) -> Result<Self::Value, D::Error> {
        self.inner.visit_some(Limited {
            inner,
            hold: self.hold,
        })
    }
    fn visit_newtype_struct<D: de::Deserializer<'de>>(
        self,
        inner: D,
    ) -> Result<Self::Value, D::Error> {
        self.inner.visit_newtype_struct(Limited {
            inner,
            hold: self.hold,
        })
    }
    fn visit_seq<S: SeqAccess<'de>>(self, inner: S) -> Result<Self::Value, S::Error> {
        self.inner.visit_seq(LimitedSeq {
            inner,
            hold: self.hold,
        })
    }
    fn visit_map<M: MapAccess<'de>>(self, inner: M) -> Result<Self::Value, M::Error> {
        self.inner.visit_map(LimitedMap {
            inner,
            hold: self.hold,
        })
    }
    fn visit_enum<E: EnumAccess<'de>>(self, inner: E) -> Result<Self::Value, E::Error> {
        self.inner.visit_enum(LimitedEnum {
            inner,
            hold: self.hold,
        })
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        self.hold.charge::<E>(value.len())?;
        self.inner.visit_str(value)
    }
    fn visit_borrowed_str<E: de::Error>(self, value: &'de str) -> Result<Self::Value, E> {
        self.hold.charge::<E>(value.len())?;
        self.inner.visit_borrowed_str(value)
    }
    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        self.hold.charge::<E>(value.len())?;
        self.inner.visit_string(value)
    }
    fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
        self.hold.charge::<E>(value.len())?;
        self.inner.visit_bytes(value)
    }
    fn visit_borrowed_bytes<E: de::Error>(self, value: &'de [u8]) -> Result<Self::Value, E> {
        self.hold.charge::<E>(value.len())?;
        self.inner.visit_borrowed_bytes(value)
    }
    fn visit_byte_buf<E: de::Error>(self, value: Vec<u8>) -> Result<Self::Value, E> {
        self.hold.charge::<E>(value.len())?;
        self.inner.visit_byte_buf(value)
    }
}

macro_rules! forward_deserializers {
    ($($method:ident),* $(,)?) => {$(
        fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
            self.inner.$method(LimitedVisitor { inner: visitor, hold: self.hold })
        }
    )*};
}
impl<'de, D: de::Deserializer<'de>> de::Deserializer<'de> for Limited<'_, D> {
    type Error = D::Error;
    forward_deserializers! { deserialize_any, deserialize_bool, deserialize_i8, deserialize_i16,
    deserialize_i32, deserialize_i64, deserialize_i128, deserialize_u8, deserialize_u16,
    deserialize_u32, deserialize_u64, deserialize_u128, deserialize_f32, deserialize_f64,
    deserialize_char, deserialize_str, deserialize_string, deserialize_bytes, deserialize_byte_buf,
    deserialize_option, deserialize_unit, deserialize_seq, deserialize_map, deserialize_identifier,
    deserialize_ignored_any }
    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.inner.deserialize_unit_struct(
            name,
            LimitedVisitor {
                inner: visitor,
                hold: self.hold,
            },
        )
    }
    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.inner.deserialize_newtype_struct(
            name,
            LimitedVisitor {
                inner: visitor,
                hold: self.hold,
            },
        )
    }
    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.inner.deserialize_tuple(
            len,
            LimitedVisitor {
                inner: visitor,
                hold: self.hold,
            },
        )
    }
    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.inner.deserialize_tuple_struct(
            name,
            len,
            LimitedVisitor {
                inner: visitor,
                hold: self.hold,
            },
        )
    }
    fn deserialize_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.inner.deserialize_struct(
            name,
            fields,
            LimitedVisitor {
                inner: visitor,
                hold: self.hold,
            },
        )
    }
    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.inner.deserialize_enum(
            name,
            variants,
            LimitedVisitor {
                inner: visitor,
                hold: self.hold,
            },
        )
    }
    fn is_human_readable(&self) -> bool {
        self.inner.is_human_readable()
    }
}

pub(crate) fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> io::Result<Budgeted<T>> {
    decode_with_hold(bytes, Hold::new())
}

fn decode_with_hold<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    mut hold: Hold,
) -> io::Result<Budgeted<T>> {
    hold.grow(std::mem::size_of::<T>())?;
    let mut decoder = postcard::Deserializer::from_bytes(bytes);
    let value = T::deserialize(Limited {
        inner: &mut decoder,
        hold: &mut hold,
    })
    .map_err(|error| {
        if hold.exhausted {
            io::Error::other(
                "framed input memory budget exhausted; reduce connections or pipeline depth",
            )
        } else {
            io::Error::new(io::ErrorKind::InvalidData, error)
        }
    })?;
    Ok(Budgeted { value, hold })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hold(budget: &Arc<Budget>) -> Hold {
        Hold {
            budget: budget.clone(),
            used: 0,
            reserved: 0,
            exhausted: false,
        }
    }
    fn budget() -> Arc<Budget> {
        Arc::new(Budget {
            used: AtomicUsize::new(0),
            limit: RESERVATION_GRANULE,
        })
    }

    #[test]
    fn queued_values_share_the_budget_and_release_it_on_drop() {
        let shared = budget();
        let bytes = postcard::to_stdvec(&vec!["payload".to_string(); 16]).unwrap();
        let value = decode_with_hold::<Vec<String>>(&bytes, hold(&shared)).unwrap();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        tx.send(value).unwrap();
        assert!(decode_with_hold::<Vec<String>>(&bytes, hold(&shared)).is_err());
        assert_eq!(shared.used.load(Relaxed), RESERVATION_GRANULE);
        let (value, reservation) = rx.recv().unwrap().into_parts();
        assert_eq!(value.len(), 16);
        assert!(hold(&shared).grow(1).is_err());
        drop(value);
        drop(reservation);
        assert_eq!(shared.used.load(Relaxed), 0);
        assert!(decode_with_hold::<Vec<String>>(&bytes, hold(&shared)).is_ok());
    }

    #[test]
    fn tiny_payload_cannot_expand_an_unbounded_collection() {
        // Vec<()> has no element bytes in postcard. The hostile count must
        // still consume budget, without trusting Vec's allocation hint.
        let bytes = postcard::to_stdvec(&vec![(); 1_000_000]).unwrap();
        assert!(bytes.len() < 8);
        let shared = budget();
        let error = decode_with_hold::<Vec<()>>(&bytes, hold(&shared)).unwrap_err();
        assert!(error.to_string().contains("memory budget exhausted"));
        assert_eq!(shared.used.load(Relaxed), 0);
    }

    #[test]
    fn malformed_nested_values_release_their_reservations() {
        let mut bytes = postcard::to_stdvec(&vec![vec!["abc".to_string(); 4]; 8]).unwrap();
        bytes.pop();
        let shared = budget();
        assert!(decode_with_hold::<Vec<Vec<String>>>(&bytes, hold(&shared)).is_err());
        assert_eq!(shared.used.load(Relaxed), 0);
    }
}
