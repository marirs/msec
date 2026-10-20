//! aapt2's protobuf resource table (`ResourceTable` in AOSP
//! `frameworks/base/tools/aapt2/Resources.proto`): `resources.pb` in each module of an app
//! bundle, which bundletool compiles into the `resources.arsc` of the APKs Google Play serves.
//!
//! Decoded whole into packages, types and entries, and answering what
//! [`ResourceTable`](super::ResourceTable) answers for `resources.arsc`: names, values per
//! configuration, lookups by name, locales. Configurations (`Configuration.proto`) are
//! re-encoded as the `ResTable_config` bytes [`Config`] reads, so qualifiers read the same in
//! both formats. Compound values keep a style's parent and items and an array's elements;
//! attributes, styleables, plurals and macros are kept as empty bags (nothing msec reads uses
//! them).

use std::collections::BTreeSet;

use super::proto::{Fields, ProtoProblem, WireValue};
use super::proto_xml::item;
use super::resources::{Config, EntryValue, ResourceName, ResourceValue};

/// `Res_MAKEARRAY(0)`: binary arrays key their elements from here.
const ARRAY_KEY_BASE: u32 = 0x0200_0000;

/// A decoded `resources.pb`.
#[derive(Debug, Clone, Default)]
pub(crate) struct ProtoTable {
    packages: Vec<Package>,
}

#[derive(Debug, Clone, Default)]
struct Package {
    id: u32,
    name: String,
    types: Vec<Type>,
}

#[derive(Debug, Clone, Default)]
struct Type {
    id: u32,
    name: String,
    entries: Vec<Entry>,
}

#[derive(Debug, Clone, Default)]
struct Entry {
    id: u32,
    name: String,
    values: Vec<ResourceValue>,
}

impl ProtoTable {
    /// `ResourceTable`: field 2 holds the packages.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, ProtoProblem> {
        let mut table = Self::default();
        for field in Fields::new(bytes) {
            let (number, value) = field?;
            if number == 2 {
                table.packages.push(package(value.bytes()?)?);
            }
        }
        Ok(table)
    }

    pub(crate) fn package_names(&self) -> Vec<String> {
        self.packages
            .iter()
            .map(|package| package.name.clone())
            .collect()
    }

    pub(crate) fn name(&self, id: u32) -> Option<ResourceName> {
        let (package, kind, entry) = self.locate(id)?;
        Some(ResourceName {
            package: package.name.clone(),
            type_name: kind.name.clone(),
            entry: entry.name.clone(),
        })
    }

    pub(crate) fn values(&self, id: u32) -> Vec<ResourceValue> {
        self.locate(id)
            .map(|(_, _, entry)| entry.values.clone())
            .unwrap_or_default()
    }

    pub(crate) fn find(&self, type_name: &str, entry_name: &str) -> Option<u32> {
        self.packages.iter().find_map(|package| {
            let kind = package.types.iter().find(|kind| kind.name == type_name)?;
            let entry = kind.entries.iter().find(|entry| entry.name == entry_name)?;
            Some(resource_id(package, kind, entry))
        })
    }

    pub(crate) fn ids_of_type(&self, type_name: &str) -> Vec<u32> {
        let mut ids: Vec<u32> = self
            .packages
            .iter()
            .flat_map(|package| {
                package
                    .types
                    .iter()
                    .filter(|kind| kind.name == type_name)
                    .flat_map(move |kind| {
                        kind.entries
                            .iter()
                            .map(move |entry| resource_id(package, kind, entry))
                    })
            })
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    pub(crate) fn locales(&self) -> Vec<String> {
        let mut locales = BTreeSet::new();
        let strings = self
            .packages
            .iter()
            .flat_map(|package| &package.types)
            .filter(|kind| kind.name == "string")
            .flat_map(|kind| &kind.entries)
            .flat_map(|entry| &entry.values);
        for value in strings {
            if let Some(locale) = value.config.locale() {
                locales.insert(locale);
            }
        }
        locales.into_iter().collect()
    }

    /// Package, type and entry of a resource ID. Package ID 0 maps to the first package, as
    /// in the binary table.
    fn locate(&self, id: u32) -> Option<(&Package, &Type, &Entry)> {
        let package_id = id >> 24;
        let type_id = (id >> 16) & 0xff;
        let entry_id = id & 0xffff;
        let package = if package_id == 0 {
            self.packages.first()?
        } else {
            self.packages
                .iter()
                .find(|package| package.id == package_id)?
        };
        let kind = package.types.iter().find(|kind| kind.id == type_id)?;
        let entry = kind.entries.iter().find(|entry| entry.id == entry_id)?;
        Some((package, kind, entry))
    }
}

fn resource_id(package: &Package, kind: &Type, entry: &Entry) -> u32 {
    (package.id << 24) | (kind.id << 16) | entry.id
}

/// `PackageId`, `TypeId` and `EntryId` each wrap `uint32 id = 1`.
fn wrapped_id(bytes: &[u8]) -> Result<u32, ProtoProblem> {
    let mut id = 0;
    for field in Fields::new(bytes) {
        let (number, value) = field?;
        if number == 1 {
            id = value.uint32()?;
        }
    }
    Ok(id)
}

/// `Package`: id (1), name (2), types (3).
fn package(bytes: &[u8]) -> Result<Package, ProtoProblem> {
    let mut package = Package::default();
    for field in Fields::new(bytes) {
        let (number, value) = field?;
        match number {
            1 => package.id = wrapped_id(value.bytes()?)?,
            2 => package.name = value.string()?.to_owned(),
            3 => package.types.push(resource_type(value.bytes()?)?),
            _ => {}
        }
    }
    Ok(package)
}

/// `Type`: id (1), name (2), entries (3).
fn resource_type(bytes: &[u8]) -> Result<Type, ProtoProblem> {
    let mut kind = Type::default();
    for field in Fields::new(bytes) {
        let (number, value) = field?;
        match number {
            1 => kind.id = wrapped_id(value.bytes()?)?,
            2 => kind.name = value.string()?.to_owned(),
            3 => kind.entries.push(entry(value.bytes()?)?),
            _ => {}
        }
    }
    Ok(kind)
}

/// `Entry`: id (1), name (2), values per configuration (6).
fn entry(bytes: &[u8]) -> Result<Entry, ProtoProblem> {
    let mut entry = Entry::default();
    for field in Fields::new(bytes) {
        let (number, value) = field?;
        match number {
            1 => entry.id = wrapped_id(value.bytes()?)?,
            2 => entry.name = value.string()?.to_owned(),
            6 => entry.values.extend(config_value(value.bytes()?)?),
            _ => {}
        }
    }
    Ok(entry)
}

/// `ConfigValue`: configuration (1), value (2). `None` for a value with nothing msec reads.
fn config_value(bytes: &[u8]) -> Result<Option<ResourceValue>, ProtoProblem> {
    // A value without a configuration is the default configuration.
    let mut config = Config::from_bytes(&[]);
    let mut value = None;
    for field in Fields::new(bytes) {
        let (number, field) = field?;
        match number {
            1 => config = configuration(field.bytes()?)?,
            2 => value = entry_value(field.bytes()?)?,
            _ => {}
        }
    }
    Ok(value.map(|value| ResourceValue { config, value }))
}

/// `Value`: an item (4) or a compound value (5).
fn entry_value(bytes: &[u8]) -> Result<Option<EntryValue>, ProtoProblem> {
    let mut value = None;
    for field in Fields::new(bytes) {
        let (number, field) = field?;
        match number {
            4 => value = item(field.bytes()?)?.map(EntryValue::Simple),
            5 => value = Some(compound(field.bytes()?)?),
            _ => {}
        }
    }
    Ok(value)
}

/// `CompoundValue`: a style (2) keeps its parent and `(attribute, value)` items, an array (4)
/// its elements keyed as binary arrays key them; other bags are kept empty.
fn compound(bytes: &[u8]) -> Result<EntryValue, ProtoProblem> {
    let mut bag = EntryValue::Complex {
        parent: 0,
        items: Vec::new(),
    };
    for field in Fields::new(bytes) {
        let (number, field) = field?;
        match number {
            2 => bag = style(field.bytes()?)?,
            4 => bag = array(field.bytes()?)?,
            _ => {}
        }
    }
    Ok(bag)
}

/// `Style`: parent reference (1), entries (3) each with a key reference (3) and an item (4).
fn style(bytes: &[u8]) -> Result<EntryValue, ProtoProblem> {
    let mut parent = 0;
    let mut items = Vec::new();
    for field in Fields::new(bytes) {
        let (number, field) = field?;
        match number {
            1 => parent = reference_id(field.bytes()?)?,
            3 => {
                let mut key = 0;
                let mut value = None;
                for entry_field in Fields::new(field.bytes()?) {
                    let (entry_number, entry_value) = entry_field?;
                    match entry_number {
                        3 => key = reference_id(entry_value.bytes()?)?,
                        4 => value = item(entry_value.bytes()?)?,
                        _ => {}
                    }
                }
                items.extend(value.map(|value| (key, value)));
            }
            _ => {}
        }
    }
    Ok(EntryValue::Complex { parent, items })
}

/// `Array`: elements (1), each with an item (3).
fn array(bytes: &[u8]) -> Result<EntryValue, ProtoProblem> {
    let mut items = Vec::new();
    for field in Fields::new(bytes) {
        let (number, field) = field?;
        if number != 1 {
            continue;
        }
        for element_field in Fields::new(field.bytes()?) {
            let (element_number, element_value) = element_field?;
            if element_number == 3
                && let Some(value) = item(element_value.bytes()?)?
            {
                let key = ARRAY_KEY_BASE + items.len() as u32;
                items.push((key, value));
            }
        }
    }
    Ok(EntryValue::Complex { parent: 0, items })
}

/// `Reference.id` (2).
fn reference_id(bytes: &[u8]) -> Result<u32, ProtoProblem> {
    let mut id = 0;
    for field in Fields::new(bytes) {
        let (number, value) = field?;
        if number == 2 {
            id = value.uint32()?;
        }
    }
    Ok(id)
}

/// `Configuration` (`Configuration.proto`) as `ResTable_config` bytes. The enums share the
/// binary encoding where noted; the others are mapped field by field.
fn configuration(bytes: &[u8]) -> Result<Config, ProtoProblem> {
    let mut raw = [0u8; 64];
    raw[0] = 64;
    for field in Fields::new(bytes) {
        let (number, value) = field?;
        match number {
            1 => put_u16(&mut raw, 4, value.uint32()?),
            2 => put_u16(&mut raw, 6, value.uint32()?),
            3 => put_locale(&mut raw, value.string()?),
            // Layout direction: LTR 0x40, RTL 0x80 in screenLayout.
            4 => {
                raw[28] |= [0, 0x40, 0x80]
                    .get(usize::from(small(value)?))
                    .copied()
                    .unwrap_or(0)
            }
            5 => put_u16(&mut raw, 20, value.uint32()?),
            6 => put_u16(&mut raw, 22, value.uint32()?),
            7 => put_u16(&mut raw, 32, value.uint32()?),
            8 => put_u16(&mut raw, 34, value.uint32()?),
            9 => put_u16(&mut raw, 30, value.uint32()?),
            // Screen size: same values (small 1 to xlarge 4).
            10 => raw[28] |= small(value)? & 0x0f,
            // Long: LONG 0x20, NOTLONG 0x10.
            11 => {
                raw[28] |= [0, 0x20, 0x10]
                    .get(usize::from(small(value)?))
                    .copied()
                    .unwrap_or(0)
            }
            // Round: ROUND 2, NOTROUND 1 in screenLayout2.
            12 => {
                raw[48] |= [0, 2, 1]
                    .get(usize::from(small(value)?))
                    .copied()
                    .unwrap_or(0)
            }
            // Wide colour gamut: WIDECG 2, NOWIDECG 1; HDR: HIGHDR 0x08, LOWDR 0x04.
            13 => {
                raw[49] |= [0, 2, 1]
                    .get(usize::from(small(value)?))
                    .copied()
                    .unwrap_or(0)
            }
            14 => {
                raw[49] |= [0, 0x08, 0x04]
                    .get(usize::from(small(value)?))
                    .copied()
                    .unwrap_or(0)
            }
            // Orientation, touchscreen, keyboard and navigation: same values.
            15 => raw[12] = small(value)?,
            19 => raw[13] = small(value)?,
            21 => raw[16] = small(value)?,
            23 => raw[17] = small(value)?,
            // UI mode type: same values; night: NIGHT 0x20, NOTNIGHT 0x10.
            16 => raw[29] |= small(value)? & 0x0f,
            17 => {
                raw[29] |= [0, 0x20, 0x10]
                    .get(usize::from(small(value)?))
                    .copied()
                    .unwrap_or(0)
            }
            18 => put_u16(&mut raw, 14, value.uint32()?),
            // Keys hidden: same values in the low bits; navigation hidden: 0x04 / 0x08.
            20 => raw[18] |= small(value)? & 0x03,
            22 => {
                raw[18] |= [0, 0x04, 0x08]
                    .get(usize::from(small(value)?))
                    .copied()
                    .unwrap_or(0)
            }
            24 => put_u16(&mut raw, 24, value.uint32()?),
            _ => {}
        }
    }
    Ok(Config::from_bytes(&raw))
}

/// A `uint32` field stored as a 16-bit `ResTable_config` field (clamped).
fn put_u16(raw: &mut [u8; 64], offset: usize, value: u32) {
    raw[offset..offset + 2].copy_from_slice(&(value.min(0xffff) as u16).to_le_bytes());
}

/// A small enum or byte-sized field (clamped).
fn small(value: WireValue<'_>) -> Result<u8, ProtoProblem> {
    Ok(value.uint32()?.min(0xff) as u8)
}

/// A BCP-47 tag (`en`, `en-GB`, `zh-Hant-TW`, `es-419`) into the language (8), region (10)
/// and script (36) fields. Three-letter codes are packed the way `ResTable_config` packs them.
fn put_locale(raw: &mut [u8; 64], tag: &str) {
    let mut parts = tag.split(['-', '_']);
    let Some(language) = parts.next().filter(|part| (2..=3).contains(&part.len())) else {
        return;
    };
    if let Some(packed) = pack(&language.to_ascii_lowercase(), b'a') {
        raw[8..10].copy_from_slice(&packed);
    }
    for part in parts {
        if part.len() == 4 && part.chars().all(|c| c.is_ascii_alphabetic()) {
            raw[36..40].copy_from_slice(part.as_bytes());
        } else if ((part.len() == 2 && part.chars().all(|c| c.is_ascii_alphabetic()))
            || (part.len() == 3 && part.chars().all(|c| c.is_ascii_digit())))
            && let Some(packed) = pack(&part.to_ascii_uppercase(), b'0')
        {
            raw[10..12].copy_from_slice(&packed);
        }
    }
}

/// Two characters stored as is; three packed into 15 bits from `base` with the top bit set
/// (`ResTable_config::packLanguageOrRegion`).
fn pack(code: &str, base: u8) -> Option<[u8; 2]> {
    let bytes = code.as_bytes();
    match bytes {
        [first, second] => Some([*first, *second]),
        [first, second, third] => {
            let [first, second, third] = [
                first.checked_sub(base)?,
                second.checked_sub(base)?,
                third.checked_sub(base)?,
            ];
            Some([0x80 | (third << 2) | (second >> 3), (second << 5) | first])
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locales_pack_like_res_table_config() {
        let config = |tag: &str| {
            let mut raw = [0u8; 64];
            raw[0] = 64;
            put_locale(&mut raw, tag);
            Config::from_bytes(&raw)
        };
        assert_eq!(config("en-GB").locale().as_deref(), Some("en-GB"));
        assert_eq!(config("zh-Hant-TW").locale().as_deref(), Some("zh-Hant-TW"));
        assert_eq!(config("fil").locale().as_deref(), Some("fil"));
        assert_eq!(config("es-419").locale().as_deref(), Some("es-419"));
        assert_eq!(config("en-GB").qualifiers(), "en-rGB");
    }
}
