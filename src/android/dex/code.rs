//! Method, field and proto IDs, and the references each method's code makes: which framework or
//! app methods it calls (`invoke-*`), which fields it reads or writes (`iget`/`iput`/`sget`/
//! `sput`), which types it instantiates or checks (`new-instance`, `const-class`, ...), and
//! which strings it loads (`const-string`, `const-string/jumbo`). What a code rule needs to say
//! "this app calls `Window.setStatusBarColor`, from these methods", and what the secret
//! detectors need to name the class a hardcoded key is in.
//!
//! Only instruction widths and the index operand of referencing instructions are decoded
//! (formats 21c, 22c, 31c, 35c, 3rc, 45cc, 4rcc of the Dalvik bytecode spec); there is no data
//! flow.
//! Work is bounded like the rest of the reader: class data and code items may be shared or
//! overlap in a hostile file, so every member read, code unit scanned and reference recorded is
//! charged to a budget of the file's size ([`DexAnomalyKind::CodeBudgetExhausted`]).

use std::collections::{BTreeSet, HashMap};

use super::{Anomalies, DexAnomalyKind, Table};
use crate::android::chunk::{u16_at, u32_at};

/// `proto_id_item`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProtoId {
    /// String ID of the shorty descriptor (`VL`).
    pub(super) shorty: u32,
    /// Type ID of the return type.
    pub(super) return_type: u32,
    /// Range of its parameter type IDs in the file's type-list entries.
    pub(super) parameters: (u32, u32),
}

/// `field_id_item` and `method_id_item`: the declaring class, the field type or method proto,
/// and the name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MemberId {
    pub(super) class: u16,
    /// Type ID (fields) or proto ID (methods).
    pub(super) kind: u16,
    pub(super) name: u32,
}

/// What an instruction refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Target {
    /// A method ID (`invoke-*`).
    Method(u32),
    /// A field ID (instance and static field access).
    Field(u32),
    /// A type ID (`new-instance`, `const-class`, `check-cast`, `instance-of`, arrays).
    Type(u32),
}

/// One method's reference to a method, field or type, once per pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Reference {
    /// Method ID of the method whose code makes the reference.
    pub caller: u32,
    /// What it refers to.
    pub target: Target,
}

/// Instruction widths in 16-bit code units, by opcode, from the Dalvik formats (10x/11x/12x: 1;
/// 2x formats: 2; 3x and 35c/3rc: 3; 45cc/4rcc: 4; 51l: 5). Opcode 0x00 (`nop`) may start a
/// payload instead, whose width is read from it. Unused opcodes take one unit, as ART decodes
/// them before rejecting them.
const WIDTHS: [u8; 256] = {
    let mut widths = [1u8; 256];
    let mut opcode = 0;
    while opcode < 256 {
        widths[opcode] = match opcode {
            0x02 | 0x05 | 0x08 => 2,
            0x03 | 0x06 | 0x09 => 3,
            0x13 | 0x15 | 0x16 | 0x19 | 0x1a | 0x1c | 0x1f | 0x20 | 0x22 | 0x23 => 2,
            0x14 | 0x17 | 0x1b | 0x24 | 0x25 | 0x26 | 0x2a | 0x2b | 0x2c => 3,
            0x18 => 5,
            0x29 => 2,
            0x2d..=0x3d => 2,
            0x44..=0x6d => 2,
            0x6e..=0x72 | 0x74..=0x78 => 3,
            0x90..=0xaf => 2,
            0xd0..=0xe2 => 2,
            0xfa | 0xfb => 4,
            0xfc | 0xfd => 3,
            0xfe | 0xff => 2,
            _ => 1,
        };
        opcode += 1;
    }
    widths
};

/// What an instruction's index operand names: a method, field or type, or a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Operand {
    Target(Target),
    /// A string ID (`const-string`, `const-string/jumbo`).
    String(u32),
}

/// The string a `const-string` (21c, index in the second unit) or `const-string/jumbo` (31c,
/// index in the second and third units) loads.
fn string_of(opcode: u8, unit: impl Fn(usize) -> u16) -> Option<u32> {
    match opcode {
        0x1a => Some(u32::from(unit(1))),
        0x1b => Some(u32::from(unit(1)) | (u32::from(unit(2)) << 16)),
        _ => None,
    }
}

/// What a referencing instruction's index operand (the second code unit) names.
fn target_of(opcode: u8, index: u32) -> Option<Target> {
    match opcode {
        // invoke-virtual/super/direct/static/interface, their /range forms, and
        // invoke-polymorphic(/range). invoke-custom (0xfc, 0xfd) names a call site instead.
        0x6e..=0x72 | 0x74..=0x78 | 0xfa | 0xfb => Some(Target::Method(index)),
        // iget*/iput* and sget*/sput*.
        0x52..=0x6d => Some(Target::Field(index)),
        // const-class, check-cast, instance-of, new-instance, new-array, filled-new-array(/range).
        0x1c | 0x1f | 0x20 | 0x22 | 0x23 | 0x24 | 0x25 => Some(Target::Type(index)),
        _ => None,
    }
}

/// Reads the proto, field and method ID tables. Tables outside the file were reported already
/// and are read as empty.
pub(super) fn read_ids(
    bytes: &[u8],
    tables: [(Table, bool); 3],
    mut read_type_list: impl FnMut(u32) -> Option<(u32, u32)>,
) -> (Vec<ProtoId>, Vec<MemberId>, Vec<MemberId>) {
    let [
        (protos, protos_ok),
        (fields, fields_ok),
        (methods, methods_ok),
    ] = tables;
    let u32_field = |at: usize| u32_at(bytes, at).expect("the table was bounds-checked");
    let u16_field = |at: usize| u16_at(bytes, at).expect("the table was bounds-checked");
    let proto_ids = if protos_ok {
        (0..protos.count as usize)
            .map(|index| {
                let at = protos.offset as usize + 12 * index;
                ProtoId {
                    shorty: u32_field(at),
                    return_type: u32_field(at + 4),
                    parameters: read_type_list(u32_field(at + 8)).unwrap_or((0, 0)),
                }
            })
            .collect()
    } else {
        Vec::new()
    };
    let members = |table: Table, ok: bool| -> Vec<MemberId> {
        if !ok {
            return Vec::new();
        }
        (0..table.count as usize)
            .map(|index| {
                let at = table.offset as usize + 8 * index;
                MemberId {
                    class: u16_field(at),
                    kind: u16_field(at + 2),
                    name: u32_field(at + 4),
                }
            })
            .collect()
    };
    (
        proto_ids,
        members(fields, fields_ok),
        members(methods, methods_ok),
    )
}

/// The references of every method with code, deduplicated per (caller, target) and sorted.
pub(super) struct CodeScan<'data> {
    pub(super) bytes: &'data [u8],
    /// Bytes code may lie in: the logical file and the rest of its container.
    pub(super) bounds: (usize, usize),
    pub(super) method_count: u32,
    pub(super) field_count: u32,
    pub(super) type_count: u32,
    pub(super) string_count: u32,
    /// Work still allowed in this container ([`super::Budgets::code_work`]).
    pub(super) budget: &'data mut usize,
    /// Operands of each code item already scanned, by offset: ranges in `operands`.
    by_offset: HashMap<u32, (usize, usize)>,
    operands: Vec<Operand>,
    pub(super) references: BTreeSet<Reference>,
    /// (method ID, string ID) for every string a method's code loads.
    pub(super) string_uses: BTreeSet<(u32, u32)>,
    /// Methods with code read.
    pub(super) methods_with_code: usize,
    /// Method IDs of every method the classes define (with or without code), in class order.
    pub(super) defined_methods: Vec<u32>,
}

enum CodeProblem {
    Invalid,
    BudgetExhausted,
}

impl<'data> CodeScan<'data> {
    pub(super) fn new(
        bytes: &'data [u8],
        bounds: (usize, usize),
        counts: (u32, u32, u32, u32),
        budget: &'data mut usize,
    ) -> Self {
        Self {
            bytes,
            bounds,
            method_count: counts.0,
            field_count: counts.1,
            type_count: counts.2,
            string_count: counts.3,
            budget,
            by_offset: HashMap::new(),
            operands: Vec::new(),
            references: BTreeSet::new(),
            string_uses: BTreeSet::new(),
            methods_with_code: 0,
            defined_methods: Vec::new(),
        }
    }

    fn charge(&mut self, work: usize) -> Result<(), CodeProblem> {
        if work > *self.budget {
            *self.budget = 0;
            return Err(CodeProblem::BudgetExhausted);
        }
        *self.budget -= work;
        Ok(())
    }

    /// Reads one class's `class_data_item` and scans each method's code. Returns false when
    /// the budget ran out (reading stops).
    pub(super) fn class(&mut self, class_def: u32, offset: u32, anomalies: &mut Anomalies) -> bool {
        match self.class_data(offset, anomalies) {
            Ok(()) => true,
            Err(CodeProblem::Invalid) => {
                anomalies.record(DexAnomalyKind::InvalidClassData { class_def });
                true
            }
            Err(CodeProblem::BudgetExhausted) => {
                anomalies.record(DexAnomalyKind::CodeBudgetExhausted { class_def });
                false
            }
        }
    }

    fn class_data(&mut self, offset: u32, anomalies: &mut Anomalies) -> Result<(), CodeProblem> {
        let (lower, upper) = self.bounds;
        let mut reader = Uleb {
            bytes: &self.bytes[..upper],
            position: offset as usize,
        };
        if (offset as usize) < lower {
            return Err(CodeProblem::Invalid);
        }
        let static_fields = reader.read()?;
        let instance_fields = reader.read()?;
        let direct_methods = reader.read()?;
        let virtual_methods = reader.read()?;
        // Each member takes at least two bytes: more than the rest of the file is malformed.
        let members = u64::from(static_fields)
            + u64::from(instance_fields)
            + u64::from(direct_methods)
            + u64::from(virtual_methods);
        if members > (upper - reader.position) as u64 {
            return Err(CodeProblem::Invalid);
        }
        self.charge(members as usize)?;
        for _ in 0..u64::from(static_fields) + u64::from(instance_fields) {
            reader.read()?;
            reader.read()?;
        }
        for count in [direct_methods, virtual_methods] {
            // Method indexes are differences from the previous one in each list.
            let mut method: u32 = 0;
            for _ in 0..count {
                method = method.wrapping_add(reader.read()?);
                reader.read()?;
                let code_offset = reader.read()?;
                if method < self.method_count {
                    self.defined_methods.push(method);
                }
                if code_offset != 0 {
                    self.method_code(method, code_offset, anomalies)?;
                }
            }
        }
        Ok(())
    }

    fn method_code(
        &mut self,
        method: u32,
        offset: u32,
        anomalies: &mut Anomalies,
    ) -> Result<(), CodeProblem> {
        if method >= self.method_count {
            return Err(CodeProblem::Invalid);
        }
        let (start, length) = match self.by_offset.get(&offset) {
            Some(&range) => range,
            None => match self.scan(offset) {
                Ok(range) => range,
                Err(CodeProblem::Invalid) => {
                    anomalies.record(DexAnomalyKind::InvalidCode { method });
                    return Ok(());
                }
                Err(problem) => return Err(problem),
            },
        };
        // Attaching a shared code item's operands to another method costs too.
        self.charge(length)?;
        self.methods_with_code += 1;
        for index in start..start + length {
            match self.operands[index] {
                Operand::Target(target) => {
                    self.references.insert(Reference {
                        caller: method,
                        target,
                    });
                }
                Operand::String(string) => {
                    self.string_uses.insert((method, string));
                }
            }
        }
        Ok(())
    }

    /// Scans the `code_item` at `offset`, returning the range of its distinct operands.
    fn scan(&mut self, offset: u32) -> Result<(usize, usize), CodeProblem> {
        let (lower, upper) = self.bounds;
        let at = offset as usize;
        if at < lower || !at.is_multiple_of(4) || at.saturating_add(16) > upper {
            return Err(CodeProblem::Invalid);
        }
        let units = u32_at(self.bytes, at + 12).ok_or(CodeProblem::Invalid)? as usize;
        let start = at + 16;
        if (start as u64) + 2 * units as u64 > upper as u64 {
            return Err(CodeProblem::Invalid);
        }
        self.charge(units)?;
        let unit = |index: usize| -> u16 {
            u16_at(self.bytes, start + 2 * index).expect("the code item was bounds-checked")
        };
        let mut found: BTreeSet<Operand> = BTreeSet::new();
        let mut position = 0;
        while position < units {
            let first = unit(position);
            let opcode = (first & 0xff) as u8;
            let width = if opcode == 0 {
                payload_width(first >> 8, |index| {
                    (position + index < units).then(|| unit(position + index))
                })
                .ok_or(CodeProblem::Invalid)?
            } else {
                usize::from(WIDTHS[usize::from(opcode)])
            };
            if position + width > units {
                return Err(CodeProblem::Invalid);
            }
            if width >= 2
                && let Some(target) = target_of(opcode, u32::from(unit(position + 1)))
            {
                let (index, count) = match target {
                    Target::Method(index) => (index, self.method_count),
                    Target::Field(index) => (index, self.field_count),
                    Target::Type(index) => (index, self.type_count),
                };
                if index >= count {
                    return Err(CodeProblem::Invalid);
                }
                found.insert(Operand::Target(target));
            }
            if let Some(string) = string_of(opcode, |index| unit(position + index)) {
                if string >= self.string_count {
                    return Err(CodeProblem::Invalid);
                }
                found.insert(Operand::String(string));
            }
            position += width;
        }
        let range = (self.operands.len(), found.len());
        self.operands.extend(found);
        self.by_offset.insert(offset, range);
        Ok(range)
    }
}

/// Width of the instruction at a `nop` opcode: one unit, or a payload's full size
/// (packed-switch 0x01, sparse-switch 0x02, fill-array-data 0x03). `None` when a payload's
/// header runs past the code.
fn payload_width(kind: u16, unit: impl Fn(usize) -> Option<u16>) -> Option<usize> {
    match kind {
        0x01 => Some(usize::from(unit(1)?) * 2 + 4),
        0x02 => Some(usize::from(unit(1)?) * 4 + 2),
        0x03 => {
            let element_width = u64::from(unit(1)?);
            let size = u64::from(unit(2)?) | (u64::from(unit(3)?) << 16);
            usize::try_from((size * element_width).div_ceil(2) + 4).ok()
        }
        _ => Some(1),
    }
}

/// Unsigned LEB128 values of at most five bytes, within the slice.
struct Uleb<'data> {
    bytes: &'data [u8],
    position: usize,
}

impl Uleb<'_> {
    fn read(&mut self) -> Result<u32, CodeProblem> {
        let mut value: u32 = 0;
        for shift in [0, 7, 14, 21, 28] {
            let byte = *self.bytes.get(self.position).ok_or(CodeProblem::Invalid)?;
            self.position += 1;
            value |= u32::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(CodeProblem::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widths_follow_the_dalvik_formats() {
        // invoke-virtual (35c), invoke-virtual/range (3rc), invoke-polymorphic (45cc),
        // const-wide (51l), goto (10t), iget (22c), sget (21c).
        for (opcode, width) in [
            (0x6e, 3),
            (0x74, 3),
            (0xfa, 4),
            (0x18, 5),
            (0x28, 1),
            (0x52, 2),
            (0x60, 2),
        ] {
            assert_eq!(WIDTHS[opcode], width, "{opcode:#x}");
        }
        assert_eq!(target_of(0x71, 7), Some(Target::Method(7)));
        assert_eq!(target_of(0xfc, 7), None);
        assert_eq!(target_of(0x62, 3), Some(Target::Field(3)));
        assert_eq!(target_of(0x22, 2), Some(Target::Type(2)));
        // A packed-switch payload of 3 targets takes 3 * 2 + 4 units.
        assert_eq!(
            payload_width(0x01, |index| [0x0100, 3][..].get(index).copied()),
            Some(10)
        );
    }
}
