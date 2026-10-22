//! Method, field and proto IDs, and the references each method's code makes: which framework or
//! app methods it calls (`invoke-*`), which fields it reads or writes (`iget`/`iput`/`sget`/
//! `sput`), which types it instantiates or checks (`new-instance`, `const-class`, ...), and
//! which strings it loads (`const-string`, `const-string/jumbo`). What a code rule needs to say
//! "this app calls `Window.setStatusBarColor`, from these methods", and what the secret
//! detectors need to name the class a hardcoded key is in.
//!
//! Only instruction widths and the index operand of referencing instructions are decoded
//! (formats 21c, 22c, 31c, 35c, 3rc, 45cc, 4rcc of the Dalvik bytecode spec) for references.
//!
//! Calls also record the arguments that are constants at the call site
//! ([`ConstantArgument`]): a register set by `const*` or `const-string` (or moved from one) on
//! the only path into the call, within the calling method. Registers are forgotten wherever
//! control may arrive from elsewhere: at every branch target, switch case and exception handler,
//! and after every unconditional transfer, so a value merged from several paths, passed in as a
//! parameter, or read from a field is never taken for a constant. That is the whole of the
//! data flow: nothing crosses methods, and a constant passed through a helper is not seen.
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

/// A value a register holds at a call: a 32-bit literal (`const/4`, `const/16`, `const`,
/// `const/high16`: integers, `false`/`true`, `null`) or a string (`const-string`, by string ID).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Constant {
    /// A 32-bit literal.
    Int(i32),
    /// A string, by string ID.
    String(u32),
}

/// A call one of whose argument registers holds a constant at the call site, once per
/// (caller, callee, slot, value). `slot` counts argument registers as the call lists them: for
/// an instance method slot 0 is `this`, and a `long` or `double` argument takes two slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConstantArgument {
    /// Method ID of the calling method.
    pub caller: u32,
    /// Method ID of the method called.
    pub callee: u32,
    /// The argument slot.
    pub slot: u8,
    /// The constant.
    pub value: Constant,
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

/// Where a code item's distinct operands, then its calls' constant arguments, sit in the scan's
/// vectors: (start, length) each.
type ItemRanges = ((usize, usize), (usize, usize));

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
    /// Operands of each code item already scanned, by offset: ranges in `operands`, then in
    /// `call_constants`.
    by_offset: HashMap<u32, ItemRanges>,
    operands: Vec<Operand>,
    /// (callee, slot, value) for each call with a constant argument, per code item.
    call_constants: Vec<(u32, u8, Constant)>,
    /// Calls with constant arguments, per calling method.
    pub(super) constant_arguments: BTreeSet<ConstantArgument>,
    pub(super) references: BTreeSet<Reference>,
    /// (method ID, string ID) for every string a method's code loads.
    pub(super) string_uses: BTreeSet<(u32, u32)>,
    /// Methods with code read.
    pub(super) methods_with_code: usize,
    /// Method IDs of every method the classes define (with or without code), in class order.
    pub(super) defined_methods: Vec<u32>,
}

#[derive(Debug)]
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
            call_constants: Vec::new(),
            constant_arguments: BTreeSet::new(),
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
        let ((start, length), (calls_start, calls_length)) = match self.by_offset.get(&offset) {
            Some(&ranges) => ranges,
            None => match self.scan(offset) {
                Ok(ranges) => ranges,
                Err(CodeProblem::Invalid) => {
                    anomalies.record(DexAnomalyKind::InvalidCode { method });
                    return Ok(());
                }
                Err(problem) => return Err(problem),
            },
        };
        // Attaching a shared code item's operands to another method costs too.
        self.charge(length + calls_length)?;
        self.methods_with_code += 1;
        for &(callee, slot, value) in &self.call_constants[calls_start..calls_start + calls_length]
        {
            self.constant_arguments.insert(ConstantArgument {
                caller: method,
                callee,
                slot,
                value,
            });
        }
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

    /// Scans the `code_item` at `offset`, returning the ranges of its distinct operands and of
    /// its calls' constant arguments.
    fn scan(&mut self, offset: u32) -> Result<ItemRanges, CodeProblem> {
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
        let tries = u16_at(self.bytes, at + 6).ok_or(CodeProblem::Invalid)?;
        let handlers = handler_addresses(self.bytes, start, units, tries, upper)
            .ok_or(CodeProblem::Invalid)?;
        // The second pass costs as much again.
        self.charge(units)?;
        let constants = call_constants(&unit, units, &handlers, self.method_count)?;
        let range = (self.operands.len(), found.len());
        self.operands.extend(found);
        let calls = (self.call_constants.len(), constants.len());
        self.call_constants.extend(constants);
        self.by_offset.insert(offset, (range, calls));
        Ok((range, calls))
    }
}

/// The code-unit addresses of a code item's exception handlers (`encoded_catch_handler_list`,
/// after the `try_item`s, which follow the instructions and a padding unit when their count is
/// odd). `None` when the lists run past the code's bounds or are malformed.
fn handler_addresses(
    bytes: &[u8],
    instructions: usize,
    units: usize,
    tries: u16,
    upper: usize,
) -> Option<Vec<usize>> {
    if tries == 0 {
        return Some(Vec::new());
    }
    let padding = if units % 2 == 1 { 2 } else { 0 };
    let list = instructions
        .checked_add(2 * units)?
        .checked_add(padding)?
        .checked_add(8 * usize::from(tries))?;
    if list > upper {
        return None;
    }
    let mut reader = Uleb {
        bytes: &bytes[..upper],
        position: list,
    };
    let handler_lists = reader.read().ok()?;
    let mut addresses = Vec::new();
    // Each handler takes at least one byte: more than the rest of the file is malformed.
    if handler_lists as usize > upper - reader.position {
        return None;
    }
    for _ in 0..handler_lists {
        let size = reader.read_signed().ok()?;
        if size.unsigned_abs() as usize > upper - reader.position {
            return None;
        }
        for _ in 0..size.unsigned_abs() {
            reader.read().ok()?;
            addresses.push(reader.read().ok()? as usize);
        }
        if size <= 0 {
            addresses.push(reader.read().ok()? as usize);
        }
    }
    Some(addresses)
}

/// The register an instruction writes, read from the first code unit (`vA` of formats 12x,
/// 11n, 22c, 22s; `vAA` of 11x, 21c, 21s, 21h, 23x, 22b, 31i, 31c, 51l) or the second (`vAAAA`
/// of 32x); `None` for instructions that write none. A wide result ([`writes_wide`]) also takes
/// the next register, which the caller forgets too.
fn written_register(opcode: u8, first: u16, second: u16) -> Option<u16> {
    let low_nibble = first >> 8 & 0x0f;
    let high_byte = first >> 8;
    match opcode {
        0x01 | 0x04 | 0x07 | 0x12 | 0x20 | 0x21 | 0x23 => Some(low_nibble),
        0x52..=0x58 | 0x7b..=0x8f | 0xb0..=0xcf | 0xd0..=0xd7 => Some(low_nibble),
        0x02 | 0x05 | 0x08 | 0x0a..=0x0d | 0x13..=0x1c | 0x22 | 0x2d..=0x31 => Some(high_byte),
        0x44..=0x4a | 0x60..=0x66 | 0x90..=0xaf | 0xd8..=0xe2 | 0xfe | 0xff => Some(high_byte),
        0x03 | 0x06 | 0x09 => Some(second),
        _ => None,
    }
}

/// Where control may continue other than the next instruction: branch, `goto` and switch
/// targets (code-unit addresses), or `None` when the instruction is not a branch. Switch
/// payloads are read from the code; one that is not where its switch says is malformed.
fn branch_targets(
    position: usize,
    opcode: u8,
    unit: &impl Fn(usize) -> u16,
    units: usize,
) -> Result<Vec<i64>, CodeProblem> {
    let at = position as i64;
    let signed16 = |index: usize| i64::from(unit(position + index) as i16);
    let signed32 = |index: usize| {
        i64::from(
            (u32::from(unit(position + index)) | (u32::from(unit(position + index + 1)) << 16))
                as i32,
        )
    };
    Ok(match opcode {
        0x28 => vec![at + i64::from((unit(position) >> 8) as u8 as i8)],
        0x29 => vec![at + signed16(1)],
        0x2a => vec![at + signed32(1)],
        0x32..=0x3d => vec![at + signed16(1)],
        0x2b | 0x2c => {
            let payload = at + signed32(1);
            let payload = usize::try_from(payload).map_err(|_| CodeProblem::Invalid)?;
            let in_code = |index: usize| -> Result<u16, CodeProblem> {
                let at = payload.checked_add(index).ok_or(CodeProblem::Invalid)?;
                if at < units {
                    Ok(unit(at))
                } else {
                    Err(CodeProblem::Invalid)
                }
            };
            let size = usize::from(in_code(1)?);
            // packed-switch: ident, size, first key (2 units), targets; sparse-switch: ident,
            // size, keys (2 units each), targets.
            let (ident, first_target) = if opcode == 0x2b {
                (0x0100, 4)
            } else {
                (0x0200, 2 + 2 * size)
            };
            if in_code(0)? != ident {
                return Err(CodeProblem::Invalid);
            }
            let mut targets = Vec::with_capacity(size);
            for case in 0..size {
                let index = first_target + 2 * case;
                let relative =
                    (u32::from(in_code(index)?) | (u32::from(in_code(index + 1)?) << 16)) as i32;
                targets.push(at + i64::from(relative));
            }
            targets
        }
        _ => Vec::new(),
    })
}

/// Opcodes whose result is 64 bits wide (long, double), taking the written register and the
/// next: `move-wide*`, `move-result-wide`, `const-wide*`, `aget-wide`, `iget-wide`,
/// `sget-wide`, and the long and double conversions and arithmetic.
fn writes_wide(opcode: u8) -> bool {
    matches!(
        opcode,
        0x04..=0x06
            | 0x0b
            | 0x16..=0x19
            | 0x45
            | 0x53
            | 0x61
            | 0x7d
            | 0x7e
            | 0x80
            | 0x81
            | 0x83
            | 0x86
            | 0x88
            | 0x89
            | 0x8b
            | 0x9b..=0xa5
            | 0xab..=0xaf
            | 0xbb..=0xc5
            | 0xcb..=0xcf
    )
}

/// Opcodes after which control never falls through: returns, `throw`, `goto`.
fn ends_flow(opcode: u8) -> bool {
    matches!(opcode, 0x0e..=0x11 | 0x27 | 0x28..=0x2a)
}

/// Opcodes no instruction set defines: ART rejects them; everything known is forgotten.
fn unused_opcode(opcode: u8) -> bool {
    matches!(opcode, 0x3e..=0x43 | 0x73 | 0x79 | 0x7a | 0xe3..=0xf9)
}

/// The constant arguments of every call (`invoke-*` and `/range`, by method ID) in a code item
/// whose instructions are `units` code units read by `unit`, with its exception handlers at
/// `handlers`. A register's constant is forgotten at every place control may join from
/// elsewhere, so only a constant set on the one path into the call is reported.
fn call_constants(
    unit: &impl Fn(usize) -> u16,
    units: usize,
    handlers: &[usize],
    method_count: u32,
) -> Result<Vec<(u32, u8, Constant)>, CodeProblem> {
    let width_at = |position: usize| -> Result<usize, CodeProblem> {
        let first = unit(position);
        let opcode = (first & 0xff) as u8;
        if opcode == 0 {
            payload_width(first >> 8, |index| {
                (position + index < units).then(|| unit(position + index))
            })
            .ok_or(CodeProblem::Invalid)
        } else {
            Ok(usize::from(WIDTHS[usize::from(opcode)]))
        }
    };
    // Pass 1: where control may join.
    let mut joins: BTreeSet<usize> = handlers.iter().copied().collect();
    let mut position = 0;
    while position < units {
        let first = unit(position);
        let opcode = (first & 0xff) as u8;
        let width = width_at(position)?;
        if opcode != 0 {
            for target in branch_targets(position, opcode, unit, units)? {
                if let Ok(target) = usize::try_from(target) {
                    joins.insert(target);
                }
            }
            if ends_flow(opcode) || unused_opcode(opcode) {
                joins.insert(position + width);
            }
        }
        position += width;
    }
    // Pass 2: registers holding constants, forgotten at joins and on writes.
    let mut registers: HashMap<u16, Constant> = HashMap::new();
    let mut found: BTreeSet<(u32, u8, Constant)> = BTreeSet::new();
    let mut position = 0;
    while position < units {
        if joins.contains(&position) {
            registers.clear();
        }
        let first = unit(position);
        let opcode = (first & 0xff) as u8;
        let width = width_at(position)?;
        let second = if width >= 2 { unit(position + 1) } else { 0 };
        // A wide result also overwrites the next register.
        let forget = |registers: &mut HashMap<u16, Constant>, register: u16| {
            registers.remove(&register);
            if writes_wide(opcode) {
                registers.remove(&register.wrapping_add(1));
            }
        };
        match opcode {
            // const/4 vA, #+B: B is a signed nibble.
            0x12 => {
                let register = first >> 8 & 0x0f;
                let value = i32::from(((first >> 12) as i8) << 4 >> 4);
                forget(&mut registers, register);
                registers.insert(register, Constant::Int(value));
            }
            // const/16 vAA, #+BBBB
            0x13 => {
                forget(&mut registers, first >> 8);
                registers.insert(first >> 8, Constant::Int(i32::from(second as i16)));
            }
            // const vAA, #+BBBBBBBB
            0x14 => {
                let value = (u32::from(second) | (u32::from(unit(position + 2)) << 16)) as i32;
                forget(&mut registers, first >> 8);
                registers.insert(first >> 8, Constant::Int(value));
            }
            // const/high16 vAA, #+BBBB0000
            0x15 => {
                forget(&mut registers, first >> 8);
                registers.insert(first >> 8, Constant::Int((u32::from(second) << 16) as i32));
            }
            // const-string vAA and const-string/jumbo vAA.
            0x1a | 0x1b => {
                let string = string_of(opcode, |index| unit(position + index)).unwrap_or_default();
                forget(&mut registers, first >> 8);
                registers.insert(first >> 8, Constant::String(string));
            }
            // move and move-object (12x, 22x, 32x): the constant moves with the value.
            0x01 | 0x02 | 0x03 | 0x07 | 0x08 | 0x09 => {
                let (destination, source) = match opcode {
                    0x01 | 0x07 => (first >> 8 & 0x0f, first >> 12),
                    0x02 | 0x08 => (first >> 8, second),
                    _ => (second, unit(position + 2)),
                };
                let value = registers.get(&source).copied();
                forget(&mut registers, destination);
                if let Some(value) = value {
                    registers.insert(destination, value);
                }
            }
            // invoke-* (35c) and invoke-*/range (3rc), by method ID.
            0x6e..=0x72 | 0x74..=0x78 => {
                let callee = u32::from(second);
                if callee >= method_count {
                    return Err(CodeProblem::Invalid);
                }
                let argument_registers: Vec<u16> = if opcode <= 0x72 {
                    let count = usize::from(first >> 12).min(5);
                    let packed = unit(position + 2);
                    let listed = [
                        packed & 0x0f,
                        packed >> 4 & 0x0f,
                        packed >> 8 & 0x0f,
                        packed >> 12,
                        first >> 8 & 0x0f,
                    ];
                    listed[..count].to_vec()
                } else {
                    let count = first >> 8;
                    let base = unit(position + 2);
                    (0..count).map(|offset| base.wrapping_add(offset)).collect()
                };
                for (slot, register) in argument_registers.iter().enumerate() {
                    if let (Some(value), Ok(slot)) = (registers.get(register), u8::try_from(slot)) {
                        found.insert((callee, slot, *value));
                    }
                }
            }
            _ if unused_opcode(opcode) => registers.clear(),
            _ => {
                if let Some(register) = written_register(opcode, first, second) {
                    forget(&mut registers, register);
                }
            }
        }
        position += width;
    }
    Ok(found.into_iter().collect())
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
    /// A signed LEB128 value of at most five bytes.
    fn read_signed(&mut self) -> Result<i32, CodeProblem> {
        let mut value: i64 = 0;
        for (index, shift) in [0, 7, 14, 21, 28].into_iter().enumerate() {
            let byte = *self.bytes.get(self.position).ok_or(CodeProblem::Invalid)?;
            self.position += 1;
            value |= i64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                let bits = 7 * (index + 1);
                if bits < 64 && byte & 0x40 != 0 {
                    value -= 1 << bits;
                }
                return i32::try_from(value).map_err(|_| CodeProblem::Invalid);
            }
        }
        Err(CodeProblem::Invalid)
    }

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

    /// The constant arguments of hand-assembled code (`handlers`: handler addresses).
    fn constants_of(code: &[u16], handlers: &[usize]) -> Vec<(u32, u8, Constant)> {
        call_constants(&|index| code[index], code.len(), handlers, 16).unwrap()
    }

    // invoke-static {vC} method@0 (35c, one argument).
    const fn invoke_one(register: u16) -> [u16; 3] {
        [0x1071, 0x0000, register]
    }

    #[test]
    fn constants_reach_calls_only_on_their_one_path() {
        // 0: const/4 v0, #1; 1: if-eqz v1, +5 (to 6); 3: invoke {v0}; 6: invoke {v0}
        let [a, b, c] = invoke_one(0);
        let code = [0x1012, 0x1038, 0x0005, a, b, c, a, b, c];
        // The fall-through call sees the constant; the branch target is a join, and does not.
        assert_eq!(constants_of(&code, &[]), [(0, 0, Constant::Int(1))]);
        let calls = |code: &[u16]| constants_of(code, &[]).len();
        // A move carries the constant: const-string v0 s3; move-object v1, v0; invoke {v1}.
        let [a, b, c] = invoke_one(1);
        let moved = [0x001a, 0x0003, 0x0107, a, b, c];
        assert_eq!(constants_of(&moved, &[]), [(0, 0, Constant::String(3))]);
        // A narrow write to v0 leaves v1: const/4 v1, #1; new-instance v0 t0; invoke {v1}.
        let narrow = [0x1112, 0x0022, 0x0000, a, b, c];
        assert_eq!(calls(&narrow), 1);
        // A wide write to v0 takes v1: const/4 v1, #1; const-wide/16 v0, #0; invoke {v1}.
        let wide = [0x1112, 0x0016, 0x0000, a, b, c];
        assert_eq!(calls(&wide), 0);
        // An exception handler is a join: const/4 v0, #1; invoke {v0} at 1 is a handler.
        let [a, b, c] = invoke_one(0);
        let handled = [0x1012, a, b, c];
        assert_eq!(constants_of(&handled, &[1]).len(), 0);
        assert_eq!(constants_of(&handled, &[]).len(), 1);
        // After an unconditional goto the next instruction is reached from elsewhere:
        // const/4 v0, #1; goto +4 (to 5); 2: invoke {v0}; 5: return-void.
        let after_goto = [0x1012, 0x0428, a, b, c, 0x000e];
        assert_eq!(constants_of(&after_goto, &[]).len(), 0);
    }

    #[test]
    fn switch_cases_are_joins_and_payloads_are_checked() {
        let [a, b, c] = invoke_one(0);
        // 0: const/4 v0, #1; 1: packed-switch v1, +7 (payload at 8); 4: invoke {v0} (case 0,
        // the payload's one target: +3 from the switch); 7: nop; 8: payload.
        let code = [
            0x1012, 0x012b, 0x0007, 0x0000, a, b, c, 0x0000, 0x0100, 0x0001, 0x0000, 0x0000,
            0x0003, 0x0000,
        ];
        assert_eq!(constants_of(&code, &[]).len(), 0);
        // A payload that is not one is malformed.
        let mut broken = code;
        broken[8] = 0x0300;
        assert!(call_constants(&|index| broken[index], broken.len(), &[], 16).is_err());
    }

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
