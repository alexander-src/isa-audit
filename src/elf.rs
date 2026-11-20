use std::fmt;

const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EM_X86_64: u16 = 62;

const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_DYNSYM: u32 = 11;
const SHF_EXECINSTR: u64 = 0x4;

const STT_FUNC: u8 = 2;
const SHN_UNDEF: u16 = 0;
const ET_REL: u16 = 1;

const ELF64_EHDR_SIZE: usize = 64;
const ELF64_SHDR_SIZE: usize = 64;
const ELF64_SYM_SIZE: usize = 24;

/// Typed errors returned while parsing an ELF64 binary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElfError {
    TooSmall { expected: usize, actual: usize },
    BadMagic,
    UnsupportedClass(u8),
    UnsupportedEndianness(u8),
    UnsupportedMachine(u16),
    InvalidSectionTable(String),
    OutOfBounds(&'static str),
}

impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ElfError::TooSmall { expected, actual } => {
                write!(
                    f,
                    "input too small for ELF64 header (need {expected} bytes, got {actual})"
                )
            }
            ElfError::BadMagic => write!(f, "file does not start with ELF magic bytes"),
            ElfError::UnsupportedClass(c) => {
                write!(
                    f,
                    "unsupported ELF class {c} (only 64-bit ELFCLASS64 supported)"
                )
            }
            ElfError::UnsupportedEndianness(e) => {
                write!(
                    f,
                    "unsupported ELF endianness {e} (only little-endian ELFDATA2LSB supported)"
                )
            }
            ElfError::UnsupportedMachine(m) => {
                write!(
                    f,
                    "unsupported ELF machine {m} (only x86-64 / EM_X86_64=62 supported)"
                )
            }
            ElfError::InvalidSectionTable(msg) => write!(f, "invalid ELF section table: {msg}"),
            ElfError::OutOfBounds(ctx) => write!(f, "ELF field points outside file bounds: {ctx}"),
        }
    }
}

impl std::error::Error for ElfError {}

/// An executable `SHT_PROGBITS` section extracted from an ELF64 file.
#[derive(Debug, Clone)]
pub struct ExecSection<'a> {
    pub index: u16,
    pub name: String,
    pub vaddr: u64,
    pub offset: u64,
    pub bytes: &'a [u8],
}

/// A function symbol span used for attribution and decoder resynchronization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolSpan {
    pub name: String,
    pub section_index: u16,
    pub addr: u64,
    pub size: u64,
}

/// Parsed view over an x86-64 ELF64 binary.
#[derive(Debug)]
pub struct ElfBinary<'a> {
    pub elf_type: u16,
    pub entry_point: u64,
    pub exec_sections: Vec<ExecSection<'a>>,
    pub symbols: Vec<SymbolSpan>,
}

#[derive(Debug, Clone, Copy)]
struct RawSectionHeader {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_entsize: u64,
}

fn read_u16_le(data: &[u8], off: usize, ctx: &'static str) -> Result<u16, ElfError> {
    let end = off.checked_add(2).ok_or(ElfError::OutOfBounds(ctx))?;
    let slice = data.get(off..end).ok_or(ElfError::OutOfBounds(ctx))?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32_le(data: &[u8], off: usize, ctx: &'static str) -> Result<u32, ElfError> {
    let end = off.checked_add(4).ok_or(ElfError::OutOfBounds(ctx))?;
    let slice = data.get(off..end).ok_or(ElfError::OutOfBounds(ctx))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_u64_le(data: &[u8], off: usize, ctx: &'static str) -> Result<u64, ElfError> {
    let end = off.checked_add(8).ok_or(ElfError::OutOfBounds(ctx))?;
    let slice = data.get(off..end).ok_or(ElfError::OutOfBounds(ctx))?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

fn slice_range<'a>(
    data: &'a [u8],
    offset: u64,
    size: u64,
    ctx: &'static str,
) -> Result<&'a [u8], ElfError> {
    let start = usize::try_from(offset).map_err(|_| ElfError::OutOfBounds(ctx))?;
    let len = usize::try_from(size).map_err(|_| ElfError::OutOfBounds(ctx))?;
    let end = start.checked_add(len).ok_or(ElfError::OutOfBounds(ctx))?;
    data.get(start..end).ok_or(ElfError::OutOfBounds(ctx))
}

fn read_cstr(strtab: &[u8], offset: u32) -> String {
    let start = offset as usize;
    if start >= strtab.len() {
        return String::new();
    }
    let tail = &strtab[start..];
    let nul = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
    String::from_utf8_lossy(&tail[..nul]).into_owned()
}

impl<'a> ElfBinary<'a> {
    /// Parses an x86-64 ELF64 binary completely in memory with zero `unsafe` code.
    pub fn parse(data: &'a [u8]) -> Result<Self, ElfError> {
        if data.len() < ELF64_EHDR_SIZE {
            return Err(ElfError::TooSmall {
                expected: ELF64_EHDR_SIZE,
                actual: data.len(),
            });
        }
        if data[0..4] != ELF_MAGIC {
            return Err(ElfError::BadMagic);
        }
        if data[4] != ELFCLASS64 {
            return Err(ElfError::UnsupportedClass(data[4]));
        }
        if data[5] != ELFDATA2LSB {
            return Err(ElfError::UnsupportedEndianness(data[5]));
        }

        let elf_type = read_u16_le(data, 16, "e_type")?;
        let machine = read_u16_le(data, 18, "e_machine")?;
        if machine != EM_X86_64 {
            return Err(ElfError::UnsupportedMachine(machine));
        }

        let entry_point = read_u64_le(data, 24, "e_entry")?;
        let e_shoff = read_u64_le(data, 40, "e_shoff")?;
        let e_shentsize = read_u16_le(data, 58, "e_shentsize")? as usize;
        let e_shnum = read_u16_le(data, 60, "e_shnum")? as usize;
        let e_shstrndx = read_u16_le(data, 62, "e_shstrndx")? as usize;

        if e_shoff == 0 || e_shnum == 0 {
            return Err(ElfError::InvalidSectionTable(
                "binary has no section headers".to_string(),
            ));
        }
        if e_shentsize < ELF64_SHDR_SIZE {
            return Err(ElfError::InvalidSectionTable(format!(
                "e_shentsize ({e_shentsize}) smaller than ELF64 section header ({ELF64_SHDR_SIZE})"
            )));
        }

        let shoff_usize = usize::try_from(e_shoff).map_err(|_| ElfError::OutOfBounds("e_shoff"))?;
        let total_sh_bytes = e_shentsize
            .checked_mul(e_shnum)
            .ok_or(ElfError::OutOfBounds("section header table size"))?;
        let sh_end = shoff_usize
            .checked_add(total_sh_bytes)
            .ok_or(ElfError::OutOfBounds("section header table end"))?;
        if sh_end > data.len() {
            return Err(ElfError::OutOfBounds("section header table"));
        }

        let mut raw_sections = Vec::with_capacity(e_shnum);
        for idx in 0..e_shnum {
            let base = shoff_usize + idx * e_shentsize;
            raw_sections.push(RawSectionHeader {
                sh_name: read_u32_le(data, base, "sh_name")?,
                sh_type: read_u32_le(data, base + 4, "sh_type")?,
                sh_flags: read_u64_le(data, base + 8, "sh_flags")?,
                sh_addr: read_u64_le(data, base + 16, "sh_addr")?,
                sh_offset: read_u64_le(data, base + 24, "sh_offset")?,
                sh_size: read_u64_le(data, base + 32, "sh_size")?,
                sh_link: read_u32_le(data, base + 40, "sh_link")?,
                sh_entsize: read_u64_le(data, base + 56, "sh_entsize")?,
            });
        }

        let shstrtab: &[u8] = if e_shstrndx < raw_sections.len() {
            let sh = raw_sections[e_shstrndx];
            if sh.sh_type == SHT_STRTAB {
                slice_range(data, sh.sh_offset, sh.sh_size, "shstrtab")?
            } else {
                &[]
            }
        } else {
            &[]
        };

        let mut exec_sections = Vec::new();
        let mut symbols = Vec::new();

        for (sec_idx, sh) in raw_sections.iter().enumerate() {
            if sh.sh_type == SHT_PROGBITS && (sh.sh_flags & SHF_EXECINSTR) != 0 && sh.sh_size > 0 {
                let bytes = slice_range(data, sh.sh_offset, sh.sh_size, "executable section")?;
                let mut name = read_cstr(shstrtab, sh.sh_name);
                if name.is_empty() {
                    name = format!("<exec@0x{:x}>", sh.sh_addr);
                }
                exec_sections.push(ExecSection {
                    index: sec_idx as u16,
                    name,
                    vaddr: sh.sh_addr,
                    offset: sh.sh_offset,
                    bytes,
                });
            } else if matches!(sh.sh_type, SHT_SYMTAB | SHT_DYNSYM) && sh.sh_size > 0 {
                let entsize = if sh.sh_entsize == 0 {
                    ELF64_SYM_SIZE as u64
                } else {
                    sh.sh_entsize
                };
                if entsize < ELF64_SYM_SIZE as u64 {
                    continue;
                }
                let link = sh.sh_link as usize;
                let strtab = match raw_sections.get(link) {
                    Some(str_sh) if str_sh.sh_type == SHT_STRTAB => {
                        slice_range(data, str_sh.sh_offset, str_sh.sh_size, "symbol strtab")
                            .unwrap_or(&[])
                    }
                    _ => &[],
                };
                if let Ok(sym_bytes) = slice_range(data, sh.sh_offset, sh.sh_size, "symtab") {
                    let step = entsize as usize;
                    let mut pos = 0usize;
                    while pos + ELF64_SYM_SIZE <= sym_bytes.len() {
                        let st_name = u32::from_le_bytes([
                            sym_bytes[pos],
                            sym_bytes[pos + 1],
                            sym_bytes[pos + 2],
                            sym_bytes[pos + 3],
                        ]);
                        let st_info = sym_bytes[pos + 4];
                        let st_type = st_info & 0x0F;
                        let st_shndx = u16::from_le_bytes([sym_bytes[pos + 6], sym_bytes[pos + 7]]);
                        let st_value = u64::from_le_bytes([
                            sym_bytes[pos + 8],
                            sym_bytes[pos + 9],
                            sym_bytes[pos + 10],
                            sym_bytes[pos + 11],
                            sym_bytes[pos + 12],
                            sym_bytes[pos + 13],
                            sym_bytes[pos + 14],
                            sym_bytes[pos + 15],
                        ]);
                        let st_size = u64::from_le_bytes([
                            sym_bytes[pos + 16],
                            sym_bytes[pos + 17],
                            sym_bytes[pos + 18],
                            sym_bytes[pos + 19],
                            sym_bytes[pos + 20],
                            sym_bytes[pos + 21],
                            sym_bytes[pos + 22],
                            sym_bytes[pos + 23],
                        ]);

                        // In ET_REL object files, the first function in a section legitimately
                        // lives at st_value == 0, so we filter undefined imports via st_shndx.
                        let is_defined =
                            st_shndx != SHN_UNDEF && (elf_type == ET_REL || st_value != 0);
                        if st_type == STT_FUNC && is_defined {
                            let name = read_cstr(strtab, st_name);
                            if !name.is_empty() {
                                symbols.push(SymbolSpan {
                                    name,
                                    section_index: st_shndx,
                                    addr: st_value,
                                    size: st_size,
                                });
                            }
                        }
                        pos = match pos.checked_add(step) {
                            Some(next) => next,
                            None => break,
                        };
                    }
                }
            }
        }

        symbols.sort_by(|a, b| {
            a.section_index
                .cmp(&b.section_index)
                .then_with(|| a.addr.cmp(&b.addr))
                .then_with(|| b.size.cmp(&a.size))
        });
        symbols.dedup_by(|a, b| {
            a.section_index == b.section_index && a.addr == b.addr && a.size == b.size
        });

        Ok(ElfBinary {
            elf_type,
            entry_point,
            exec_sections,
            symbols,
        })
    }

    /// Resolves a virtual address inside a specific executable section to its function symbol.
    pub fn resolve_symbol(&self, section_index: u16, vaddr: u64) -> Option<(&str, u64)> {
        if self.symbols.is_empty() {
            return None;
        }
        let sec_start = self
            .symbols
            .partition_point(|s| s.section_index < section_index);
        let sec_end = self
            .symbols
            .partition_point(|s| s.section_index <= section_index);
        let slice = &self.symbols[sec_start..sec_end];
        if slice.is_empty() {
            return None;
        }

        let idx = slice.partition_point(|s| s.addr <= vaddr);
        if idx == 0 {
            return None;
        }
        // Walk backwards across co-located aliases if needed.
        for sym in slice[..idx].iter().rev().take(8) {
            let offset = vaddr - sym.addr;
            if sym.size > 0 && offset < sym.size {
                return Some((sym.name.as_str(), offset));
            }
        }
        // Fallback: if symbol has st_size == 0 (assembly label), allow small proximity window.
        let nearest = &slice[idx - 1];
        if nearest.size == 0 && vaddr - nearest.addr < 0x1000 {
            return Some((nearest.name.as_str(), vaddr - nearest.addr));
        }
        None
    }
}
