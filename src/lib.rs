use std::mem::{
	size_of,
	transmute,
};

use winapi::shared::minwindef::*;
use winapi::um::winnt::*;

#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct IMAGE_COFF_HEADER {
	Magic: WORD,
	MajorLinkerVersion: BYTE,
	MinorLinkerVersion: BYTE,
	SizeOfCode: DWORD,
	SizeOfInitializedData: DWORD,
	SizeOfUninitializedData: DWORD,
	AddressOfEntryPoint: DWORD,
	BaseOfCode: DWORD,
}







macro_rules! bitfield {
    (
		$public:vis struct $name:ident : $base_type:ty { 
			$( $field:ident : $value:expr ),+ 
		}
	) => {
        #[derive(Copy, Clone, Debug, PartialEq, Eq)]
        $public struct $name {
			is_unknown: bool,
            $( pub $field: bool ),*
		}
		impl Default for $name {
			fn default() -> Self {
				Self::none()
			}
		}
        impl $name {
			pub fn none() -> Self {
                Self {
					is_unknown: false,
                    $( $field: false ),*
                }
			}
			pub fn all() -> Self {
				Self {
					is_unknown: false,
                    $( $field: true ),*
                }
			}
            pub fn parse(flags: $base_type) -> Self {
				let combined = Self::all().value();
                Self {
					is_unknown: ((combined ^ flags) + flags) != combined,
                    $( $field: (flags & $value as $base_type) != 0 ),*
				}
            }
            pub fn value(&self) -> $base_type {
                $( self.$field as $base_type * $value as $base_type )|*
			}
			pub fn is_valid(&self) -> bool {
				!self.is_unknown
			}
		}
	};


	(
		$public:vis enum $name:ident : $base_type:ty  {
			$( $field:ident : $value:expr ),*
		}
	) => {
        #[derive(Copy, Clone, Debug, PartialEq, Eq)]
        $public enum $name {
            Unknown = 0,
            $( $field ),*
		}
		impl Default for $name {
			fn default() -> Self {
				Self::Unknown
			}
		}
        impl $name {
            pub fn parse(flag: $base_type) -> Self {
				$(
					if (flag == $value as $base_type) {
						return Self::$field;
					}
				)*
				Self::Unknown
            }
            pub fn value(&self) -> $base_type {
                match self {
                    $( Self::$field => $value as $base_type, )*
                    _ => 0,
                }
			}
			pub fn is_valid(&self) -> bool {
				match self {
					Self::Unknown => false,
					_ => true,
				}
			}
		}
    };
}
macro_rules! impl_core_vec {
	( $ident:ident $( , $var:ident : $var_ty:ty )* ) => {
		impl $ident {
			pub fn read<T>(data: &Vec<T>, offset: usize $( , $var : $var_ty )*) -> Result<Self, OutOfBoundsError> {
				unsafe {
					Self::read_buffer(data.as_ptr(), Some(data.len()), offset $( , $var )*)
				}
			}
			pub fn write<T>(&self, data: &mut Vec<T>, offset: usize) -> Result<(), OutOfBoundsError> {
				unsafe {
					self.write_buffer(data.as_mut_ptr(), Some(data.len()), offset)
				}
			}
		}
	}
}
macro_rules! impl_core_buffer {
	( $ident:ident : $read_size:expr $( , $var:ident : $var_ty:ty )* ) => {
		impl $ident {
			pub unsafe fn read_buffer<T>(data: *const T, length: Option<usize>, offset: usize $( , $var : $var_ty )*) -> Result<Self, OutOfBoundsError> {
				let value_size = ::std::mem::size_of::<T>();
				if let Some(length) = length {
					if length < ($read_size / value_size + offset) {
						return Err(OutOfBoundsError {});
					}
				}
				Self::read_interface(::std::mem::transmute((data as usize + (offset * value_size)) as *const T) $( , $var )*)
			}
		
			pub unsafe fn write_buffer<T>(&self, data: *mut T, length: Option<usize>, offset: usize) -> Result<(), OutOfBoundsError> {
				let value_size = ::std::mem::size_of::<T>();
				if let Some(length) = length {
					if length < (self.get_size() / value_size + offset) {
						return Err(OutOfBoundsError {});
					}
				}
				
				self.write_interface(::std::mem::transmute((data as usize + (offset * value_size)) as *mut T));
				Ok(())
			}
		}
	}
}
macro_rules! impl_core {
	( $ident:ident $( , $var:ident : $var_ty:ty )* ) => {
		impl_core_vec!($ident $( , $var : $var_ty )* );
		impl_core_buffer!($ident : Self::static_size() $( , $var : $var_ty )* );
		impl $ident {
			pub fn get_size(&self) -> usize {
				Self::static_size()
			}
		}
	};
	( $ident:ident : $read_size:expr $( , $var:ident : $var_ty:ty )* ) => {
		impl_core_vec!($ident $( , $var : $var_ty )* );
		impl_core_buffer!($ident : $read_size $( , $var : $var_ty )* );
	};
}


unsafe fn offset_ptr<T>(pointer: *const T, offset: isize) -> *const T {
	(pointer as isize + offset) as *const T
}
unsafe fn offset_ptr_mut<T>(pointer: *mut T, offset: isize) -> *mut T {
	(pointer as isize + offset) as *mut T
}




#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct OutOfBoundsError;




#[derive(Clone, Debug)]
pub struct DosStub {
	pub rva: usize,
	pub size: usize,
}
#[derive(Clone, Debug)]
pub struct DosHeader {
    pub e_magic: WORD,
    pub e_cblp: WORD,
    pub e_cp: WORD,
    pub e_crlc: WORD,
    pub e_cparhdr: WORD,
    pub e_minalloc: WORD,
    pub e_maxalloc: WORD,
    pub e_ss: WORD,
    pub e_sp: WORD,
    pub e_csum: WORD,
    pub e_ip: WORD,
    pub e_cs: WORD,
    pub e_lfarlc: WORD,
    pub e_ovno: WORD,
    pub e_res: [WORD; 4],
    pub e_oemid: WORD,
    pub e_oeminfo: WORD,
    pub e_res2: [WORD; 10],
    pub e_lfanew: LONG,

	pub stub: DosStub,
}
impl_core!(DosHeader);
impl DosHeader {
	unsafe fn read_interface(i: &IMAGE_DOS_HEADER) -> Result<Self, OutOfBoundsError> {
		Ok(Self {
			e_magic: i.e_magic,
			e_cblp: i.e_cblp,
			e_cp: i.e_cp,
			e_crlc: i.e_crlc,
			e_cparhdr: i.e_cparhdr,
			e_minalloc: i.e_minalloc,
			e_maxalloc: i.e_maxalloc,
			e_ss: i.e_ss,
			e_sp: i.e_sp,
			e_csum: i.e_csum,
			e_ip: i.e_ip,
			e_cs: i.e_cs,
			e_lfarlc: i.e_lfarlc,
			e_ovno: i.e_ovno,
			e_res: i.e_res,
			e_oemid: i.e_oemid,
			e_oeminfo: i.e_oeminfo,
			e_res2: i.e_res2,
			e_lfanew: i.e_lfanew,

			stub: DosStub {
				rva: Self::static_size(),
				size: i.e_lfanew as usize - Self::static_size(),
			}
		})
	}
	unsafe fn write_interface(&self, i: &mut IMAGE_DOS_HEADER) {
		i.e_magic = self.e_magic;
		i.e_cblp = self.e_cblp;
		i.e_cp = self.e_cp;
		i.e_crlc = self.e_crlc;
		i.e_cparhdr = self.e_cparhdr;
		i.e_minalloc = self.e_minalloc;
		i.e_maxalloc = self.e_maxalloc;
		i.e_ss = self.e_ss;
		i.e_sp = self.e_sp;
		i.e_csum = self.e_csum;
		i.e_ip = self.e_ip;
		i.e_cs = self.e_cs;
		i.e_lfarlc = self.e_lfarlc;
		i.e_ovno = self.e_ovno;
		i.e_res = self.e_res;
		i.e_oemid = self.e_oemid;
		i.e_oeminfo = self.e_oeminfo;
		i.e_res2 = self.e_res2;
		i.e_lfanew = self.e_lfanew;
	}

	pub fn static_size() -> usize {
		size_of::<IMAGE_DOS_HEADER>()
	}
	pub fn is_valid(&self) -> bool {
		self.e_magic == IMAGE_DOS_SIGNATURE &&
		self.e_lfanew as usize >= Self::static_size() &&
		self.e_lfanew % 8 == 0 &&
		self.e_res.iter().fold(true, |is_zero, x| is_zero && *x == 0) &&
		self.e_res2.iter().fold(true, |is_zero, x| is_zero && *x == 0)
	}
}




const IMAGE_RICH_SIGNATURE: DWORD = 0x68636952;
const IMAGE_DANS_SIGNATURE: DWORD = 0x536E6144;

#[derive(Clone, Debug)]
pub struct RichProductIdentifier {
	pub build_number: WORD,
	pub product_id: WORD,
	pub count: DWORD,
}
#[derive(Clone, Debug)]
pub struct RichHeader {
	has_dans_signature: bool,

	pub rva: usize,
	pub size: usize,

	pub identifiers: Vec<RichProductIdentifier>,
	pub xor_key: DWORD,
}
impl RichHeader {
	pub fn read<T>(data: &Vec<T>, start: usize, stop: usize) -> Result<Option<Self>, OutOfBoundsError> {
		if start + stop > data.len() {
			return Err(OutOfBoundsError {});
		}
		unsafe {
			Self::read_buffer(data.as_ptr(), start, stop)
		}
	}
	pub unsafe fn read_buffer<T>(data: *const T, start: usize, stop: usize) -> Result<Option<Self>, OutOfBoundsError> {
		let type_size = size_of::<DWORD>();
		let data = data as *const u8;
		
		// Pattern scan for the `Rich` signature
		let rich_index = match Self::find_signature( data, start, stop) {
			Some(index) => index,
			None => return Ok(None),
		};

		// The xor key is located right after the `Rich` signature
		let xor_index = rich_index + type_size;
		if xor_index > stop - type_size {
			return Err(OutOfBoundsError {});
		}
		let xor_key = *(offset_ptr(data, xor_index as isize) as *const DWORD);

		// Iterate backwards in steps of size_of(dword), while xor'ing to decrypt the identifiers
		// Ignore null bytes
		// Stop after decrypting the `DanS` signature or before going out of bounds
		// Every identifier is the size of 2 DWORD (reversed), the first DWORD is the count
		// the second DWORD is the build number and product id
		let mut has_dans_signature = false;
		let mut ids = vec!();
		let mut index = rich_index - type_size;
		let mut is_first_dword = true;
		while index >= start {
			let value = xor_key ^ *(offset_ptr(data, index as isize) as * const DWORD);

			if value == IMAGE_DANS_SIGNATURE {
				has_dans_signature = true;
				break
			}
			else if value != 0 {
				if is_first_dword {
					is_first_dword = false;
					ids.push(RichProductIdentifier {
						build_number: 0,
						product_id: 0,
						count: value,
					});
				} else {
					is_first_dword = true;
					if let Some(id) = ids.last_mut() {
						id.build_number = (value & 0xffff) as WORD;
						id.product_id = ((value >> (size_of::<WORD>() * 8)) & 0xffff) as WORD;
					}
				}
			}
			index -= 4;
		}

		Ok(Some(Self {
			rva: index,
			size: (xor_index + type_size) - index,

			identifiers: ids,
			xor_key: xor_key,
			has_dans_signature: has_dans_signature,
		}))
	}
	unsafe fn find_signature(bytes: *const u8, start: usize, stop: usize) -> Option<usize>{
		let mut rich_index = None;
		let mut index = start;
		'outer: while index < stop {
			'inner: for offset in 0..(size_of::<DWORD>()) {
				let byte = *offset_ptr(bytes, (index + offset) as isize);
				if byte != ((IMAGE_RICH_SIGNATURE >> (offset * 8)) & 0xff) as u8 {
					index += offset;
					break 'inner;
				}
				else if offset == size_of::<DWORD>() - 1 {
					rich_index = Some(index);
					break 'outer;
				}
			}
			index += 1;
		}
		rich_index
	}

	pub fn is_valid(&self) -> bool {
		self.has_dans_signature &&
		self.size != 0
	}
}




#[derive(Clone, Debug)]
pub struct FileHeader {
    pub machine: ImageFileMachine,
    pub number_of_sections: WORD,
    pub time_date_stamp: DWORD,
    pub pointer_to_symbol_table: DWORD,
    pub number_of_symbols: DWORD,
    pub size_of_optional_header: WORD,
    pub characteristics: ImageFileCharacteristics,
}
impl_core!(FileHeader);
impl FileHeader {
	unsafe fn read_interface(i: &IMAGE_FILE_HEADER) -> Result<Self, OutOfBoundsError> {
		Ok(Self {
			machine: ImageFileMachine::parse(i.Machine),
			number_of_sections: i.NumberOfSections,
			time_date_stamp: i.TimeDateStamp,
			pointer_to_symbol_table: i.PointerToSymbolTable,
			number_of_symbols: i.NumberOfSymbols,
			size_of_optional_header: i.SizeOfOptionalHeader,
			characteristics: ImageFileCharacteristics::parse(i.Characteristics),
		})
	}
	unsafe fn write_interface(&self, i: &mut IMAGE_FILE_HEADER) {
		i.Machine = self.machine.value();
		i.NumberOfSections = self.number_of_sections;
		i.TimeDateStamp = self.time_date_stamp;
		i.PointerToSymbolTable = self.pointer_to_symbol_table;
		i.NumberOfSymbols = self.number_of_symbols;
		i.SizeOfOptionalHeader = self.size_of_optional_header;
		i.Characteristics = self.characteristics.value();
	}

	pub fn static_size() -> usize {
		size_of::<IMAGE_FILE_HEADER>()
	}
	pub fn is_valid(&self) -> bool {
		self.machine.is_valid() &&
		self.characteristics.is_valid()
	}
}
bitfield!{
	pub enum ImageFileMachine : WORD {
		Am33: IMAGE_FILE_MACHINE_AM33,
		Amd64: IMAGE_FILE_MACHINE_AMD64,
		Arm: IMAGE_FILE_MACHINE_ARM,
		Arm64: IMAGE_FILE_MACHINE_ARM64,
		ArmNt: IMAGE_FILE_MACHINE_ARMNT,
		Ebc: IMAGE_FILE_MACHINE_EBC,
		I386: IMAGE_FILE_MACHINE_I386,
		Ia64: IMAGE_FILE_MACHINE_IA64,
		M32R: IMAGE_FILE_MACHINE_M32R,
		Mips16: IMAGE_FILE_MACHINE_MIPS16,
		MipsFpu: IMAGE_FILE_MACHINE_MIPSFPU,
		MipsFpu16: IMAGE_FILE_MACHINE_MIPSFPU16,
		PowerPc: IMAGE_FILE_MACHINE_POWERPC,
		PowerPcFp: IMAGE_FILE_MACHINE_POWERPCFP,
		R4000: IMAGE_FILE_MACHINE_R4000,
		Sh3: IMAGE_FILE_MACHINE_SH3,
		Sh3Dsp: IMAGE_FILE_MACHINE_SH3DSP,
		Sh4: IMAGE_FILE_MACHINE_SH4,
		Sh5: IMAGE_FILE_MACHINE_SH5,
		Thumb: IMAGE_FILE_MACHINE_THUMB,
		MipsWceV2: IMAGE_FILE_MACHINE_WCEMIPSV2
	}
}
bitfield!{
	pub struct ImageFileCharacteristics : WORD {
		relocs_stripped: IMAGE_FILE_RELOCS_STRIPPED,
		executable_image: IMAGE_FILE_EXECUTABLE_IMAGE,
		line_nums_stripped: IMAGE_FILE_LINE_NUMS_STRIPPED,
		local_syms_stripped: IMAGE_FILE_LOCAL_SYMS_STRIPPED,
		aggresive_ws_trim: IMAGE_FILE_AGGRESIVE_WS_TRIM,
		large_address_aware: IMAGE_FILE_LARGE_ADDRESS_AWARE,
		bytes_reversed_lo: IMAGE_FILE_BYTES_REVERSED_LO,
		machine_32bit: IMAGE_FILE_32BIT_MACHINE,
		debug_stripped: IMAGE_FILE_DEBUG_STRIPPED,
		removable_run_from_swap: IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP,
		not_run_from_swap: IMAGE_FILE_NET_RUN_FROM_SWAP,
		system: IMAGE_FILE_SYSTEM,
		dll: IMAGE_FILE_DLL,
		up_system_only: IMAGE_FILE_UP_SYSTEM_ONLY
		//bytes_reversed_hi: IMAGE_FILE_BYTES_REVERSED_HI
	}
}




#[derive(Clone, Debug)]
pub struct CoffHeader {
	pub magic: ImageMagic,
	pub major_linker_version: BYTE,
	pub minor_linker_version: BYTE,
	pub size_of_code: DWORD,
	pub size_of_initialized_data: DWORD,
	pub size_of_uninitialized_data: DWORD,
	pub address_of_entry_point: DWORD,
	pub base_of_code: DWORD,
}
impl_core!(CoffHeader);
impl CoffHeader {
	unsafe fn read_interface(i: &IMAGE_COFF_HEADER) -> Result<Self, OutOfBoundsError> {
		Ok(Self {
			magic: ImageMagic::parse(i.Magic),
			major_linker_version: i.MajorLinkerVersion,
			minor_linker_version: i.MinorLinkerVersion,
			size_of_code: i.SizeOfCode,
			size_of_initialized_data: i.SizeOfInitializedData,
			size_of_uninitialized_data: i.SizeOfUninitializedData,
			address_of_entry_point: i.AddressOfEntryPoint,
			base_of_code: i.BaseOfCode,
		})
	}
	unsafe fn write_interface(&self, i: &mut IMAGE_COFF_HEADER) {
		i.Magic = self.magic.value();
		i.MajorLinkerVersion = self.major_linker_version;
		i.MinorLinkerVersion = self.minor_linker_version;
		i.SizeOfCode = self.size_of_code;
		i.SizeOfInitializedData = self.size_of_initialized_data;
		i.SizeOfUninitializedData = self.size_of_uninitialized_data;
		i.AddressOfEntryPoint = self.address_of_entry_point;
		i.BaseOfCode = self.base_of_code;
	}

	pub fn static_size() -> usize {
		size_of::<IMAGE_COFF_HEADER>()
	}
	pub fn is_valid(&self) -> bool {
		self.magic.is_valid()
	}
}
bitfield!{
	pub enum ImageMagic : WORD {
    	Pe32: IMAGE_NT_OPTIONAL_HDR32_MAGIC,
	    Pe32Plus: IMAGE_NT_OPTIONAL_HDR64_MAGIC,
    	Rom: IMAGE_ROM_OPTIONAL_HDR_MAGIC
	}
}




#[derive(Clone, Debug)]
pub enum OptionalHeader {
	Unknown,
	Pe32(OptionalHeader32),
	Pe32Plus(OptionalHeader64),
	Rom(OptionalHeaderRom),
}
impl_core_vec!(OptionalHeader, size: usize, magic: ImageMagic);
impl OptionalHeader {
	pub unsafe fn read_buffer<T>(data: *const T, length: Option<usize>, offset: usize, size: usize, magic: ImageMagic) -> Result<Self, OutOfBoundsError> {
		let optional = match magic {
			ImageMagic::Rom => OptionalHeader::Rom(
				OptionalHeaderRom::read_buffer(data, length, offset, size)?
			),
			ImageMagic::Pe32 => OptionalHeader::Pe32(
				OptionalHeader32::read_buffer(data, length, offset, size)?
			),
			ImageMagic::Pe32Plus => OptionalHeader::Pe32Plus(
				OptionalHeader64::read_buffer(data, length, offset, size)?
			),
			ImageMagic::Unknown => OptionalHeader::Unknown,
		};
		Ok(optional)
	}
	pub unsafe fn write_buffer<T>(&self, data: *mut T, length: Option<usize>, offset: usize) -> Result<(), OutOfBoundsError> {
		match self {
			Self::Unknown => Ok(()), 
			Self::Rom(header) => header.write_buffer(data, length, offset), 
			Self::Pe32(header) => header.write_buffer(data, length, offset), 
			Self::Pe32Plus(header) => header.write_buffer(data, length, offset), 
		}
	}

	pub fn static_size(&self) -> usize {
		match self {
			Self::Unknown => 0, 
			Self::Rom(_) => OptionalHeaderRom::static_size(), 
			Self::Pe32(_) => OptionalHeader32::static_size(), 
			Self::Pe32Plus(_) => OptionalHeader64::static_size(), 
		}
	}
	pub fn get_size(&self) -> usize {
		match self {
			Self::Unknown => 0, 
			Self::Rom(header) => header.get_size(), 
			Self::Pe32(header) => header.get_size(), 
			Self::Pe32Plus(header) => header.get_size(), 
		}
	}
	pub fn is_valid(&self) -> bool {
		match self {
			Self::Unknown => false, 
			Self::Rom(_) => true, 
			Self::Pe32(header) => header.is_valid(), 
			Self::Pe32Plus(header) => header.is_valid(), 
		}
	}
}

#[derive(Clone, Debug)]
pub struct OptionalHeaderRom {
	size: usize,

	pub base_of_data: DWORD,
    pub base_of_bss: DWORD,
    pub gpr_mask: DWORD,
    pub cpr_mask: [DWORD; 4],
    pub gp_value: DWORD,
}
impl_core!(OptionalHeaderRom: size, size: usize);
impl OptionalHeaderRom {
	unsafe fn read_interface(i: &IMAGE_ROM_OPTIONAL_HEADER, size: usize) -> Result<Self, OutOfBoundsError> {
		let i: &IMAGE_ROM_OPTIONAL_HEADER = transmute(
			offset_ptr(i as *const _, -(CoffHeader::static_size() as isize))
		);

		Ok(Self {
			size: size,

			base_of_data: i.BaseOfData,
			base_of_bss: i.BaseOfBss,
			gpr_mask: i.GprMask,
			cpr_mask: i.CprMask,
			gp_value: i.GpValue,
		})
	}
	unsafe fn write_interface(&self, i: &mut IMAGE_ROM_OPTIONAL_HEADER) {
		let i: &mut IMAGE_ROM_OPTIONAL_HEADER = transmute(
			offset_ptr_mut(i as *mut _, -(CoffHeader::static_size() as isize))
		);

		i.BaseOfData = self.base_of_data;
		i.BaseOfBss = self.base_of_bss;
		i.GprMask = self.gpr_mask;
		i.CprMask = self.cpr_mask;
		i.GpValue = self.gp_value;
	}

	pub fn static_size() -> usize {
		size_of::<IMAGE_ROM_OPTIONAL_HEADER>() - CoffHeader::static_size()
	}
	pub fn get_size(&self) -> usize {
		self.size
	}
}


#[derive(Clone, Debug)]
pub struct OptionalHeader32 {
	pub size: usize,

    pub base_of_data: DWORD,
    pub image_base: DWORD,
    pub section_alignment: DWORD,
    pub file_alignment: DWORD,
    pub major_operating_system_version: WORD,
    pub minor_operating_system_version: WORD,
    pub major_image_version: WORD,
    pub minor_image_version: WORD,
    pub major_subsystem_version: WORD,
    pub minor_subsystem_version: WORD,
    pub win32_version_value: DWORD,
    pub size_of_image: DWORD,
    pub size_of_headers: DWORD,
    pub checksum: DWORD,
    pub subsystem: ImageSubsystem,
    pub dll_characteristics: ImageDllCharacteristics,
    pub size_of_stack_reserve: DWORD,
    pub size_of_stack_commit: DWORD,
    pub size_of_heap_reserve: DWORD,
    pub size_of_heap_commit: DWORD,
    pub loader_flags: DWORD,
    pub number_of_rva_and_sizes: DWORD,
    pub data_directory: DataDirectory,
}
impl_core!(OptionalHeader32: size, size: usize);
impl OptionalHeader32 {
	unsafe fn read_interface(i: &IMAGE_OPTIONAL_HEADER32, size: usize) -> Result<Self, OutOfBoundsError> {
		let i: &IMAGE_OPTIONAL_HEADER32 = transmute(
			offset_ptr(i as *const _, -(CoffHeader::static_size() as isize))
		);

		let data_directory;
		if i.NumberOfRvaAndSizes == 0 {
			data_directory = DataDirectory::default();
		} else {
			data_directory = DataDirectory::read_interface(&i.DataDirectory[0], i.NumberOfRvaAndSizes as usize)?;
		}

		Ok(Self {
			size: size,

			base_of_data: i.BaseOfData,
			image_base: i.ImageBase,
			section_alignment: i.SectionAlignment,
			file_alignment: i.FileAlignment,
			major_operating_system_version: i.MajorOperatingSystemVersion,
			minor_operating_system_version: i.MinorOperatingSystemVersion,
			major_image_version: i.MajorImageVersion,
			minor_image_version: i.MinorImageVersion,
			major_subsystem_version: i.MajorSubsystemVersion,
			minor_subsystem_version: i.MinorSubsystemVersion,
			win32_version_value: i.Win32VersionValue,
			size_of_image: i.SizeOfImage,
			size_of_headers: i.SizeOfHeaders,
			checksum: i.CheckSum,
			subsystem: ImageSubsystem::parse(i.Subsystem),
			dll_characteristics: ImageDllCharacteristics::parse(i.DllCharacteristics),
			size_of_stack_reserve: i.SizeOfStackReserve,
			size_of_stack_commit: i.SizeOfStackCommit,
			size_of_heap_reserve: i.SizeOfHeapReserve,
			size_of_heap_commit: i.SizeOfHeapCommit,
			loader_flags: i.LoaderFlags,
			number_of_rva_and_sizes: i.NumberOfRvaAndSizes,
			data_directory: data_directory,
		})
	}
	unsafe fn write_interface(&self, i: &mut IMAGE_OPTIONAL_HEADER32) {
		let i: &mut IMAGE_OPTIONAL_HEADER32 = transmute(
			offset_ptr_mut(i as *mut _, -(CoffHeader::static_size() as isize))
		);

		i.BaseOfData = self.base_of_data;
		i.ImageBase = self.image_base;
		i.SectionAlignment = self.section_alignment;
		i.FileAlignment = self.file_alignment;
		i.MajorOperatingSystemVersion = self.major_operating_system_version;
		i.MinorOperatingSystemVersion = self.minor_operating_system_version;
		i.MajorImageVersion = self.major_image_version;
		i.MinorImageVersion = self.minor_image_version;
		i.MajorSubsystemVersion = self.major_subsystem_version;
		i.MinorSubsystemVersion = self.minor_subsystem_version;
		i.Win32VersionValue = self.win32_version_value;
		i.SizeOfImage = self.size_of_image;
		i.SizeOfHeaders = self.size_of_headers;
		i.CheckSum = self.checksum;
		i.Subsystem = self.subsystem.value();
		i.DllCharacteristics = self.dll_characteristics.value();
		i.SizeOfStackReserve = self.size_of_stack_reserve;		
		i.SizeOfStackCommit = self.size_of_stack_commit;
		i.SizeOfHeapReserve = self.size_of_heap_reserve;
		i.SizeOfHeapCommit = self.size_of_heap_commit;
		i.LoaderFlags = self.loader_flags;
		i.NumberOfRvaAndSizes = self.number_of_rva_and_sizes;
		self.data_directory.write_interface(transmute(&mut i.DataDirectory));
	}


	pub fn static_size() -> usize {
		size_of::<IMAGE_OPTIONAL_HEADER32>() - CoffHeader::static_size()
	}
	pub fn get_size(&self) -> usize {
		self.size
	}
	pub fn is_valid(&self) -> bool {
		self.section_alignment >= self.file_alignment &&
		self.file_alignment >= 512 && self.file_alignment <= 65536 &&
		(self.file_alignment & (self.file_alignment - 1)) == 0 &&
		self.win32_version_value == 0 &&
		self.size_of_image % self.section_alignment == 0 &&
		self.size_of_headers % self.file_alignment == 0 &&
		self.subsystem.is_valid() && 
		self.dll_characteristics.is_valid() &&
		self.loader_flags == 0
	}
}


#[derive(Clone, Debug)]
pub struct OptionalHeader64 {
	pub size: usize,

    pub image_base: ULONGLONG,
    pub section_alignment: DWORD,
    pub file_alignment: DWORD,
    pub major_operating_system_version: WORD,
    pub minor_operating_system_version: WORD,
    pub major_image_version: WORD,
    pub minor_image_version: WORD,
    pub major_subsystem_version: WORD,
    pub minor_subsystem_version: WORD,
    pub win32_version_value: DWORD,
    pub size_of_image: DWORD,
    pub size_of_headers: DWORD,
    pub checksum: DWORD,
    pub subsystem: ImageSubsystem,
    pub dll_characteristics: ImageDllCharacteristics,
    pub size_of_stack_reserve: ULONGLONG,
    pub size_of_stack_commit: ULONGLONG,
    pub size_of_heap_reserve: ULONGLONG,
    pub size_of_heap_commit: ULONGLONG,
    pub loader_flags: DWORD,
    pub number_of_rva_and_sizes: DWORD,
    pub data_directory: DataDirectory,
}
impl_core!(OptionalHeader64: size, size: usize);
impl OptionalHeader64 {
	unsafe fn read_interface(i: &IMAGE_OPTIONAL_HEADER64, size: usize) -> Result<Self, OutOfBoundsError> {
		let i: &IMAGE_OPTIONAL_HEADER64 = transmute(
			offset_ptr(i as *const _, -(CoffHeader::static_size() as isize))
		);

		let data_directory;
		if i.NumberOfRvaAndSizes == 0 {
			data_directory = DataDirectory::default();
		} else {
			data_directory = DataDirectory::read_interface(&i.DataDirectory[0], i.NumberOfRvaAndSizes as usize)?;
		}

		Ok(Self {
			size: size,

			image_base: i.ImageBase,
			section_alignment: i.SectionAlignment,
			file_alignment: i.FileAlignment,
			major_operating_system_version: i.MajorOperatingSystemVersion,
			minor_operating_system_version: i.MinorOperatingSystemVersion,
			major_image_version: i.MajorImageVersion,
			minor_image_version: i.MinorImageVersion,
			major_subsystem_version: i.MajorSubsystemVersion,
			minor_subsystem_version: i.MinorSubsystemVersion,
			win32_version_value: i.Win32VersionValue,
			size_of_image: i.SizeOfImage,
			size_of_headers: i.SizeOfHeaders,
			checksum: i.CheckSum,
			subsystem: ImageSubsystem::parse(i.Subsystem),
			dll_characteristics: ImageDllCharacteristics::parse(i.DllCharacteristics),
			size_of_stack_reserve: i.SizeOfStackReserve,
			size_of_stack_commit: i.SizeOfStackCommit,
			size_of_heap_reserve: i.SizeOfHeapReserve,
			size_of_heap_commit: i.SizeOfHeapCommit,
			loader_flags: i.LoaderFlags,
			number_of_rva_and_sizes: i.NumberOfRvaAndSizes,
			data_directory: data_directory,
		})
	}
	unsafe fn write_interface(&self, i: &mut IMAGE_OPTIONAL_HEADER64) {
		let i: &mut IMAGE_OPTIONAL_HEADER64 = transmute(
			offset_ptr_mut(i as *mut _, -(CoffHeader::static_size() as isize))
		);

		i.ImageBase = self.image_base;
		i.SectionAlignment = self.section_alignment;
		i.FileAlignment = self.file_alignment;
		i.MajorOperatingSystemVersion = self.major_operating_system_version;
		i.MinorOperatingSystemVersion = self.minor_operating_system_version;
		i.MajorImageVersion = self.major_image_version;
		i.MinorImageVersion = self.minor_image_version;
		i.MajorSubsystemVersion = self.major_subsystem_version;
		i.MinorSubsystemVersion = self.minor_subsystem_version;
		i.Win32VersionValue = self.win32_version_value;
		i.SizeOfImage = self.size_of_image;
		i.SizeOfHeaders = self.size_of_headers;
		i.CheckSum = self.checksum;
		i.Subsystem = self.subsystem.value();
		i.DllCharacteristics = self.dll_characteristics.value();
		i.SizeOfStackReserve = self.size_of_stack_reserve;		
		i.SizeOfStackCommit = self.size_of_stack_commit;
		i.SizeOfHeapReserve = self.size_of_heap_reserve;
		i.SizeOfHeapCommit = self.size_of_heap_commit;
		i.LoaderFlags = self.loader_flags;
		i.NumberOfRvaAndSizes = self.number_of_rva_and_sizes;
		self.data_directory.write_interface(transmute(&mut i.DataDirectory));
	}


	pub fn static_size() -> usize {
		size_of::<IMAGE_OPTIONAL_HEADER64>() - CoffHeader::static_size()
	}
	pub fn get_size(&self) -> usize {
		self.size
	}
	pub fn is_valid(&self) -> bool {
		self.section_alignment >= self.file_alignment &&
		self.file_alignment >= 512 && self.file_alignment <= 65536 &&
		(self.file_alignment & (self.file_alignment - 1)) == 0 &&
		self.win32_version_value == 0 &&
		self.size_of_image % self.section_alignment == 0 &&
		self.size_of_headers % self.file_alignment == 0 &&
		self.subsystem.is_valid() && 
		self.dll_characteristics.is_valid() &&
		self.loader_flags == 0
	}
}

bitfield!{
	pub enum ImageSubsystem : WORD {
		Native: IMAGE_SUBSYSTEM_NATIVE,
		WindowsGui: IMAGE_SUBSYSTEM_WINDOWS_GUI,
		WindowsCui: IMAGE_SUBSYSTEM_WINDOWS_CUI,
		Os2Cui: IMAGE_SUBSYSTEM_OS2_CUI,
		PosixCui: IMAGE_SUBSYSTEM_POSIX_CUI,
		NativeWindows: IMAGE_SUBSYSTEM_NATIVE_WINDOWS,
		WindowsCeGui: IMAGE_SUBSYSTEM_WINDOWS_CE_GUI,
		EfiApplication: IMAGE_SUBSYSTEM_EFI_APPLICATION,
		EfiServiceDriver: IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER,
		EfiRuntimeDriver: IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER,
		EfiRom: IMAGE_SUBSYSTEM_EFI_ROM,
		Xbox: IMAGE_SUBSYSTEM_XBOX,
		Boot: IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION,
		XboxCatalog: IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG
	}
}
bitfield!{
	pub struct ImageDllCharacteristics : WORD {
		high_entropy_va: IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA,
		dynamic_base: IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
		force_integrity: IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY,
		nx_compat: IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
		no_isolation: IMAGE_DLLCHARACTERISTICS_NO_ISOLATION,
		no_seh: IMAGE_DLLCHARACTERISTICS_NO_SEH,
		no_bind: IMAGE_DLLCHARACTERISTICS_NO_BIND,
		app_cointainer: IMAGE_DLLCHARACTERISTICS_APPCONTAINER,
		wdm_driver: IMAGE_DLLCHARACTERISTICS_WDM_DRIVER,
		guard_cf: IMAGE_DLLCHARACTERISTICS_GUARD_CF,
		terminal_server_aware: IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE
	}
}




#[derive(Clone, Debug, Default)]
pub struct DataDirectoryEntry {
	pub virtual_address: DWORD,
	pub size: DWORD,
}
impl_core!(DataDirectoryEntry);
impl DataDirectoryEntry {
	pub(crate) unsafe fn read_interface(i: &IMAGE_DATA_DIRECTORY) -> Result<Self, OutOfBoundsError> {
		Ok(Self {
			virtual_address: i.VirtualAddress,
			size: i.Size,
		})
	}
	pub(crate) unsafe fn write_interface(&self, i: &mut IMAGE_DATA_DIRECTORY) {
		i.Size = self.size;
		i.VirtualAddress = self.virtual_address;
	}


	pub fn static_size() -> usize {
		size_of::<IMAGE_DATA_DIRECTORY>()
	}
}

#[derive(Clone, Debug, Default)]
pub struct DataDirectory {
	//pub entries: [DataDirectoryEntry; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
	pub count: usize,

	pub export_table: Option<DataDirectoryEntry>,
	pub import_table: Option<DataDirectoryEntry>,
	pub resource_table: Option<DataDirectoryEntry>,
	pub exception_table: Option<DataDirectoryEntry>,
	pub certificate_table: Option<DataDirectoryEntry>,
	pub base_relocation_table: Option<DataDirectoryEntry>,
	pub debug: Option<DataDirectoryEntry>,
	pub architecture: Option<DataDirectoryEntry>,
	pub global_ptr: Option<DataDirectoryEntry>,
	pub tls_table: Option<DataDirectoryEntry>,
	pub load_config_table: Option<DataDirectoryEntry>,
	pub bound_import: Option<DataDirectoryEntry>,
	pub iat: Option<DataDirectoryEntry>,
	pub delay_import_descriptor: Option<DataDirectoryEntry>,
	pub clr_runtime_header: Option<DataDirectoryEntry>,
	pub reserved: Option<DataDirectoryEntry>,
}
impl_core!(DataDirectory: DataDirectoryEntry::static_size() * count, count: usize);
impl DataDirectory {
	pub(crate) unsafe fn read_interface(i: &IMAGE_DATA_DIRECTORY, count: usize) -> Result<Self, OutOfBoundsError> {
		let mut result = Self {
			count: count,
			.. Self::default()
		};
		
		for index in 0..count {
			let next: IMAGE_DATA_DIRECTORY = *offset_ptr(i as *const _, (index * size_of::<IMAGE_DATA_DIRECTORY>()) as isize);
			match result.get_mut(index) {
				Some(entry) => {
					*entry = Some(DataDirectoryEntry::read_interface(&next)?);
				}
				None => return Err(OutOfBoundsError {}),
			}
		}

		Ok(result)
	}
	pub(crate) unsafe fn write_interface(&self, i: &mut IMAGE_DATA_DIRECTORY) {
		for index in 0..self.count {
			match self.get(index) {
				Some(entry) => {
					entry.write_interface(transmute(offset_ptr_mut(i as *mut _, (index * size_of::<IMAGE_DATA_DIRECTORY>()) as isize)));
				}
				None => continue,
			}
		}
	}

	pub fn get(&self, index: usize) -> Option<&DataDirectoryEntry> {
		match index as u16 {
			IMAGE_DIRECTORY_ENTRY_EXPORT 			=> self.export_table.as_ref(),
			IMAGE_DIRECTORY_ENTRY_IMPORT 			=> self.import_table.as_ref(),
			IMAGE_DIRECTORY_ENTRY_RESOURCE 			=> self.resource_table.as_ref(),
			IMAGE_DIRECTORY_ENTRY_EXCEPTION 		=> self.exception_table.as_ref(),
			IMAGE_DIRECTORY_ENTRY_SECURITY 			=> self.certificate_table.as_ref(),
			IMAGE_DIRECTORY_ENTRY_BASERELOC 		=> self.base_relocation_table.as_ref(),
			IMAGE_DIRECTORY_ENTRY_DEBUG 			=> self.debug.as_ref(),
			IMAGE_DIRECTORY_ENTRY_ARCHITECTURE 		=> self.architecture.as_ref(),
			IMAGE_DIRECTORY_ENTRY_GLOBALPTR 		=> self.global_ptr.as_ref(),
			IMAGE_DIRECTORY_ENTRY_TLS 				=> self.tls_table.as_ref(),
			IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG 		=> self.load_config_table.as_ref(),
			IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT 		=> self.bound_import.as_ref(),
			IMAGE_DIRECTORY_ENTRY_IAT 				=> self.iat.as_ref(),
			IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT 		=> self.delay_import_descriptor.as_ref(),
			IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR	=> self.clr_runtime_header.as_ref(),
			15	=> self.reserved.as_ref(),
			_ => None,
		}
	}
	pub fn get_mut(&mut self, index: usize) -> Option<&mut Option<DataDirectoryEntry>> {
		match index as u16 {
			IMAGE_DIRECTORY_ENTRY_EXPORT 			=> Some(&mut self.export_table),
			IMAGE_DIRECTORY_ENTRY_IMPORT 			=> Some(&mut self.import_table),
			IMAGE_DIRECTORY_ENTRY_RESOURCE 			=> Some(&mut self.resource_table),
			IMAGE_DIRECTORY_ENTRY_EXCEPTION 		=> Some(&mut self.exception_table),
			IMAGE_DIRECTORY_ENTRY_SECURITY 			=> Some(&mut self.certificate_table),
			IMAGE_DIRECTORY_ENTRY_BASERELOC 		=> Some(&mut self.base_relocation_table),
			IMAGE_DIRECTORY_ENTRY_DEBUG 			=> Some(&mut self.debug),
			IMAGE_DIRECTORY_ENTRY_ARCHITECTURE 		=> Some(&mut self.architecture),
			IMAGE_DIRECTORY_ENTRY_GLOBALPTR 		=> Some(&mut self.global_ptr),
			IMAGE_DIRECTORY_ENTRY_TLS 				=> Some(&mut self.tls_table),
			IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG 		=> Some(&mut self.load_config_table),
			IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT 		=> Some(&mut self.bound_import),
			IMAGE_DIRECTORY_ENTRY_IAT 				=> Some(&mut self.iat),
			IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT 		=> Some(&mut self.delay_import_descriptor),
			IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR	=> Some(&mut self.clr_runtime_header),
			15	=> Some(&mut self.reserved),
			_ => None,
		}
	}

	pub fn static_size() -> usize {
		DataDirectoryEntry::static_size() * IMAGE_NUMBEROF_DIRECTORY_ENTRIES
	}
	pub fn get_size(&self) -> usize {
		DataDirectoryEntry::static_size() * self.count
	}
	pub fn is_valid(&self) -> bool {
		self.architecture.is_none() && 
		self.reserved.is_none() && 
		match &self.global_ptr {
			Some(entry) => entry.size == 0,
			None => true,
		}
	}
}




#[derive(Clone, Debug, Default)]
pub struct SectionTableEntry {
	pub name: [BYTE; IMAGE_SIZEOF_SHORT_NAME],
	pub virtual_size: DWORD,
	pub virtual_address: DWORD,
	pub size_of_raw_data: DWORD,
	pub pointer_to_raw_data: DWORD,
	pub pointer_to_relocations: DWORD,
	pub pointer_to_linenumbers: DWORD,
	pub number_of_relocations: WORD,
	pub number_of_linenumbers: WORD,
	pub characteristics: SectionCharacteristics,
}
impl_core!(SectionTableEntry);
impl SectionTableEntry {
	pub(crate) unsafe fn read_interface(i: &IMAGE_SECTION_HEADER) -> Result<Self, OutOfBoundsError> {
		Ok(Self {
			name: i.Name,
			virtual_size: *i.Misc.VirtualSize(),
			virtual_address: i.VirtualAddress,
			size_of_raw_data: i.SizeOfRawData,
			pointer_to_raw_data: i.PointerToRawData,
			pointer_to_relocations: i.PointerToRelocations,
			pointer_to_linenumbers: i.PointerToLinenumbers,
			number_of_relocations: i.NumberOfRelocations,
			number_of_linenumbers: i.NumberOfLinenumbers,
			characteristics: SectionCharacteristics::parse(i.Characteristics),
		})
	}
	pub(crate) unsafe fn write_interface(&self, i: &mut IMAGE_SECTION_HEADER) {
		i.Name = self.name;
		*i.Misc.VirtualSize_mut() = self.virtual_size;
		i.VirtualAddress = self.virtual_address;
		i.SizeOfRawData = self.size_of_raw_data;
		i.PointerToRawData = self.pointer_to_raw_data;
		i.PointerToRelocations = self.pointer_to_relocations;
		i.PointerToLinenumbers = self.pointer_to_linenumbers;
		i.NumberOfRelocations = self.number_of_relocations;
		i.NumberOfLinenumbers = self.number_of_linenumbers;
		i.Characteristics = self.characteristics.value();
	}

	pub fn static_size() -> usize {
		size_of::<IMAGE_SECTION_HEADER>()
	}
	pub fn is_valid(&self, file_alignment: DWORD) -> bool {
		self.size_of_raw_data % file_alignment == 0 &&
		self.pointer_to_raw_data % file_alignment == 0 &&
		self.pointer_to_linenumbers == 0 &&
		self.number_of_linenumbers == 0 && 
		self.characteristics.is_valid()
	}

	pub fn string_name(&self) -> String {
		String::from_utf8(self.name.to_vec()).unwrap_or("".to_string())
	}
}


#[derive(Clone, Debug, Default)]
pub struct SectionTable {
	pub entries: Vec<SectionTableEntry>,
}
impl_core!(SectionTable : SectionTableEntry::static_size() * count, count: usize);
impl SectionTable {
	pub(crate) unsafe fn read_interface(i: &IMAGE_SECTION_HEADER, count: usize) -> Result<Self, OutOfBoundsError> {
		let mut entries = vec!();
		for index in 0..count {
			let next: IMAGE_SECTION_HEADER = *offset_ptr(i as *const _, (index * size_of::<IMAGE_SECTION_HEADER>()) as isize);
			entries.push(SectionTableEntry::read_interface(&next)?);
		}
		Ok(Self {
			entries: entries,
		})
	}
	pub(crate) unsafe fn write_interface(&self, i: &mut IMAGE_DATA_DIRECTORY) {
		for index in 0..self.entries.len() {
			match self.entries.get(index) {
				Some(entry) => entry.write_interface(transmute(offset_ptr_mut(i as *mut _, (index * size_of::<IMAGE_SECTION_HEADER>()) as isize))),
				None => continue,
			}
		}
	}

	pub fn get_size(&self) -> usize {
		SectionTableEntry::static_size() * self.entries.len()
	}
	pub fn is_valid(&self, file_alignment: DWORD) -> bool {
		for entry in &self.entries {
			if !entry.is_valid(file_alignment) {
				return false;
			}
		}
		true
	}
}

bitfield!{
	pub struct SectionCharacteristics : DWORD {
		cnt_code: IMAGE_SCN_CNT_CODE,
		cnt_initialized_data: IMAGE_SCN_CNT_INITIALIZED_DATA,
		cnt_uninitialized_data: IMAGE_SCN_CNT_UNINITIALIZED_DATA,
		lnk_info: IMAGE_SCN_LNK_INFO,
		lnk_remove: IMAGE_SCN_LNK_REMOVE,
		lnk_comdat: IMAGE_SCN_LNK_COMDAT,
		no_defer_spec_exc: IMAGE_SCN_NO_DEFER_SPEC_EXC,
		gprel: IMAGE_SCN_GPREL,
		mem_fardata: IMAGE_SCN_MEM_FARDATA,
		mem_purgeable: IMAGE_SCN_MEM_PURGEABLE,
		mem_16bit: IMAGE_SCN_MEM_16BIT,
		mem_locked: IMAGE_SCN_MEM_LOCKED,
		mem_preload: IMAGE_SCN_MEM_PRELOAD,
		align_1bytes: IMAGE_SCN_ALIGN_1BYTES,
		align_2bytes: IMAGE_SCN_ALIGN_2BYTES,
		align_4bytes: IMAGE_SCN_ALIGN_4BYTES,
		align_8bytes: IMAGE_SCN_ALIGN_8BYTES,
		align_16bytes: IMAGE_SCN_ALIGN_16BYTES,
		align_32bytes: IMAGE_SCN_ALIGN_32BYTES,
		align_64bytes: IMAGE_SCN_ALIGN_64BYTES,
		align_128bytes: IMAGE_SCN_ALIGN_128BYTES,
		align_256bytes: IMAGE_SCN_ALIGN_256BYTES,
		align_512bytes: IMAGE_SCN_ALIGN_512BYTES,
		align_1024bytes: IMAGE_SCN_ALIGN_1024BYTES,
		align_2048bytes: IMAGE_SCN_ALIGN_2048BYTES,
		align_4096bytes: IMAGE_SCN_ALIGN_4096BYTES,
		align_8192bytes: IMAGE_SCN_ALIGN_8192BYTES,
		align_mask: IMAGE_SCN_ALIGN_MASK,
		lnk_nreloc_ovfl: IMAGE_SCN_LNK_NRELOC_OVFL,
		mem_discardable: IMAGE_SCN_MEM_DISCARDABLE,
		mem_not_cached: IMAGE_SCN_MEM_NOT_CACHED,
		mem_not_paged: IMAGE_SCN_MEM_NOT_PAGED,
		mem_shared: IMAGE_SCN_MEM_SHARED,
		mem_execute: IMAGE_SCN_MEM_EXECUTE,
		mem_read: IMAGE_SCN_MEM_READ,
		mem_write: IMAGE_SCN_MEM_WRITE
	}
}








#[derive(Clone, Debug)]
pub struct PeHeaders {
	pub dos_header: DosHeader,
	pub rich_header: Option<RichHeader>,
	pub signature: DWORD,
	pub file_header: FileHeader,
	pub coff_header: CoffHeader,
	pub optional_header: OptionalHeader,
	pub section_table: SectionTable,
}
impl_core_vec!(PeHeaders);
impl PeHeaders {
	pub unsafe fn read_buffer<T>(data: *const T, length: Option<usize>, mut offset: usize) -> Result<Self, OutOfBoundsError> {
		let data = data as *const u8;
		
		let dos = DosHeader::read_buffer(data, length, offset)?;
		offset += dos.e_lfanew as usize + size_of::<DWORD>();
		
		let file = FileHeader::read_buffer(data, length, offset)?;
		let signature = *offset_ptr(data as *const DWORD, (offset - size_of::<DWORD>()) as isize);
		let rich = RichHeader::read_buffer(data, dos.get_size() + dos.stub.size, offset)?;
		offset += file.get_size();
		
		let coff = CoffHeader::read_buffer(data, length, offset)?;
		offset += coff.get_size();

		let optional = OptionalHeader::read_buffer(data, length, offset, file.size_of_optional_header as usize - coff.get_size(), coff.magic)?;
		offset += optional.get_size() as usize;

		let section = SectionTable::read_buffer(data, length, offset, file.number_of_sections as usize)?;

		Ok(Self {
			dos_header: dos,
			rich_header: rich,
			signature: signature,
			file_header: file,
			coff_header: coff,
			optional_header: optional,
			section_table: section,
		})
	}
	pub unsafe fn write_buffer<T>(&self, data: *mut T, length: Option<usize>, mut offset: usize) -> Result<(), OutOfBoundsError> {
		let data = data as *mut u8;
		
		self.dos_header.write_buffer(data, length, offset)?;
		offset += self.dos_header.e_lfanew as usize + size_of::<DWORD>();
		
		self.file_header.write_buffer(data, length, offset)?;
		*offset_ptr_mut(data as *mut DWORD, (offset - size_of::<DWORD>()) as isize) = self.signature;
		//self.rich_header.write_buffer(data, dos.get_size() + dos.stub.size, offset)?;
		offset += self.file_header.get_size();
		
		self.coff_header.write_buffer(data, length, offset)?;
		offset += self.coff_header.get_size();

		self.optional_header.write_buffer(data, length, offset)?;
		offset += self.optional_header.get_size();

		self.section_table.write_buffer(data, length, offset)?;
		
		Ok(())
	}

	pub fn get_size(&self) -> usize {
		self.dos_header.e_lfanew as usize + 
		size_of::<DWORD>() +
		self.file_header.get_size() + 
		self.optional_header.get_size() + 
		self.section_table.get_size()
	}
}
