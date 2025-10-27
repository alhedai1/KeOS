//! ## ELF Loading.
//!
//! When you run a program on a modern operating system, the kernel needs to
//! know **how to take the program stored on disk and place it into memory so it
//! can start running**. The file format that describes this mapping is called
//! **ELF (Executable and Linkable Format)**.
//!
//! ![ELF](<https://raw.githubusercontent.com/casys-kaist/KeOS/79a689838dc34de607bb8d1beb89aa5535cd4af2/images/image.png>)
//!
//! Think of ELF as a "blueprint" for a program’s memory layout. It tells the
//! kernel where each part of the program (code, data, uninitialized variables)
//! should go in memory, what permissions they need (read, write, execute), and
//! where the program should begin execution.
//!
//! An ELF file contains:
//! - **ELF header** – a small table of contents that points to the rest of the
//!   file and gives the program’s entry point (where execution starts).
//! - **Program headers** – a list of **segments**, each describing a chunk of
//!   the file that should be loaded into memory.
//!
//! In KeOS, we only care about the **program headers**, because they tell us
//! how to build the process’s memory image. Each program header (`Phdr`) says:
//! - **Virtual address** ([`Phdr::p_vaddr`]) – Where in memory they should go.
//! - **Memory size** ([`Phdr::p_memsz`]) – How big the memory region should be
//!   in total.
//! - **File size** ([`Phdr::p_filesz`]) – How many bytes come from the file.
//! - **File offset** ([`Phdr::p_offset`]) - Where in the file the bytes are
//!   stored.
//! - **Permissions** ([`Phdr::p_flags`]) – What permissions the region needs.
//!
//! You can iterate through the [`Phdr`]s with [`Elf::phdrs()`], which returns
//! an iterator over [`Phdr`] entries. The most important type of header is
//! [`PType::Load`], meaning “this segment must be loaded into memory.” To load
//! it, KeOS does the following:
//! 1. Allocate memory at the given virtual address using [`MmStruct::do_mmap`].
//! 2. Copy `filesz` bytes from the ELF file (starting at `p_offset`) into that
//!    memory.
//! 3. If `memsz > filesz`, fill the extra space with zeros — this is how ELF
//!    represents the **`.bss` section**, which holds uninitialized global
//!    variables.
//!
//! By repeating this for every loadable segment, the kernel reconstructs the
//! program’s expected memory image: code in `.text`, constants in `.rodata`,
//! variables in `.data`, and zero-initialized memory in `.bss`. When this is
//! done, the program’s virtual memory matches exactly what the compiler and
//! linker prepared, and the kernel can safely jump to the entry point to start
//! execution.
//!
//! There are some pitfalls while loding a ELF:
//!  - `p_vaddr` must be page-aligned. If not, round it down and adjust offsets
//!    accordingly.
//!  - Ensure segments do not overwrite existing mappings like the stack or
//!    kernel memory.
//!
//! ## State on Program Startup
//!
//! The KeOS user-space C library (`kelibc`) defines `_start()`, located in
//! `kelibc/entry.c`, as the program entry point. It calls `main()` and
//! exits when `main()` returns. The kernel must set up the registers and user
//! program's stack correctly before execution, passing arguments according to
//! the standard calling convention. [`Registers`] contains the CPU states on
//! launching a program, including instruction pointer, stack pointer, and
//! general-purpose registers.
//
//!
//! **Example command:** `/bin/ls -l foo bar`
//!
//! 1. Split the command into words: `"/bin/ls"`, `"-l"`, `"foo"`, `"bar"`.
//! 2. Copy the argument strings to the top of the stack (order does not
//!    matter).
//! 3. Push their addresses, followed by a null sentinel (`argv[argc] = NULL`).
//!    - Align the stack pointer to an 8-byte boundary for performance.
//! 4. Set `%rdi = argc` (argument count) and `%rsi = argv` (argument array).
//! 5. Push a fake return address to maintain stack integrity.
//!
//! **Example stack layout before execution:**
//!
//! | Address    | Name           | Data       | Type        |
//! | ---------- | -------------- | ---------- | ----------- |
//! | 0x4747fffc | argv\[3\]\[...\]   | 'bar\0'    | char\[4\]     |
//! | 0x4747fff8 | argv\[2\]\[...\]   | 'foo\0'    | char\[4\]     |
//! | 0x4747fff5 | argv\[1\]\[...\]   | '-l\0'     | char\[3\]     |
//! | 0x4747ffed | argv\[0\]\[...\]   | '/bin/ls\0'| char\[8\]     |
//! | 0x4747ffe8 | word-align     | 0          | uint8_t\[\]   |
//! | 0x4747ffe0 | argv\[4\]        | 0          | char *      |
//! | 0x4747ffd8 | argv\[3\]        | 0x4747fffc | char *      |
//! | 0x4747ffd0 | argv\[2\]        | 0x4747fff8 | char *      |
//! | 0x4747ffc8 | argv\[1\]        | 0x4747fff5 | char *      |
//! | 0x4747ffc0 | argv\[0\]        | 0x4747ffed | char *      |
//! | 0x4747ffb8 | return address | 0          | void (*) () |
//!
//! The stack pointer (`rsp`) is initialized to `0x4747ffb8`. The first two
//! arguments, `%rdi` and `%rsi`, should be `4` and `0x4747ffc0`, respectively.
//! The user program stack always starts at `0x47480000` in KeOS, and always
//! grows downward.
//!
//! [`StackBuilder`] is a utility for constructing user-space stacks. It
//! provides:
//!
//! - [`StackBuilder::push_usize`] – Pushes a `usize` value (e.g., pointers like
//!   `argv[]`).
//! - [`StackBuilder::push_str`] – Pushes a null-terminated string and returns
//!   its address.
//! - [`StackBuilder::align`] – Aligns the stack pointer for proper memory
//!   access.
//!
//! You can use these methods to set up the stack in
//! [`LoadContext::build_stack`].
//!
//! #### Launching a Process
//!
//! After loading the program in memory and setting up the stack, the kernel
//! switches to user mode and begin execution. This is done using
//! [`Registers::launch`]. Calling [`Registers::launch`] causes the CPU to
//! change the privilege level to user mode and start executing from `rip`. You
//! don't need to implement this functionality as it is already implemented in
//! the outside of this module.
//!
//! ## Implementation Requirements
//! You need to implement the followings:
//! - [`Phdr::permission`]
//! - [`StackBuilder::push_bytes`]
//! - [`LoadContext::load_phdr`]
//! - [`LoadContext::build_stack`]
//!
//! This ends the project 2.
//!
//! [`Registers::launch`]: ../../keos/syscall/struct.Registers.html#method.launch

#[allow(dead_code)]
pub mod elf;
pub mod stack_builder;

use crate::{mm_struct::MmStruct, page_table::PageTable, pager::Pager};
use alloc::vec::Vec;
#[cfg(doc)]
use elf::Phdr;
use elf::{Elf, PType};
#[cfg(doc)]
use keos::mm::page_table::Permission;
use keos::{
    addressing::{Va, PAGE_MASK}, fs::RegularFile, mm::{page_table, Page}, syscall::Registers, KernelError
};
use stack_builder::StackBuilder;

// Helpers
fn align_up(x: usize, align: usize) -> usize {
    (x + align - 1) & !(align - 1)
}

fn align_down(x: usize, align: usize) -> usize {
    x & !(align - 1)
}

/// A context that holds the necessary state for loading and initializing a user
/// program.
///
/// `LoadContext` is used during the loading an ELF binary into memory. It
/// encapsulates both the memory layout for the program and its initial register
/// state, allowing the loader to fully prepare the user-space
/// execution context.
pub struct LoadContext<P: Pager> {
    /// Virtual memory layout for the new user program.
    pub mm_struct: MmStruct<P>,
    /// Initial CPU register values for the user process, including the
    /// instruction pointer.
    pub regs: Registers,
}

impl<P: Pager> LoadContext<P> {
    /// Loads program headers ([`Phdr`]s) from an ELF binary into memory.
    ///
    /// This function iterates over the ELF program headers and maps the
    /// corresponding segments into the process's memory space. It ensures
    /// that each segment is correctly mapped according to its permissions
    /// and alignment requirements.
    ///
    /// # Parameters
    /// - `elf`: The ELF binary representation containing program headers.
    ///
    /// # Returns
    /// - `Ok(())` on success, indicating that all segments were successfully
    ///   loaded.
    /// - `Err(KernelError)` if any error occurs during the loading process,
    ///   such as an invalid memory mapping, insufficient memory, or an
    ///   unsupported segment type.
    ///
    /// # Behavior
    /// - Iterates over all program headers using [`Elf::phdrs`].
    /// - Maps each segment into memory if its type is [`PType::Load`].
    /// - Applies appropriate memory permissions using [`Phdr::permission`].
    /// - Ensures proper alignment and memory allocation before mapping.
    pub fn load_phdr(&mut self, elf: Elf) -> Result<(), KernelError> {
        for phdr in elf.phdrs().map_err(|_| KernelError::InvalidArgument)? {
            if phdr.type_ == PType::Load {
                let (vaddr, memsz, filesz, fileofs, perm): (Va, _, _, _, _) = (
                    Va::new(phdr.p_vaddr as usize).unwrap(),
                    phdr.p_memsz as usize,
                    phdr.p_filesz as usize,
                    phdr.p_offset as usize,
                    phdr.permission(),
                );

                // 1. ERROR CHECKS
                if memsz < filesz {
                    return Err(KernelError::InvalidArgument);
                }

                let mut tmp = vaddr;
                while tmp.into_usize() < (vaddr.into_usize() + (memsz as usize)) {
                    if let Ok(pte) = self.mm_struct.page_table.walk(tmp) {
                        if pte.flags().contains(page_table::PteFlags::P) {
                            return Err(KernelError::InvalidArgument);
                        }
                    }
                    tmp = Va::new(tmp.into_usize() + 0x1000)
                        .ok_or(KernelError::InvalidArgument)?;
                }

                // 2. MAP FILE-BACKED PAGES
                let page_offset = vaddr.into_usize() & 0xFFF;
                let aligned_vaddr = Va::new(vaddr.into_usize() - page_offset).unwrap();
                let aligned_fileofs = fileofs - page_offset;

                let file_end = vaddr.into_usize() + filesz;
                let aligned_file_end = align_up(file_end, 0x1000);

                let map_filesz = aligned_file_end - aligned_vaddr.into_usize();
                if map_filesz > 0 {
                    self.mm_struct.do_mmap(
                        aligned_vaddr,
                        map_filesz,
                        perm,
                        Some(elf.file),
                        aligned_fileofs,
                    )?;
                }

                // 3. ZERO OUT PARTIAL BSS
                let bss_start_offset_in_page = file_end & 0xFFF;
                if bss_start_offset_in_page != 0 {
                    let va_of_partial_page = Va::new(align_down(file_end, 0x1000)).unwrap();
                    let mem_end_in_page = (vaddr.into_usize() + memsz).min(aligned_file_end);
                    
                    let bss_end_offset_in_page = mem_end_in_page & 0xFFF;
                    let zero_end = if bss_end_offset_in_page == 0 && mem_end_in_page > va_of_partial_page.into_usize() {
                        0x1000 
                    } else { 
                        bss_end_offset_in_page 
                    };

                    if zero_end > bss_start_offset_in_page {
                        self.mm_struct
                            .get_user_page_and(va_of_partial_page, |mut page, _| {
                                page.inner_mut()[bss_start_offset_in_page..zero_end].fill(0);
                            })?;
                    }
                }

                // 4. MAP ANONYMOUS BSS PAGES
                let mem_end_addr = vaddr.into_usize() + memsz;
                let aligned_mem_end = align_up(mem_end_addr, 0x1000);

                if aligned_mem_end > aligned_file_end {
                    let bss_map_size = aligned_mem_end - aligned_file_end;
                    self.mm_struct.do_mmap(
                        Va::new(aligned_file_end).unwrap(),
                        bss_map_size,
                        perm | page_table::Permission::WRITE, // BSS must be writable
                        None,
                        0,
                    )?;
                }
            }
        }
        Ok(())
    }
    
    /// Builds a user stack and initializes it with arguments.
    ///
    /// This function sets up a new stack for the process by allocating memory,
    /// pushing program arguments (`argv`), and preparing the initial register
    /// state.
    ///
    /// # Parameters
    /// - `arguments`: A slice of strs representing the command-line arguments
    ///   (`argv`).
    /// - `regs`: A mutable reference to the register state, which will be
    ///   updated with the initial stack pointer (`sp`) and argument count
    ///   (`argc`).
    ///
    /// # Returns
    /// - `Ok(())` on success, indicating that the stack has been built
    ///   correctly.
    /// - `Err(KernelError)` if an error occurs during memory allocation or
    ///   argument copying.
    ///
    /// # Behavior
    /// - Pushes the argument strings onto the stack.
    /// - Sets up `argv` and `argc` for the process.
    /// - Aligns the stack pointer to ensure proper function call execution.
    ///
    /// # Safety
    /// - The function must be called before transferring control to user space.
    /// - The memory layout should follow the standard calling convention for
    ///   argument passing.
    pub fn build_stack(&mut self, arguments: &[&str]) -> Result<(), KernelError> {
        let Self {
            mm_struct: mm_state,
            regs,
        } = self;
        let mut builder = StackBuilder::new(mm_state)?;

        // Push argument strings and collect their addresses
        // We push in reverse order to match the diagram's addresses
        let mut arg_addrs = Vec::new();
        for &arg in arguments.iter().rev() {
            let addr = builder.push_str(arg);
            arg_addrs.push(addr);
        }
        // `arg_addrs` now has pointers in reverse order: [addr_bar, addr_foo, ...]
        arg_addrs.reverse();
        // `arg_addrs` is now correct: [addr_ls, addr_l, ...]

        // Align stack to 8-byte boundary
        builder.align(8);

        // Push null terminator for argv array (argv[argc] = NULL)
        builder.push_usize(0);

        // Push argv pointers in reverse order (argv[argc-1] first)
        for &addr in arg_addrs.iter().rev() {
            builder.push_usize(addr.into_usize());
        }

        // Save the argv pointer (points to argv[0])
        let argv_ptr = builder.sp().into_usize();

        // Push fake return address
        builder.push_usize(0);

        // Set up registers
        *regs.rsp() = builder.sp().into_usize(); // rsp points to the fake return address
        regs.gprs.rdi = arguments.len(); // rdi = argc
        regs.gprs.rsi = argv_ptr; // rsi = argv

        // DEBUG: Print final registers
        println!("[build_stack] FINAL REGISTERS:"); // DEBUG
        println!("  -> rsp (stack ptr):   0x{:x}", regs.rsp()); // DEBUG
        println!("  -> rdi (argc):        {}", regs.gprs.rdi); // DEBUG
        println!("  -> rsi (argv ptr):  0x{:x}", regs.gprs.rsi); // DEBUG

        Ok(())
    }

    /// Creates a new memory state and initializes a user process from an ELF
    /// executable.
    ///
    /// This function loads an ELF binary into memory, sets up the program
    /// headers, and constructs the initial user stack with arguments. It
    /// also prepares the register state for execution.
    ///
    /// # Parameters
    /// - `file`: A reference to the ELF executable file.
    /// - `args`: A slice of strs representing the command-line arguments
    ///   (`argv`).
    ///
    /// # Returns
    /// - `Ok((Self, Registers))` on success, where:
    ///   - `Self` is the initialized memory state.
    ///   - `Registers` contains the initial register values.
    /// - `Err(KernelError)` if an error occurs while loading the ELF file or
    ///   setting up memory.
    ///
    /// # Behavior
    /// - Parses the ELF file and validates its format.
    /// - Loads program headers ([`PType::Load`]) into memory.
    /// - Allocates and builds the user stack.
    /// - Initializes the register state (`rip` -> entry point, `rsp` -> stack
    ///   pointer, arg1 -> the number of arguments, arg1 -> address of arguments
    ///   vector.).
    pub fn load(mut self, file: &RegularFile, args: &[&str]) -> Result<Self, KernelError> {
        if let Some(elf) = elf::Elf::from_file(file) {
            *self.regs.rip() = elf.header.e_entry as usize;
            self.load_phdr(elf)?;
            self.build_stack(args)?;

            Ok(self)
        } else {
            Err(KernelError::InvalidArgument)
        }
    }
}
