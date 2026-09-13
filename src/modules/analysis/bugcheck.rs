//! BugCheck (stop code) decoding.
//!
//! Two jobs: turn a stop code into its documented name, and — for the codes
//! where Microsoft documents a parameter as holding a code address — say which
//! parameter that is. The second is what makes honest crash attribution
//! possible: instead of scraping any `fffff…` token out of a log message, we
//! read the one parameter that is defined to be an instruction pointer.

/// Documented name for a bugcheck code.
pub fn name(code: u32) -> &'static str {
    match code {
        0x00000001 => "APC_INDEX_MISMATCH",
        0x00000004 => "INVALID_DATA_ACCESS_TRAP",
        0x0000000A => "IRQL_NOT_LESS_OR_EQUAL",
        0x00000012 => "TRAP_CAUSE_UNKNOWN",
        0x00000018 => "REFERENCE_BY_POINTER",
        0x0000001A => "MEMORY_MANAGEMENT",
        0x0000001E => "KMODE_EXCEPTION_NOT_HANDLED",
        0x00000021 => "QUOTA_UNDERFLOW",
        0x00000024 => "NTFS_FILE_SYSTEM",
        0x0000002B => "PANIC_STACK_SWITCH",
        0x0000002E => "DATA_BUS_ERROR",
        0x00000031 => "PHASE0_INITIALIZATION_FAILED",
        0x00000032 => "PHASE1_INITIALIZATION_FAILED",
        0x00000035 => "NO_MORE_IRP_STACK_LOCATIONS",
        0x00000037 => "FLOPPY_INTERNAL_ERROR",
        0x0000003B => "SYSTEM_SERVICE_EXCEPTION",
        0x0000003D => "INTERRUPT_EXCEPTION_NOT_HANDLED",
        0x0000003F => "NO_MORE_SYSTEM_PTES",
        0x00000041 => "MUST_SUCCEED_POOL_EMPTY",
        0x00000044 => "MULTIPLE_IRP_COMPLETE_REQUESTS",
        0x00000050 => "PAGE_FAULT_IN_NONPAGED_AREA",
        0x00000051 => "REGISTRY_ERROR",
        0x00000058 => "FTDISK_INTERNAL_ERROR",
        0x0000005C => "HAL_INITIALIZATION_FAILED",
        0x0000007A => "KERNEL_DATA_INPAGE_ERROR",
        0x0000007B => "INACCESSIBLE_BOOT_DEVICE",
        0x0000007E => "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
        0x0000007F => "UNEXPECTED_KERNEL_MODE_TRAP",
        0x00000080 => "NMI_HARDWARE_FAILURE",
        0x0000008E => "KERNEL_MODE_EXCEPTION_NOT_HANDLED",
        0x0000009C => "MACHINE_CHECK_EXCEPTION",
        0x0000009E => "USER_MODE_HEALTH_MONITOR",
        0x0000009F => "DRIVER_POWER_STATE_FAILURE",
        0x000000A0 => "INTERNAL_POWER_ERROR",
        0x000000A5 => "ACPI_BIOS_ERROR",
        0x000000BE => "ATTEMPTED_WRITE_TO_READONLY_MEMORY",
        0x000000C1 => "SPECIAL_POOL_DETECTED_MEMORY_CORRUPTION",
        0x000000C2 => "BAD_POOL_CALLER",
        0x000000C4 => "DRIVER_VERIFIER_DETECTED_VIOLATION",
        0x000000C5 => "DRIVER_CORRUPTED_EXPOOL",
        0x000000C7 => "TIMER_OR_DPC_INVALID",
        0x000000C9 => "DRIVER_VERIFIER_IOMANAGER_VIOLATION",
        0x000000CA => "PNP_DETECTED_FATAL_ERROR",
        0x000000CE => "DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS",
        0x000000D1 => "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
        0x000000D5 => "DRIVER_PAGE_FAULT_IN_FREED_SPECIAL_POOL",
        0x000000D6 => "DRIVER_PAGE_FAULT_BEYOND_END_OF_ALLOCATION",
        0x000000DA => "SYSTEM_PTE_MISUSE",
        0x000000DE => "POOL_CORRUPTION_IN_FILE_AREA",
        0x000000E2 => "MANUALLY_INITIATED_CRASH",
        0x000000E3 => "RESOURCE_NOT_OWNED",
        0x000000E4 => "WORKER_INVALID",
        0x000000EA => "THREAD_STUCK_IN_DEVICE_DRIVER",
        0x000000EF => "CRITICAL_PROCESS_DIED",
        0x000000F4 => "CRITICAL_OBJECT_TERMINATION",
        0x000000F5 => "FLTMGR_FILE_SYSTEM",
        0x000000F7 => "DRIVER_OVERRAN_STACK_BUFFER",
        0x000000FC => "ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY",
        0x000000FE => "BUGCODE_USB_DRIVER",
        0x00000101 => "CLOCK_WATCHDOG_TIMEOUT",
        0x00000109 => "CRITICAL_STRUCTURE_CORRUPTION",
        0x0000010D => "WDF_VIOLATION",
        0x0000010E => "VIDEO_MEMORY_MANAGEMENT_INTERNAL",
        0x00000113 => "VIDEO_DXGKRNL_FATAL_ERROR",
        0x00000116 => "VIDEO_TDR_FAILURE",
        0x00000117 => "VIDEO_TDR_TIMEOUT_DETECTED",
        0x00000119 => "VIDEO_SCHEDULER_INTERNAL_ERROR",
        0x0000011B => "DRIVER_RETURNED_HOLDING_CANCEL_LOCK",
        0x0000011C => "ATTEMPTED_WRITE_TO_CM_PROTECTED_STORAGE",
        0x00000124 => "WHEA_UNCORRECTABLE_ERROR",
        0x00000133 => "DPC_WATCHDOG_VIOLATION",
        0x00000139 => "KERNEL_SECURITY_CHECK_FAILURE",
        0x0000013A => "KERNEL_MODE_HEAP_CORRUPTION",
        0x00000141 => "VIDEO_ENGINE_TIMEOUT_DETECTED",
        0x00000144 => "BUGCODE_USB3_DRIVER",
        0x00000149 => "REFS_FILE_SYSTEM",
        0x00000154 => "UNEXPECTED_STORE_EXCEPTION",
        0x00000155 => "SYSTEM_MEMORY_STATE_INVALID",
        0x00000159 => "SOCKET_NO_LONGER_AVAILABLE",
        0x00000161 => "LIVE_SYSTEM_DUMP",
        0x00000162 => "KERNEL_AUTO_BOOST_INVALID_LOCK_RELEASE",
        0x00000163 => "SESSION_HAS_INVALID_POOL_MONITORS",
        0x00000164 => "PROCESS_ATTACH_NOT_CALLED",
        0x0000018B => "SECURE_KERNEL_ERROR",
        0x00000192 => "KERNEL_AUTO_BOOST_LOCK_ACQUISITION_WITH_RAISED_IRQL",
        0x0000019C => "WIN32K_POWER_WATCHDOG_TIMEOUT",
        0x000001A1 => "WIN32K_POWER_WATCHDOG_TIMEOUT",
        0x000001C8 => "ASSERTION_FAILURE",
        0x000001CA => "SYNTHETIC_WATCHDOG_TIMEOUT",
        0x000001D5 => "DRIVER_PNP_WATCHDOG",
        0x000001E4 => "VIDEO_DXGKRNL_SYSMM_FATAL_ERROR",
        0x1000007E => "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_M",
        0x1000008E => "KERNEL_MODE_EXCEPTION_NOT_HANDLED_M",
        0xC0000218 => "STATUS_CANNOT_LOAD_REGISTRY_FILE",
        0xC000021A => "STATUS_SYSTEM_PROCESS_TERMINATED",
        0xDEADDEAD => "MANUALLY_INITIATED_CRASH1",
        _ => "UNKNOWN_BUGCHECK",
    }
}

/// Which of the four bugcheck parameters holds a code address, for the codes
/// where Microsoft documents one.
///
/// Deliberately conservative: only codes whose parameter meaning is documented
/// and unambiguous are listed. Everything else returns `None`, and the crash is
/// reported as unattributed rather than guessed at.
pub fn culprit_parameter_index(code: u32) -> Option<usize> {
    match code {
        // Parameter 4: address that referenced the bad memory.
        0x0000000A | 0x000000D1 => Some(3),
        // Parameter 2: address where the exception occurred.
        // 0x3B's third parameter is a context record, NOT an instruction.
        // https://learn.microsoft.com/windows-hardware/drivers/debugger/bug-check-0x3b--system-service-exception
        0x0000001E | 0x0000003B | 0x0000007E | 0x0000008E | 0x1000007E | 0x1000008E => Some(1),
        // Parameter 3: address of the faulting instruction.
        0x00000050 => Some(2),
        _ => None,
    }
}

/// Extract the culprit code address from a decoded bugcheck, when one is
/// available and looks like a kernel address.
pub fn culprit_address(code: u32, parameters: &[u64; 4]) -> Option<u64> {
    let index = culprit_parameter_index(code)?;
    let candidate = parameters[index];
    is_kernel_address(candidate).then_some(candidate)
}

/// x64 kernel addresses are sign-extended above the canonical hole. This
/// rejects the small integers and user-mode pointers that appear in other
/// parameter slots.
pub fn is_kernel_address(addr: u64) -> bool {
    addr >= 0xFFFF_8000_0000_0000
}

/// Plain-language interpretation of what a stop code usually means, used to
/// steer the reader toward hardware versus driver investigation.
pub fn interpretation(code: u32) -> &'static str {
    match code {
        0x00000124 | 0x0000009C => {
            "The processor reported an uncorrectable hardware error. This is a CPU, memory or \
             bus fault, not a software bug."
        }
        0x0000001A | 0x00000050 | 0x0000007A => {
            "Memory management fault. Frequently caused by failing RAM, an unstable memory \
             overclock (XMP/EXPO), or a driver corrupting the pool."
        }
        0x00000101 => {
            "A processor stopped responding to the clock interrupt. Usually an unstable CPU \
             overclock or undervolt, occasionally a firmware bug."
        }
        0x00000133 => {
            "A driver held the CPU at high IRQL for too long. The offending driver is normally \
             a storage, network or virtualisation filter."
        }
        0x00000116 | 0x00000117 | 0x00000119 | 0x00000141 => {
            "The graphics driver failed to respond and could not be reset. Points at the GPU \
             driver, GPU overclocking, or a failing card."
        }
        0x0000000A | 0x000000D1 => {
            "A driver accessed invalid memory at an interrupt level that forbids it. This \
             almost always identifies a specific faulty driver."
        }
        0x0000009F => {
            "A driver did not complete a power state transition. Common after sleep or \
             hibernate, usually a network, storage or chipset driver."
        }
        0x000000EF | 0x000000F4 => {
            "A process Windows requires stayed dead. Often follows disk corruption or an \
             aggressive security product."
        }
        0x00000139 | 0x00000109 => {
            "The kernel detected that its own structures had been corrupted. Causes include \
             failing memory, an incompatible driver, or tampering."
        }
        0x0000007B => {
            "Windows could not reach the boot volume. A storage controller driver or disk \
             failure."
        }
        0x000000C4 => {
            "Driver Verifier caught a driver breaking the rules. Parameter 1 identifies which \
             rule; the named driver is the culprit by construction."
        }
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_codes_decode() {
        assert_eq!(name(0x0000000A), "IRQL_NOT_LESS_OR_EQUAL");
        assert_eq!(name(0x00000124), "WHEA_UNCORRECTABLE_ERROR");
        assert_eq!(name(0x000000D1), "DRIVER_IRQL_NOT_LESS_OR_EQUAL");
        assert_eq!(name(0x00000133), "DPC_WATCHDOG_VIOLATION");
        assert_eq!(name(0xABCDEF), "UNKNOWN_BUGCHECK");
    }

    #[test]
    fn culprit_parameter_is_only_claimed_where_documented() {
        assert_eq!(culprit_parameter_index(0xD1), Some(3));
        assert_eq!(culprit_parameter_index(0x3B), Some(1));
        assert_eq!(culprit_parameter_index(0x7E), Some(1));
        // 0x124 is a hardware fault; its parameters point at WHEA records, not
        // at code. Claiming an address here is what produced false culprits.
        assert_eq!(culprit_parameter_index(0x124), None);
        assert_eq!(culprit_parameter_index(0x133), None);
    }

    #[test]
    fn only_kernel_addresses_are_accepted_as_culprits() {
        let params = [0, 2, 0, 0xFFFF_F803_1234_5678];
        assert_eq!(culprit_address(0xD1, &params), Some(0xFFFF_F803_1234_5678));

        // A small integer in the culprit slot is not an address.
        let junk = [0, 2, 0, 0x8];
        assert_eq!(culprit_address(0xD1, &junk), None);

        // A user-mode pointer is not a kernel culprit.
        let user = [0, 2, 0, 0x0000_0001_4000_0000];
        assert_eq!(culprit_address(0xD1, &user), None);
    }

    #[test]
    fn system_service_exception_uses_instruction_not_context_record() {
        let instruction = 0xFFFF_F803_1234_5678;
        let context = 0xFFFF_F900_9876_0000;
        assert_eq!(
            culprit_address(0x3B, &[0xC000_0005, instruction, context, 0]),
            Some(instruction)
        );
        assert_eq!(culprit_address(0x3B, &[0xC000_0005, 0, context, 0]), None);
    }

    #[test]
    fn minidump_exception_variants_keep_the_documented_parameter_mapping() {
        for code in [0x1000007E, 0x1000008E] {
            assert_eq!(
                culprit_address(code, &[0xC000_0005, 0xFFFF_F803_1234_5678, 0, 0]),
                Some(0xFFFF_F803_1234_5678)
            );
            assert_ne!(name(code), "UNKNOWN_BUGCHECK");
        }
        assert_eq!(culprit_parameter_index(0x10000124), None);
    }

    #[test]
    fn hardware_codes_carry_a_hardware_interpretation() {
        assert!(interpretation(0x124).contains("hardware error"));
        assert!(interpretation(0x101).contains("overclock"));
        assert!(interpretation(0xABCD).is_empty());
    }
}
