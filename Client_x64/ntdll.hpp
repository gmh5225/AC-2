#pragma once

#include <Windows.h>
#include <winternl.h>

#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED   0x00000001
#define SEC_NO_CHANGE 0x00400000
#define NtCurrentThread (HANDLE)-1
#define NtCurrentProcess  (HANDLE)-1
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define TIMEOUT_MS(x) (x * (-10000))

namespace ntdll
{
    constexpr NTSTATUS STATUS_BUFFER_TOO_SMALL = 0xC0000023;
    constexpr NTSTATUS STATUS_SUCCESS = 0;
    constexpr NTSTATUS STATUS_UNSUCCESSFUL = 0xC0000001;

    typedef enum _TOKEN_INFORMATION_CLASS {
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId,
        TokenGroupsAndPrivileges,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin,
        TokenElevationType,
        TokenLinkedToken,
        TokenElevation,
        TokenHasRestrictions,
        TokenAccessInformation,
        TokenVirtualizationAllowed,
        TokenVirtualizationEnabled,
        TokenIntegrityLevel,
        TokenUIAccess,
        TokenMandatoryPolicy,
        TokenLogonSid,
        TokenIsAppContainer,
        TokenCapabilities,
        TokenAppContainerSid,
        TokenAppContainerNumber,
        TokenUserClaimAttributes,
        TokenDeviceClaimAttributes,
        TokenRestrictedUserClaimAttributes,
        TokenRestrictedDeviceClaimAttributes,
        TokenDeviceGroups,
        TokenRestrictedDeviceGroups,
        TokenSecurityAttributes,
        TokenIsRestricted,
        TokenProcessTrustLevel,
        TokenPrivateNameSpace,
        TokenSingletonAttributes,
        TokenBnoIsolation,
        TokenChildProcessFlags,
        TokenIsLessPrivilegedAppContainer,
        TokenIsSandboxed,
        TokenIsAppSilo,
        MaxTokenInfoClass
    } TOKEN_INFORMATION_CLASS, * PTOKEN_INFORMATION_CLASS;

    typedef enum _SECTION_INHERIT
    {
        ViewShare = 1,
        ViewUnmap = 2
    } SECTION_INHERIT;

    typedef struct _SYSTEM_PROCESS_INFORMATION
    {
        ULONG NextEntryOffset;
        ULONG NumberOfThreads;
        LARGE_INTEGER WorkingSetPrivateSize; // Since Vista
        ULONG HardFaultCount; // Since Windows 7
        ULONG NumberOfThreadsHighWatermark; // Since Windows 7
        ULONGLONG CycleTime; // Since Windows 7
        LARGE_INTEGER CreateTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER KernelTime;
        UNICODE_STRING ImageName;
        KPRIORITY BasePriority;
        HANDLE UniqueProcessId;
        HANDLE InheritedFromUniqueProcessId;
        ULONG HandleCount;
        ULONG SessionId;
        ULONG_PTR UniqueProcessKey; // Since Vista (requires SystemExtendedProcessInformation)
        SIZE_T PeakVirtualSize;
        SIZE_T VirtualSize;
        ULONG PageFaultCount;
        SIZE_T PeakWorkingSetSize;
        SIZE_T WorkingSetSize;
        SIZE_T QuotaPeakPagedPoolUsage;
        SIZE_T QuotaPagedPoolUsage;
        SIZE_T QuotaPeakNonPagedPoolUsage;
        SIZE_T QuotaNonPagedPoolUsage;
        SIZE_T PagefileUsage;
        SIZE_T PeakPagefileUsage;
        SIZE_T PrivatePageCount;
        LARGE_INTEGER ReadOperationCount;
        LARGE_INTEGER WriteOperationCount;
        LARGE_INTEGER OtherOperationCount;
        LARGE_INTEGER ReadTransferCount;
        LARGE_INTEGER WriteTransferCount;
        LARGE_INTEGER OtherTransferCount;
        SYSTEM_THREAD_INFORMATION Threads[1];
    } SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

    typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
    {
        USHORT UniqueProcessId;
        USHORT CreatorBackTraceIndex;
        UCHAR ObjectTypeIndex;
        UCHAR HandleAttributes;
        USHORT HandleValue;
        PVOID Object;
        ULONG GrantedAccess;
    } SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

    typedef struct _SYSTEM_HANDLE_INFORMATION
    {
        ULONG NumberOfHandles;
        SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
    } SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

    typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
    {
        PVOID Object;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR HandleValue;
        ULONG GrantedAccess;
        USHORT CreatorBackTraceIndex;
        USHORT ObjectTypeIndex;
        ULONG HandleAttributes;
        ULONG Reserved;
    } SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

    typedef struct _SYSTEM_HANDLE_INFORMATION_EX
    {
        ULONG_PTR NumberOfHandles;
        ULONG_PTR Reserved;
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
    } SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

    typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
    {
        ULONG Version;
        ULONG Reserved;
        PVOID Callback;
    } PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, * PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

    typedef enum _PROCESSINFOCLASS
    {
        ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
        ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
        ProcessIoCounters, // q: IO_COUNTERS
        ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
        ProcessTimes, // q: KERNEL_USER_TIMES
        ProcessBasePriority, // s: KPRIORITY
        ProcessRaisePriority, // s: ULONG
        ProcessDebugPort, // q: HANDLE
        ProcessExceptionPort, // s: HANDLE
        ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
        ProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
        ProcessLdtSize, // s: PROCESS_LDT_SIZE
        ProcessDefaultHardErrorMode, // qs: ULONG
        ProcessIoPortHandlers, // (kernel-mode only)
        ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
        ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
        ProcessUserModeIOPL,
        ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
        ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
        ProcessWx86Information,
        ProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
        ProcessAffinityMask, // s: KAFFINITY
        ProcessPriorityBoost, // qs: ULONG
        ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
        ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
        ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
        ProcessWow64Information, // q: ULONG_PTR
        ProcessImageFileName, // q: UNICODE_STRING
        ProcessLUIDDeviceMapsEnabled, // q: ULONG
        ProcessBreakOnTermination, // qs: ULONG
        ProcessDebugObjectHandle, // q: HANDLE // 30
        ProcessDebugFlags, // qs: ULONG
        ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
        ProcessIoPriority, // qs: IO_PRIORITY_HINT
        ProcessExecuteFlags, // qs: ULONG
        ProcessResourceManagement,
        ProcessCookie, // q: ULONG
        ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
        ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
        ProcessPagePriority, // q: ULONG
        ProcessInstrumentationCallback, // 40
        ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
        ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
        ProcessImageFileNameWin32, // q: UNICODE_STRING
        ProcessImageFileMapping, // q: HANDLE (input)
        ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
        ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
        ProcessGroupInformation, // q: USHORT[]
        ProcessTokenVirtualizationEnabled, // s: ULONG
        ProcessConsoleHostProcess, // q: ULONG_PTR
        ProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
        ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
        ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
        ProcessDynamicFunctionTableInformation,
        ProcessHandleCheckingMode,
        ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
        ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
        ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
        ProcessHandleTable, // since WINBLUE
        ProcessCheckStackExtentsMode,
        ProcessCommandLineInformation, // q: UNICODE_STRING // 60
        ProcessProtectionInformation, // q: PS_PROTECTION
        ProcessMemoryExhaustion, // PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
        ProcessFaultInformation, // PROCESS_FAULT_INFORMATION
        ProcessTelemetryIdInformation, // PROCESS_TELEMETRY_ID_INFORMATION
        ProcessCommitReleaseInformation, // PROCESS_COMMIT_RELEASE_INFORMATION
        ProcessDefaultCpuSetsInformation,
        ProcessAllowedCpuSetsInformation,
        ProcessSubsystemProcess,
        ProcessJobMemoryInformation, // PROCESS_JOB_MEMORY_INFO
        ProcessInPrivate, // since THRESHOLD2 // 70
        ProcessRaiseUMExceptionOnInvalidHandleClose,
        ProcessIumChallengeResponse,
        ProcessChildProcessInformation, // PROCESS_CHILD_PROCESS_INFORMATION
        ProcessHighGraphicsPriorityInformation,
        ProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
        ProcessEnergyValues, // PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
        ProcessActivityThrottleState, // PROCESS_ACTIVITY_THROTTLE_STATE
        ProcessActivityThrottlePolicy, // PROCESS_ACTIVITY_THROTTLE_POLICY
        ProcessWin32kSyscallFilterInformation,
        ProcessDisableSystemAllowedCpuSets,
        ProcessWakeInformation, // PROCESS_WAKE_INFORMATION
        ProcessEnergyTrackingState, // PROCESS_ENERGY_TRACKING_STATE
        MaxProcessInfoClass
    } PROCESSINFOCLASS, PROCESS_INFORMATION_CLASS;


    typedef enum _SYSTEM_INFORMATION_CLASS
    {
        SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
        SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
        SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
        SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
        SystemPathInformation, // not implemented
        SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
        SystemCallCountInformation, // q: SYSTEM_CALL_COUNT_INFORMATION
        SystemDeviceInformation, // q: SYSTEM_DEVICE_INFORMATION
        SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
        SystemFlagsInformation, // q: SYSTEM_FLAGS_INFORMATION
        SystemCallTimeInformation, // not implemented // SYSTEM_CALL_TIME_INFORMATION // 10
        SystemModuleInformation, // q: RTL_PROCESS_MODULES
        SystemLocksInformation, // q: RTL_PROCESS_LOCKS
        SystemStackTraceInformation, // q: RTL_PROCESS_BACKTRACES
        SystemPagedPoolInformation, // not implemented
        SystemNonPagedPoolInformation, // not implemented
        SystemHandleInformation, // q: SYSTEM_HANDLE_INFORMATION
        SystemObjectInformation, // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
        SystemPageFileInformation, // q: SYSTEM_PAGEFILE_INFORMATION
        SystemVdmInstemulInformation, // q
        SystemVdmBopInformation, // not implemented // 20
        SystemFileCacheInformation, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
        SystemPoolTagInformation, // q: SYSTEM_POOLTAG_INFORMATION
        SystemInterruptInformation, // q: SYSTEM_INTERRUPT_INFORMATION
        SystemDpcBehaviorInformation, // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
        SystemFullMemoryInformation, // not implemented
        SystemLoadGdiDriverInformation, // s (kernel-mode only)
        SystemUnloadGdiDriverInformation, // s (kernel-mode only)
        SystemTimeAdjustmentInformation, // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
        SystemSummaryMemoryInformation, // not implemented
        SystemMirrorMemoryInformation, // s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
        SystemPerformanceTraceInformation, // q; s: (type depends on EVENT_TRACE_INFORMATION_CLASS)
        SystemObsolete0, // not implemented
        SystemExceptionInformation, // q: SYSTEM_EXCEPTION_INFORMATION
        SystemCrashDumpStateInformation, // s (requires SeDebugPrivilege)
        SystemKernelDebuggerInformation, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
        SystemContextSwitchInformation, // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
        SystemRegistryQuotaInformation, // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
        SystemExtendServiceTableInformation, // s (requires SeLoadDriverPrivilege) // loads win32k only
        SystemPrioritySeperation, // s (requires SeTcbPrivilege)
        SystemVerifierAddDriverInformation, // s (requires SeDebugPrivilege) // 40
        SystemVerifierRemoveDriverInformation, // s (requires SeDebugPrivilege)
        SystemProcessorIdleInformation, // q: SYSTEM_PROCESSOR_IDLE_INFORMATION
        SystemLegacyDriverInformation, // q: SYSTEM_LEGACY_DRIVER_INFORMATION
        SystemCurrentTimeZoneInformation, // q
        SystemLookasideInformation, // q: SYSTEM_LOOKASIDE_INFORMATION
        SystemTimeSlipNotification, // s (requires SeSystemtimePrivilege)
        SystemSessionCreate, // not implemented
        SystemSessionDetach, // not implemented
        SystemSessionInformation, // not implemented
        SystemRangeStartInformation, // q: SYSTEM_RANGE_START_INFORMATION // 50
        SystemVerifierInformation, // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
        SystemVerifierThunkExtend, // s (kernel-mode only)
        SystemSessionProcessInformation, // q: SYSTEM_SESSION_PROCESS_INFORMATION
        SystemLoadGdiDriverInSystemSpace, // s (kernel-mode only) (same as SystemLoadGdiDriverInformation)
        SystemNumaProcessorMap, // q
        SystemPrefetcherInformation, // q: PREFETCHER_INFORMATION; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
        SystemExtendedProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
        SystemRecommendedSharedDataAlignment, // q
        SystemComPlusPackage, // q; s
        SystemNumaAvailableMemory, // 60
        SystemProcessorPowerInformation, // q: SYSTEM_PROCESSOR_POWER_INFORMATION
        SystemEmulationBasicInformation, // q
        SystemEmulationProcessorInformation,
        SystemExtendedHandleInformation, // q: SYSTEM_HANDLE_INFORMATION_EX
        SystemLostDelayedWriteInformation, // q: ULONG
        SystemBigPoolInformation, // q: SYSTEM_BIGPOOL_INFORMATION
        SystemSessionPoolTagInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION
        SystemSessionMappedViewInformation, // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
        SystemHotpatchInformation, // q; s
        SystemObjectSecurityMode, // q // 70
        SystemWatchdogTimerHandler, // s (kernel-mode only)
        SystemWatchdogTimerInformation, // q (kernel-mode only); s (kernel-mode only)
        SystemLogicalProcessorInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION
        SystemWow64SharedInformationObsolete, // not implemented
        SystemRegisterFirmwareTableInformationHandler, // s (kernel-mode only)
        SystemFirmwareTableInformation, // SYSTEM_FIRMWARE_TABLE_INFORMATION
        SystemModuleInformationEx, // q: RTL_PROCESS_MODULE_INFORMATION_EX
        SystemVerifierTriageInformation, // not implemented
        SystemSuperfetchInformation, // q; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
        SystemMemoryListInformation, // q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
        SystemFileCacheInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
        SystemThreadPriorityClientIdInformation, // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
        SystemProcessorIdleCycleTimeInformation, // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[]
        SystemVerifierCancellationInformation, // not implemented // name:wow64:whNT32QuerySystemVerifierCancellationInformation
        SystemProcessorPowerInformationEx, // not implemented
        SystemRefTraceInformation, // q; s: SYSTEM_REF_TRACE_INFORMATION // ObQueryRefTraceInformation
        SystemSpecialPoolInformation, // q; s (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
        SystemProcessIdInformation, // q: SYSTEM_PROCESS_ID_INFORMATION
        SystemErrorPortInformation, // s (requires SeTcbPrivilege)
        SystemBootEnvironmentInformation, // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
        SystemHypervisorInformation, // q; s (kernel-mode only)
        SystemVerifierInformationEx, // q; s: SYSTEM_VERIFIER_INFORMATION_EX
        SystemTimeZoneInformation, // s (requires SeTimeZonePrivilege)
        SystemImageFileExecutionOptionsInformation, // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
        SystemCoverageInformation, // q; s // name:wow64:whNT32QuerySystemCoverageInformation; ExpCovQueryInformation
        SystemPrefetchPatchInformation, // not implemented
        SystemVerifierFaultsInformation, // s (requires SeDebugPrivilege)
        SystemSystemPartitionInformation, // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
        SystemSystemDiskInformation, // q: SYSTEM_SYSTEM_DISK_INFORMATION
        SystemProcessorPerformanceDistribution, // q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION // 100
        SystemNumaProximityNodeInformation, // q
        SystemDynamicTimeZoneInformation, // q; s (requires SeTimeZonePrivilege)
        SystemCodeIntegrityInformation, // q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
        SystemProcessorMicrocodeUpdateInformation, // s
        SystemProcessorBrandString, // q // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
        SystemVirtualAddressInformation, // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
        SystemLogicalProcessorAndGroupInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // since WIN7 // KeQueryLogicalProcessorRelationship
        SystemProcessorCycleTimeInformation, // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[]
        SystemStoreInformation, // q; s // SmQueryStoreInformation
        SystemRegistryAppendString, // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
        SystemAitSamplingValue, // s: ULONG (requires SeProfileSingleProcessPrivilege)
        SystemVhdBootInformation, // q: SYSTEM_VHD_BOOT_INFORMATION
        SystemCpuQuotaInformation, // q; s // PsQueryCpuQuotaInformation
        SystemNativeBasicInformation, // not implemented
        SystemSpare1, // not implemented
        SystemLowPriorityIoInformation, // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
        SystemTpmBootEntropyInformation, // q: TPM_BOOT_ENTROPY_NT_RESULT // ExQueryTpmBootEntropyInformation
        SystemVerifierCountersInformation, // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
        SystemPagedPoolInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
        SystemSystemPtesInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
        SystemNodeDistanceInformation, // q
        SystemAcpiAuditInformation, // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
        SystemBasicPerformanceInformation, // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
        SystemQueryPerformanceCounterInformation, // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
        SystemSessionBigPoolInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION // since WIN8
        SystemBootGraphicsInformation, // q; s: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
        SystemScrubPhysicalMemoryInformation, // q; s: MEMORY_SCRUB_INFORMATION
        SystemBadPageInformation,
        SystemProcessorProfileControlArea, // q; s: SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
        SystemCombinePhysicalMemoryInformation, // s: MEMORY_COMBINE_INFORMATION, MEMORY_COMBINE_INFORMATION_EX, MEMORY_COMBINE_INFORMATION_EX2 // 130
        SystemEntropyInterruptTimingCallback,
        SystemConsoleInformation, // q: SYSTEM_CONSOLE_INFORMATION
        SystemPlatformBinaryInformation, // q: SYSTEM_PLATFORM_BINARY_INFORMATION
        SystemThrottleNotificationInformation,
        SystemHypervisorProcessorCountInformation, // q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
        SystemDeviceDataInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
        SystemDeviceDataEnumerationInformation,
        SystemMemoryTopologyInformation, // q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
        SystemMemoryChannelInformation, // q: SYSTEM_MEMORY_CHANNEL_INFORMATION
        SystemBootLogoInformation, // q: SYSTEM_BOOT_LOGO_INFORMATION // 140
        SystemProcessorPerformanceInformationEx, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // since WINBLUE
        SystemSpare0,
        SystemSecureBootPolicyInformation, // q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
        SystemPageFileInformationEx, // q: SYSTEM_PAGEFILE_INFORMATION_EX
        SystemSecureBootInformation, // q: SYSTEM_SECUREBOOT_INFORMATION
        SystemEntropyInterruptTimingRawInformation,
        SystemPortableWorkspaceEfiLauncherInformation, // q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
        SystemFullProcessInformation, // q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
        SystemKernelDebuggerInformationEx, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
        SystemBootMetadataInformation, // 150
        SystemSoftRebootInformation,
        SystemElamCertificateInformation, // s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
        SystemOfflineDumpConfigInformation,
        SystemProcessorFeaturesInformation, // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
        SystemRegistryReconciliationInformation,
        SystemEdidInformation,
        SystemManufacturingInformation, // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
        SystemEnergyEstimationConfigInformation, // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
        SystemHypervisorDetailInformation, // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
        SystemProcessorCycleStatsInformation, // q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION // 160
        SystemVmGenerationCountInformation,
        SystemTrustedPlatformModuleInformation, // q: SYSTEM_TPM_INFORMATION
        SystemKernelDebuggerFlags,
        SystemCodeIntegrityPolicyInformation, // q: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
        SystemIsolatedUserModeInformation, // q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
        SystemHardwareSecurityTestInterfaceResultsInformation,
        SystemSingleModuleInformation, // q: SYSTEM_SINGLE_MODULE_INFORMATION
        SystemAllowedCpuSetsInformation,
        SystemDmaProtectionInformation, // q: SYSTEM_DMA_PROTECTION_INFORMATION
        SystemInterruptCpuSetsInformation, // q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION // 170
        SystemSecureBootPolicyFullInformation, // q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
        SystemCodeIntegrityPolicyFullInformation,
        SystemAffinitizedInterruptProcessorInformation,
        SystemRootSiloInformation, // q: SYSTEM_ROOT_SILO_INFORMATION
        SystemCpuSetInformation, // q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
        SystemCpuSetTagInformation, // q: SYSTEM_CPU_SET_TAG_INFORMATION
        SystemWin32WerStartCallout,
        SystemSecureKernelProfileInformation, // q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
        SystemCodeIntegrityPlatformManifestInformation, // q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // since REDSTONE
        SystemInterruptSteeringInformation, // 180
        SystemSupportedProcessorArchitectures,
        SystemMemoryUsageInformation, // q: SYSTEM_MEMORY_USAGE_INFORMATION
        SystemCodeIntegrityCertificateInformation, // q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
        SystemPhysicalMemoryInformation, // q: SYSTEM_PHYSICAL_MEMORY_INFORMATION // since REDSTONE2
        SystemControlFlowTransition,
        SystemKernelDebuggingAllowed,
        SystemActivityModerationExeState, // SYSTEM_ACTIVITY_MODERATION_EXE_STATE
        SystemActivityModerationUserSettings, // SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
        SystemCodeIntegrityPoliciesFullInformation,
        SystemCodeIntegrityUnlockInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION // 190
        SystemIntegrityQuotaInformation,
        SystemFlushInformation, // q: SYSTEM_FLUSH_INFORMATION
        MaxSystemInfoClass
    } SYSTEM_INFORMATION_CLASS;

    typedef enum _THREADINFOCLASS
    {
        ThreadBasicInformation, // q: THREAD_BASIC_INFORMATION
        ThreadTimes, // q: KERNEL_USER_TIMES
        ThreadPriority, // s: KPRIORITY
        ThreadBasePriority, // s: LONG
        ThreadAffinityMask, // s: KAFFINITY
        ThreadImpersonationToken, // s: HANDLE
        ThreadDescriptorTableEntry, // q: DESCRIPTOR_TABLE_ENTRY (or WOW64_DESCRIPTOR_TABLE_ENTRY)
        ThreadEnableAlignmentFaultFixup, // s: BOOLEAN
        ThreadEventPair,
        ThreadQuerySetWin32StartAddress, // q: PVOID
        ThreadZeroTlsCell, // 10
        ThreadPerformanceCount, // q: LARGE_INTEGER
        ThreadAmILastThread, // q: ULONG
        ThreadIdealProcessor, // s: ULONG
        ThreadPriorityBoost, // qs: ULONG
        ThreadSetTlsArrayAddress,
        ThreadIsIoPending, // q: ULONG
        ThreadHideFromDebugger, // s: void
        ThreadBreakOnTermination, // qs: ULONG
        ThreadSwitchLegacyState,
        ThreadIsTerminated, // q: ULONG // 20
        ThreadLastSystemCall, // q: THREAD_LAST_SYSCALL_INFORMATION
        ThreadIoPriority, // qs: IO_PRIORITY_HINT
        ThreadCycleTime, // q: THREAD_CYCLE_TIME_INFORMATION
        ThreadPagePriority, // q: ULONG
        ThreadActualBasePriority,
        ThreadTebInformation, // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_SET_CONTEXT)
        ThreadCSwitchMon,
        ThreadCSwitchPmu,
        ThreadWow64Context, // q: WOW64_CONTEXT
        ThreadGroupInformation, // q: GROUP_AFFINITY // 30
        ThreadUmsInformation, // q: THREAD_UMS_INFORMATION
        ThreadCounterProfiling,
        ThreadIdealProcessorEx, // q: PROCESSOR_NUMBER
        ThreadCpuAccountingInformation, // since WIN8
        ThreadSuspendCount, // since WINBLUE
        ThreadHeterogeneousCpuPolicy, // q: KHETERO_CPU_POLICY // since THRESHOLD
        ThreadContainerId, // q: GUID
        ThreadNameInformation, // qs: THREAD_NAME_INFORMATION
        ThreadSelectedCpuSets,
        ThreadSystemThreadInformation, // q: SYSTEM_THREAD_INFORMATION // 40
        ThreadActualGroupAffinity, // since THRESHOLD2
        ThreadDynamicCodePolicyInfo,
        ThreadExplicitCaseSensitivity,
        ThreadWorkOnBehalfTicket,
        ThreadSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
        ThreadDbgkWerReportActive,
        ThreadAttachContainer,
        MaxThreadInfoClass
    } THREADINFOCLASS;

    typedef enum _SHUTDOWN_ACTION
    {
        ShutdownNoReboot,
        ShutdownReboot,
        ShutdownPowerOff
    } SHUTDOWN_ACTION, * PSHUTDOWN_ACTION;

    typedef struct
    {
        LIST_ENTRY InMemoryOrderLinks;
        LIST_ENTRY InInitializationOrderLinks;
        PVOID DllBase;
        PVOID EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
        ULONG Flags;
        WORD LoadCount;
        WORD TlsIndex;
    } LDR_DATA_TABLE_ENTRY_, * PLDR_DATA_TABLE_ENTRY_;

    typedef struct
    {
        ULONG                   Length;
        BOOLEAN                 Initialized;
        PVOID                   SsHandle;
        LIST_ENTRY              InLoadOrderModuleList;
        LIST_ENTRY              InMemoryOrderModuleList;
        LIST_ENTRY              InInitializationOrderModuleList;
    } PEB_LDR_DATA_, * PPEB_LDR_DATA_;

    typedef enum _MEMORY_INFORMATION_CLASS
    {
        MemoryBasicInformation, // MEMORY_BASIC_INFORMATION
        MemoryWorkingSetInformation, // MEMORY_WORKING_SET_INFORMATION
        MemoryMappedFilenameInformation, // UNICODE_STRING
        MemoryRegionInformation, // MEMORY_REGION_INFORMATION
        MemoryWorkingSetExInformation, // MEMORY_WORKING_SET_EX_INFORMATION
        MemorySharedCommitInformation, // MEMORY_SHARED_COMMIT_INFORMATION
        MemoryImageInformation, // MEMORY_IMAGE_INFORMATION
        MemoryRegionInformationEx, // MEMORY_REGION_INFORMATION
        MemoryPrivilegedBasicInformation,
        MemoryEnclaveImageInformation, // MEMORY_ENCLAVE_IMAGE_INFORMATION // since REDSTONE3
        MemoryBasicInformationCapped, // 10
        MemoryPhysicalContiguityInformation, // MEMORY_PHYSICAL_CONTIGUITY_INFORMATION // since 20H1
        MemoryBadInformation, // since WIN11
        MaxMemoryInfoClass
    } MEMORY_INFORMATION_CLASS;

    typedef struct _CLIENT_ID
    {
        PVOID UniqueProcess;
        PVOID UniqueThread;
    } CLIENT_ID, * PCLIENT_ID;

    enum _OBEJECT_TYPE_INDEX : BYTE
    {
        OTI_Unknown00 = 0x00,
        OTI_Unknown01 = 0x01,
        OTI_Unknown02 = 0x00,
        OTI_Directory = 0x03,
        OTI_Unknown04 = 0x04,
        OTI_Token = 0x05,
        OTI_Job = 0x06,
        OTI_Process = 0x07,
        OTI_Thread = 0x08,
        OTI_Unknown09 = 0x09,
        OTI_IoCompletionReserve = 0x0A,
        OTI_Unknown0B = 0x0B,
        OTI_Unknown0C = 0x0C,
        OTI_Unknown0D = 0x0D,
        OTI_DebugObject = 0x0E,
        OTI_Event = 0x0F,
        OTI_Mutant = 0x10,
        OTI_Unknown11 = 0x11,
        OTI_Semaphore = 0x12,
        OTI_Timer = 0x13,
        OTI_IRTimer = 0x14,
        OTI_Unknown15 = 0x15,
        OTI_Unknown16 = 0x16,
        OTI_WindowStation = 0x17,
        OTI_Desktop = 0x18,
        OTI_Composition = 0x19,
        OTI_RawInputManager = 0x1A,
        OTI_Unknown1B = 0x1B,
        OTI_TpWorkerFactory = 0x1C,
        OTI_Unknown1D = 0x1D,
        OTI_Unknown1E = 0x1E,
        OTI_Unknown1F = 0x1F,
        OTI_Unknown20 = 0x20,
        OTI_IoCompletion = 0x21,
        OTI_WaitCompletionPacket = 0x22,
        OTI_File = 0x23,
        OTI_Unknown24 = 0x24,
        OTI_Unknown25 = 0x25,
        OTI_Unknown26 = 0x26,
        OTI_Unknown27 = 0x27,
        OTI_Section = 0x28,
        OTI_Session = 0x29,
        OTI_Partition = 0x2A,
        OTI_Key = 0x2B,
        OTI_Unknown2C = 0x2C,
        OTI_ALPC_Port = 0x2D,
        OTI_Unknown2E = 0x2E,
        OTI_WmiGuid = 0x2F,
        OTI_Unknown30 = 0x30,
        OTI_Unknown31 = 0x31,
        OTI_Unknown32 = 0x32,
        OTI_Unknown33 = 0x33,
        OTI_Unknown34 = 0x34,
        OTI_Unknown35 = 0x35,
    };
    typedef _OBEJECT_TYPE_INDEX OBJECT_TYPE_INDEX;

    struct _STRING64
    {
        USHORT Length;                                                          //0x0
        USHORT MaximumLength;                                                   //0x2
        ULONGLONG Buffer;                                                       //0x8
    };

    struct _CLIENT_ID64
    {
        HANDLE UniqueProcess;                                                //0x0
        HANDLE UniqueThread;                                                 //0x8
    };

    struct _ACTIVATION_CONTEXT_STACK64
    {
        ULONGLONG ActiveFrame;                                                  //0x0
        struct LIST_ENTRY64 FrameListCache;                                     //0x8
        ULONG Flags;                                                            //0x18
        ULONG NextCookieSequenceNumber;                                         //0x1c
        ULONG StackId;                                                          //0x20
    };

    struct _GDI_TEB_BATCH64
    {
        ULONG Offset : 31;                                                        //0x0
        ULONG HasRenderingCommand : 1;                                            //0x0
        ULONGLONG HDC;                                                          //0x8
        ULONG Buffer[310];                                                      //0x10
    };

    //0x1838 bytes (sizeof)
    typedef struct _TEB64
    {
        struct _NT_TIB64 NtTib;                                                 //0x0
        ULONGLONG EnvironmentPointer;                                           //0x38
        struct _CLIENT_ID64 ClientId;                                           //0x40
        ULONGLONG ActiveRpcHandle;                                              //0x50
        ULONGLONG ThreadLocalStoragePointer;                                    //0x58
        ULONGLONG ProcessEnvironmentBlock;                                      //0x60
        ULONG LastErrorValue;                                                   //0x68
        ULONG CountOfOwnedCriticalSections;                                     //0x6c
        ULONGLONG CsrClientThread;                                              //0x70
        ULONGLONG Win32ThreadInfo;                                              //0x78
        ULONG User32Reserved[26];                                               //0x80
        ULONG UserReserved[5];                                                  //0xe8
        ULONGLONG WOW32Reserved;                                                //0x100
        ULONG CurrentLocale;                                                    //0x108
        ULONG FpSoftwareStatusRegister;                                         //0x10c
        ULONGLONG ReservedForDebuggerInstrumentation[16];                       //0x110
        ULONGLONG SystemReserved1[30];                                          //0x190
        CHAR PlaceholderCompatibilityMode;                                      //0x280
        UCHAR PlaceholderHydrationAlwaysExplicit;                               //0x281
        CHAR PlaceholderReserved[10];                                           //0x282
        ULONG ProxiedProcessId;                                                 //0x28c
        struct _ACTIVATION_CONTEXT_STACK64 _ActivationStack;                    //0x290
        UCHAR WorkingOnBehalfTicket[8];                                         //0x2b8
        LONG ExceptionCode;                                                     //0x2c0
        UCHAR Padding0[4];                                                      //0x2c4
        ULONGLONG ActivationContextStackPointer;                                //0x2c8
        ULONGLONG InstrumentationCallbackSp;                                    //0x2d0
        ULONGLONG InstrumentationCallbackPreviousPc;                            //0x2d8
        ULONGLONG InstrumentationCallbackPreviousSp;                            //0x2e0
        ULONG TxFsContext;                                                      //0x2e8
        UCHAR InstrumentationCallbackDisabled;                                  //0x2ec
        UCHAR UnalignedLoadStoreExceptions;                                     //0x2ed
        UCHAR Padding1[2];                                                      //0x2ee
        struct _GDI_TEB_BATCH64 GdiTebBatch;                                    //0x2f0
        struct _CLIENT_ID64 RealClientId;                                       //0x7d8
        ULONGLONG GdiCachedProcessHandle;                                       //0x7e8
        ULONG GdiClientPID;                                                     //0x7f0
        ULONG GdiClientTID;                                                     //0x7f4
        ULONGLONG GdiThreadLocalInfo;                                           //0x7f8
        ULONGLONG Win32ClientInfo[62];                                          //0x800
        ULONGLONG glDispatchTable[233];                                         //0x9f0
        ULONGLONG glReserved1[29];                                              //0x1138
        ULONGLONG glReserved2;                                                  //0x1220
        ULONGLONG glSectionInfo;                                                //0x1228
        ULONGLONG glSection;                                                    //0x1230
        ULONGLONG glTable;                                                      //0x1238
        ULONGLONG glCurrentRC;                                                  //0x1240
        ULONGLONG glContext;                                                    //0x1248
        ULONG LastStatusValue;                                                  //0x1250
        UCHAR Padding2[4];                                                      //0x1254
        struct _STRING64 StaticUnicodeString;                                   //0x1258
        WCHAR StaticUnicodeBuffer[261];                                         //0x1268
        UCHAR Padding3[6];                                                      //0x1472
        ULONGLONG DeallocationStack;                                            //0x1478
        ULONGLONG TlsSlots[64];                                                 //0x1480
        struct LIST_ENTRY64 TlsLinks;                                           //0x1680
        ULONGLONG Vdm;                                                          //0x1690
        ULONGLONG ReservedForNtRpc;                                             //0x1698
        ULONGLONG DbgSsReserved[2];                                             //0x16a0
        ULONG HardErrorMode;                                                    //0x16b0
        UCHAR Padding4[4];                                                      //0x16b4
        ULONGLONG Instrumentation[11];                                          //0x16b8
        struct _GUID ActivityId;                                                //0x1710
        ULONGLONG SubProcessTag;                                                //0x1720
        ULONGLONG PerflibData;                                                  //0x1728
        ULONGLONG EtwTraceData;                                                 //0x1730
        ULONGLONG WinSockData;                                                  //0x1738
        ULONG GdiBatchCount;                                                    //0x1740
        union
        {
            struct _PROCESSOR_NUMBER CurrentIdealProcessor;                     //0x1744
            ULONG IdealProcessorValue;                                          //0x1744
            struct
            {
                UCHAR ReservedPad0;                                             //0x1744
                UCHAR ReservedPad1;                                             //0x1745
                UCHAR ReservedPad2;                                             //0x1746
                UCHAR IdealProcessor;                                           //0x1747
            };
        };
        ULONG GuaranteedStackBytes;                                             //0x1748
        UCHAR Padding5[4];                                                      //0x174c
        ULONGLONG ReservedForPerf;                                              //0x1750
        ULONGLONG ReservedForOle;                                               //0x1758
        ULONG WaitingOnLoaderLock;                                              //0x1760
        UCHAR Padding6[4];                                                      //0x1764
        ULONGLONG SavedPriorityState;                                           //0x1768
        ULONGLONG ReservedForCodeCoverage;                                      //0x1770
        ULONGLONG ThreadPoolData;                                               //0x1778
        ULONGLONG TlsExpansionSlots;                                            //0x1780
        ULONGLONG DeallocationBStore;                                           //0x1788
        ULONGLONG BStoreLimit;                                                  //0x1790
        ULONG MuiGeneration;                                                    //0x1798
        ULONG IsImpersonating;                                                  //0x179c
        ULONGLONG NlsCache;                                                     //0x17a0
        ULONGLONG pShimData;                                                    //0x17a8
        ULONG HeapData;                                                         //0x17b0
        UCHAR Padding7[4];                                                      //0x17b4
        ULONGLONG CurrentTransactionHandle;                                     //0x17b8
        ULONGLONG ActiveFrame;                                                  //0x17c0
        ULONGLONG FlsData;                                                      //0x17c8
        ULONGLONG PreferredLanguages;                                           //0x17d0
        ULONGLONG UserPrefLanguages;                                            //0x17d8
        ULONGLONG MergedPrefLanguages;                                          //0x17e0
        ULONG MuiImpersonation;                                                 //0x17e8
        union
        {
            volatile USHORT CrossTebFlags;                                      //0x17ec
            USHORT SpareCrossTebBits : 16;                                        //0x17ec
        };
        union
        {
            USHORT SameTebFlags;                                                //0x17ee
            struct
            {
                USHORT SafeThunkCall : 1;                                         //0x17ee
                USHORT InDebugPrint : 1;                                          //0x17ee
                USHORT HasFiberData : 1;                                          //0x17ee
                USHORT SkipThreadAttach : 1;                                      //0x17ee
                USHORT WerInShipAssertCode : 1;                                   //0x17ee
                USHORT RanProcessInit : 1;                                        //0x17ee
                USHORT ClonedThread : 1;                                          //0x17ee
                USHORT SuppressDebugMsg : 1;                                      //0x17ee
                USHORT DisableUserStackWalk : 1;                                  //0x17ee
                USHORT RtlExceptionAttached : 1;                                  //0x17ee
                USHORT InitialThread : 1;                                         //0x17ee
                USHORT SessionAware : 1;                                          //0x17ee
                USHORT LoadOwner : 1;                                             //0x17ee
                USHORT LoaderWorker : 1;                                          //0x17ee
                USHORT SkipLoaderInit : 1;                                        //0x17ee
                USHORT SpareSameTebBits : 1;                                      //0x17ee
            };
        };
        ULONGLONG TxnScopeEnterCallback;                                        //0x17f0
        ULONGLONG TxnScopeExitCallback;                                         //0x17f8
        ULONGLONG TxnScopeContext;                                              //0x1800
        ULONG LockCount;                                                        //0x1808
        LONG WowTebOffset;                                                      //0x180c
        ULONGLONG ResourceRetValue;                                             //0x1810
        ULONGLONG ReservedForWdf;                                               //0x1818
        ULONGLONG ReservedForCrt;                                               //0x1820
        struct _GUID EffectiveContainerId;                                      //0x1828
    }TEB64, * PTEB64;
}