import Foundation
#if canImport(IOKit)
import IOKit
#endif

/// Identity of the machine a scan ran on. Stamped into every report so results
/// remain meaningful once they leave the endpoint (fleet aggregation, SIEM, audits).
public struct EndpointInfo: Codable, Hashable, Sendable {
    public let hostname: String
    public let serialNumber: String?
    public let hardwareModel: String?
    public let osVersion: String
    public let osBuild: String?

    public init(
        hostname: String,
        serialNumber: String?,
        hardwareModel: String?,
        osVersion: String,
        osBuild: String?
    ) {
        self.hostname = hostname
        self.serialNumber = serialNumber
        self.hardwareModel = hardwareModel
        self.osVersion = osVersion
        self.osBuild = osBuild
    }

    /// Collects identity for the current machine using native APIs (no shell-outs).
    public static func current() -> EndpointInfo {
        let os = ProcessInfo.processInfo.operatingSystemVersion
        return EndpointInfo(
            hostname: ProcessInfo.processInfo.hostName,
            serialNumber: platformSerialNumber(),
            hardwareModel: sysctlString("hw.model"),
            osVersion: "\(os.majorVersion).\(os.minorVersion).\(os.patchVersion)",
            osBuild: sysctlString("kern.osversion")
        )
    }

    // MARK: - Private

    private static func sysctlString(_ name: String) -> String? {
        var size = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else { return nil }
        var buffer = [CChar](repeating: 0, count: size)
        guard sysctlbyname(name, &buffer, &size, nil, 0) == 0 else { return nil }
        let bytes = buffer.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) }
        return String(decoding: bytes, as: UTF8.self)
    }

    private static func platformSerialNumber() -> String? {
        #if canImport(IOKit)
        let service = IOServiceGetMatchingService(
            kIOMainPortDefault,
            IOServiceMatching("IOPlatformExpertDevice")
        )
        guard service != IO_OBJECT_NULL else { return nil }
        defer { IOObjectRelease(service) }
        guard let serial = IORegistryEntryCreateCFProperty(
            service,
            "IOPlatformSerialNumber" as CFString,
            kCFAllocatorDefault,
            0
        )?.takeRetainedValue() as? String else { return nil }
        return serial
        #else
        return nil
        #endif
    }
}
