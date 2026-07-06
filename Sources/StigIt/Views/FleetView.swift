import SwiftUI
import StigItCore

/// Fleet-wide compliance for ops teams. Endpoints publish reports into a shared drop
/// directory (`stigit-cli scan --fleet-dir …`); this view aggregates that directory.
struct FleetView: View {
    @AppStorage("fleetDirectory") private var fleetDirectory = ""

    @State private var summary: FleetService.FleetSummary?
    @State private var reports: [ScanReport] = []
    @State private var selectedHost: FleetService.EndpointSummary.ID?
    @State private var errorMessage: String?
    @State private var showingDirectoryPicker = false

    var body: some View {
        VStack(spacing: 0) {
            if fleetDirectory.isEmpty {
                ContentUnavailableView {
                    Label("No Fleet Directory", systemImage: "server.rack")
                } description: {
                    Text("Choose the directory your endpoints publish reports into with:\nstigit-cli scan --fleet-dir <directory>")
                } actions: {
                    Button("Choose Directory…") { showingDirectoryPicker = true }
                        .buttonStyle(.borderedProminent)
                }
            } else if let summary {
                header(summary)
                Divider()
                endpointTable(summary)
                if let report = selectedReport {
                    Divider()
                    endpointDetail(report)
                }
            } else {
                ContentUnavailableView(
                    "No Endpoint Reports",
                    systemImage: "tray",
                    description: Text("No reports found in \(fleetDirectory)")
                )
            }
        }
        .navigationTitle("Fleet")
        .toolbar {
            ToolbarItem {
                Button {
                    showingDirectoryPicker = true
                } label: {
                    Label("Choose Directory", systemImage: "folder")
                }
            }
            ToolbarItem {
                Button {
                    refresh()
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .disabled(fleetDirectory.isEmpty)
            }
        }
        .fileImporter(
            isPresented: $showingDirectoryPicker,
            allowedContentTypes: [.folder]
        ) { result in
            if case .success(let url) = result {
                fleetDirectory = url.path
                refresh()
            }
        }
        .alert("Fleet Error", isPresented: Binding(
            get: { errorMessage != nil },
            set: { if !$0 { errorMessage = nil } }
        )) {
            Button("OK") { errorMessage = nil }
        } message: { Text(errorMessage ?? "") }
        .onAppear(perform: refresh)
    }

    // MARK: - Sections

    private func header(_ summary: FleetService.FleetSummary) -> some View {
        HStack(spacing: 40) {
            fleetStat("Endpoints", value: "\(summary.endpointCount)", color: .primary)
            fleetStat("Average Score",
                      value: String(format: "%.0f%%", summary.averageScore * 100),
                      color: scoreColor(summary.averageScore))
            fleetStat("Stale", value: "\(summary.staleCount)",
                      color: summary.staleCount > 0 ? .orange : .green)
            fleetStat("High-Severity Failures",
                      value: "\(summary.endpoints.map(\.highSeverityFailures).reduce(0, +))",
                      color: summary.endpoints.contains { $0.highSeverityFailures > 0 } ? .red : .green)
            Spacer()
            Text(fleetDirectory)
                .font(.caption)
                .foregroundColor(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
        }
        .padding()
    }

    private func fleetStat(_ label: String, value: String, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(.caption).foregroundColor(.secondary)
            Text(value).font(.title2).bold().foregroundColor(color)
        }
    }

    private func endpointTable(_ summary: FleetService.FleetSummary) -> some View {
        Table(summary.endpoints, selection: $selectedHost) {
            TableColumn("Hostname") { endpoint in
                HStack {
                    Text(endpoint.hostname)
                    if endpoint.isStale {
                        Text("STALE")
                            .font(.caption2).bold()
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(Capsule().fill(Color.orange))
                            .foregroundColor(.white)
                    }
                }
            }
            TableColumn("Score") { endpoint in
                Text(String(format: "%.0f%%", endpoint.score * 100))
                    .foregroundColor(scoreColor(endpoint.score))
                    .bold()
            }
            TableColumn("High Fails") { endpoint in
                Text("\(endpoint.highSeverityFailures)")
                    .foregroundColor(endpoint.highSeverityFailures > 0 ? .red : .secondary)
            }
            TableColumn("Total Fails") { endpoint in
                Text("\(endpoint.totalFailures)")
            }
            TableColumn("Waived") { endpoint in
                Text("\(endpoint.waived)")
            }
            TableColumn("Profile", value: \.profileName)
            TableColumn("OS", value: \.osVersion)
            TableColumn("Last Report") { endpoint in
                Text(endpoint.reportDate.formatted(date: .abbreviated, time: .shortened))
                    .foregroundColor(endpoint.isStale ? .orange : .secondary)
            }
        }
    }

    private var selectedReport: ScanReport? {
        guard let selectedHost else { return nil }
        return reports.first { $0.endpoint.hostname == selectedHost }
    }

    private func endpointDetail(_ report: ScanReport) -> some View {
        let failing = report.results.filter { $0.outcome == .nonCompliant }
        return VStack(alignment: .leading, spacing: 8) {
            Text("\(report.endpoint.hostname) — \(failing.count) open finding(s)")
                .font(.headline)
                .padding(.horizontal)
                .padding(.top, 8)
            if failing.isEmpty {
                Label("No open findings", systemImage: "checkmark.circle.fill")
                    .foregroundColor(.green)
                    .padding(.horizontal)
                    .padding(.bottom, 8)
            } else {
                List(failing) { result in
                    HStack {
                        Text(result.severity.rawValue.uppercased())
                            .font(.caption2).bold()
                            .frame(width: 56)
                            .padding(.vertical, 2)
                            .background(Capsule().fill(severityColor(result.severity)))
                            .foregroundColor(.white)
                        Text(result.title)
                        Spacer()
                        if let stigId = result.stigId {
                            Text(stigId).font(.caption).foregroundColor(.secondary)
                        }
                    }
                }
                .frame(minHeight: 120, maxHeight: 220)
            }
        }
    }

    // MARK: - Data

    private func refresh() {
        guard !fleetDirectory.isEmpty else { return }
        do {
            reports = try FleetService.loadReports(from: URL(fileURLWithPath: fleetDirectory))
            summary = reports.isEmpty ? nil : FleetService.summarize(reports: reports)
        } catch {
            summary = nil
            reports = []
            errorMessage = "Could not read fleet directory: \(error.localizedDescription)"
        }
    }

    // MARK: - Styling

    private func scoreColor(_ score: Double) -> Color {
        score >= 0.9 ? .green : score >= 0.6 ? .orange : .red
    }

    private func severityColor(_ severity: RuleSeverity) -> Color {
        switch severity {
        case .high:   return .red
        case .medium: return .orange
        case .low:    return .blue
        case .na:     return .gray
        }
    }
}
