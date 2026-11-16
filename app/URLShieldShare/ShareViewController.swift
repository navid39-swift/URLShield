//
//  ShareViewController.swift
//  URLShieldShare
//
//  Share a link or a message from Messages, Mail, Safari, WhatsApp...
//  and see the URLShield result without leaving that app.
//

import SwiftUI
import UIKit
import UniformTypeIdentifiers

final class ShareViewController: UIViewController {

    private let model = ShareModel()

    override func viewDidLoad() {
        super.viewDidLoad()

        let root = ShareResultView(model: model) { [weak self] in
            self?.extensionContext?.completeRequest(returningItems: nil)
        }
        let host = UIHostingController(rootView: root)
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(host.view)
        host.didMove(toParent: self)

        let context = extensionContext
        Task {
            await model.load(from: context)
        }
    }
}

// MARK: - Model

@Observable
final class ShareModel {
    enum State {
        case loading
        case results([LinkAnalysis])
        case noLinks
        case failed
    }

    var state: State = .loading

    func load(from context: NSExtensionContext?) async {
        let text = await Self.collectText(from: context)
        guard let analyzer = try? LinkAnalyzer() else {
            state = .failed
            return
        }
        let results = analyzer.analyze(text: text)
            .sorted { $0.level.severity > $1.level.severity }
        state = results.isEmpty ? .noLinks : .results(results)
    }

    /// Collects the shared text and URLs into one string.
    static func collectText(from context: NSExtensionContext?) async -> String {
        var parts: [String] = []
        let items = context?.inputItems as? [NSExtensionItem] ?? []

        for item in items {
            if let text = item.attributedContentText?.string, !text.isEmpty {
                parts.append(text)
            }
            // Plain text first: asking some apps (like Notes in "Share a Link" mode)
            // for a URL makes them create an iCloud link, which can fail or hang.
            for provider in item.attachments ?? []
            where provider.hasItemConformingToTypeIdentifier(UTType.plainText.identifier) {
                if let text = try? await provider.loadItem(forTypeIdentifier: UTType.plainText.identifier) as? String,
                   !text.isEmpty {
                    parts.append(text)
                }
            }
        }
        if !parts.isEmpty { return parts.joined(separator: "\n") }

        // No text at all: fall back to a shared web link (e.g. from Safari).
        for item in items {
            for provider in item.attachments ?? []
            where provider.hasItemConformingToTypeIdentifier(UTType.url.identifier) {
                if let url = try? await provider.loadItem(forTypeIdentifier: UTType.url.identifier) as? URL,
                   url.scheme == "http" || url.scheme == "https" {
                    parts.append(url.absoluteString)
                }
            }
        }
        return parts.joined(separator: "\n")
    }
}

// MARK: - View

struct ShareResultView: View {
    let model: ShareModel
    let onClose: () -> Void

    private var lang: Bundle { LanguageSettings.shared.bundle }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    switch model.state {
                    case .loading:
                        ProgressView()
                            .frame(maxWidth: .infinity)
                            .padding(.top, 40)

                    case .noLinks:
                        ContentUnavailableView {
                            Label {
                                Text("No links found", bundle: lang)
                            } icon: {
                                Image(systemName: "link")
                            }
                        } description: {
                            Text("This text doesn't contain any web links.", bundle: lang)
                        }

                    case .failed:
                        Text("The detection model could not be loaded.", bundle: lang)
                            .foregroundStyle(.red)

                    case .results(let results):
                        ForEach(results) { analysis in
                            ResultCard(analysis: analysis)
                        }
                    }
                }
                .padding()
            }
            .navigationTitle("URLShield")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button {
                        onClose()
                    } label: {
                        Text("Done", bundle: lang)
                    }
                }
            }
        }
        .environment(\.locale, LanguageSettings.shared.locale)
    }
}
