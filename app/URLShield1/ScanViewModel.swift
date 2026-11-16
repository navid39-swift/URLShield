//
//  ScanViewModel.swift
//  URLShield1
//

import Foundation
import Observation
import UIKit

/// Holds the screen's state and talks to the LinkAnalyzer.
@Observable
final class ScanViewModel {

    var inputText = ""
    var results: [LinkAnalysis] = []
    var hasScanned = false
    var errorMessage: String?

    /// True when the clipboard probably contains a web link.
    /// Detected without reading the clipboard, so iOS shows no paste prompt.
    var clipboardHasLink = false

    private let analyzer: LinkAnalyzer?

    init() {
        do {
            analyzer = try LinkAnalyzer()
        } catch {
            analyzer = nil
            errorMessage = String(localized: "The detection model could not be loaded.", bundle: LanguageSettings.shared.bundle)
        }
    }

    func scan() {
        guard let analyzer else { return }
        results = analyzer.analyze(text: inputText)
            .sorted { $0.level.severity > $1.level.severity }
        hasScanned = true
        clipboardHasLink = false
    }

    func clear() {
        inputText = ""
        results = []
        hasScanned = false
    }

    /// Checks whether the clipboard looks like it holds a link,
    /// without reading its content.
    func refreshClipboardHint() {
        let pasteboard = UIPasteboard.general
        guard pasteboard.hasStrings else {
            clipboardHasLink = false
            return
        }
        pasteboard.detectPatterns(for: [.probableWebURL]) { [weak self] result in
            let found = (try? result.get())?.contains(.probableWebURL) ?? false
            Task { @MainActor in
                self?.clipboardHasLink = found
            }
        }
    }
}
