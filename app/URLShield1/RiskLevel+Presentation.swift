//
//  RiskLevel+Presentation.swift
//  URLShield1
//
//  Created by navid zare on 15/10/2026.
//

import SwiftUI

/// How each level looks and what it tells the user.
extension RiskLevel {

    var title: String {
        switch self {
        case .likelyPhishing:    String(localized: "Likely phishing", bundle: LanguageSettings.shared.bundle)
        case .suspicious:        String(localized: "Suspicious", bundle: LanguageSettings.shared.bundle)
        case .noRedFlags:        String(localized: "No red flags found", bundle: LanguageSettings.shared.bundle)
        case .knownSite:         String(localized: "Known site", bundle: LanguageSettings.shared.bundle)
        case .hiddenDestination: String(localized: "Hidden destination", bundle: LanguageSettings.shared.bundle)
        case .openPlatform:      String(localized: "Open platform", bundle: LanguageSettings.shared.bundle)
        }
    }

    var systemImage: String {
        switch self {
        case .likelyPhishing:    "xmark.octagon.fill"
        case .suspicious:        "exclamationmark.triangle.fill"
        case .noRedFlags:        "checkmark.circle"
        case .knownSite:         "checkmark.seal.fill"
        case .hiddenDestination: "eye.slash.fill"
        case .openPlatform:      "person.2.fill"
        }
    }

    var color: Color {
        switch self {
        case .likelyPhishing:                     .red
        case .suspicious, .hiddenDestination,
             .openPlatform:                       .orange
        case .noRedFlags:                         .blue
        case .knownSite:                          .green
        }
    }

    var explanation: String {
        switch self {
        case .likelyPhishing:
            String(localized: "Don't open this link and don't enter any personal information.", bundle: LanguageSettings.shared.bundle)
        case .suspicious:
            String(localized: "Be careful. If the message claims to be from a company, contact it through its official app or website instead.", bundle: LanguageSettings.shared.bundle)
        case .noRedFlags:
            String(localized: "We found no warning signs, but no tool can guarantee that a link is safe.", bundle: LanguageSettings.shared.bundle)
        case .knownSite:
            String(localized: "This is the official domain of a well-known website. Check that the domain below is exactly the one you expect.", bundle: LanguageSettings.shared.bundle)
        case .hiddenDestination:
            String(localized: "This is a shortened link. Its real destination can't be seen without opening it.", bundle: LanguageSettings.shared.bundle)
        case .openPlatform:
            String(localized: "Anyone can publish pages on this platform, so the domain alone can't tell whether this page is safe.", bundle: LanguageSettings.shared.bundle)
        }
    }

    /// Used to show the most dangerous link first.
    var severity: Int {
        switch self {
        case .likelyPhishing:                        5
        case .suspicious:                            4
        case .hiddenDestination, .openPlatform:      3
        case .noRedFlags:                            1
        case .knownSite:                             0
        }
    }
}
