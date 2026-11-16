//
//  LanguageSettings.swift
//  URLShield1
//
//  Lets the user choose the app language inside the app,
//  independently of the iPhone's language.
//

import Foundation
import Observation

@Observable
final class LanguageSettings {

    static let shared = LanguageSettings()

    enum Language: String, CaseIterable, Identifiable {
        case english = "en"
        case italian = "it"

        var id: String { rawValue }

        /// Always shown in its own language.
        var nativeName: String {
            switch self {
            case .english: "English"
            case .italian: "Italiano"
            }
        }
    }

    private(set) var language: Language
    /// The translation bundle used by every Text and String(localized:) in the app.
    private(set) var bundle: Bundle
    private(set) var hasChosen: Bool

    var locale: Locale { Locale(identifier: language.rawValue) }

    /// Shared with the Share and Message Filter extensions once the
    /// App Group "group.com.navidzare.URLShield1" is enabled for all targets.
    /// Without the App Group this still works, just not shared.
    static let defaults = UserDefaults(suiteName: "group.com.navidzare.URLShield1") ?? .standard

    private static let languageKey = "appLanguage"
    private static let chosenKey = "hasChosenLanguage"

    private init() {
        let saved = Self.defaults.string(forKey: Self.languageKey)
            .flatMap(Language.init(rawValue:))
        let deviceIsItalian = Locale.preferredLanguages.first?.hasPrefix("it") ?? false
        let initial = saved ?? (deviceIsItalian ? .italian : .english)

        language = initial
        bundle = Self.bundle(for: initial)
        hasChosen = Self.defaults.bool(forKey: Self.chosenKey)
    }

    func setLanguage(_ newLanguage: Language) {
        language = newLanguage
        bundle = Self.bundle(for: newLanguage)
        Self.defaults.set(newLanguage.rawValue, forKey: Self.languageKey)
    }

    func markChosen() {
        hasChosen = true
        Self.defaults.set(true, forKey: Self.chosenKey)
    }

    private static func bundle(for language: Language) -> Bundle {
        if let path = Bundle.main.path(forResource: language.rawValue, ofType: "lproj"),
           let bundle = Bundle(path: path) {
            return bundle
        }
        return .main
    }
}
