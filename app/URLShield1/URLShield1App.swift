//
//  URLShield1App.swift
//  URLShield1
//

import SwiftUI

@main
struct URLShield1App: App {
    @State private var language = LanguageSettings.shared

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(\.locale, language.locale)
        }
    }
}
