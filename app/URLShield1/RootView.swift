//
//  RootView.swift
//  URLShield1
//

import SwiftUI

struct RootView: View {
    private var lang: Bundle { LanguageSettings.shared.bundle }

    var body: some View {
        TabView {
            ContentView()
                .tabItem {
                    Label {
                        Text("Check", bundle: lang)
                    } icon: {
                        Image(systemName: "shield.lefthalf.filled")
                    }
                }

            ProtectionSetupView()
                .tabItem {
                    Label {
                        Text("Protection", bundle: lang)
                    } icon: {
                        Image(systemName: "checkmark.shield")
                    }
                }

            SpotTheFakeView()
                .tabItem {
                    Label {
                        Text("Spot the fake", bundle: lang)
                    } icon: {
                        Image(systemName: "graduationcap")
                    }
                }
        }
        .tint(Brand.accent)
        .task {
            await ModelUpdater.checkIfDue()
        }
    }
}
