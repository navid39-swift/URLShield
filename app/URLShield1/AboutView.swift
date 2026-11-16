//
//  AboutView.swift
//  URLShield1
//
//  Shown on first launch and from the info button.
//

import SwiftUI

struct AboutView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var updateStatus: String?
    @State private var isChecking = false
    private let settings = LanguageSettings.shared
    private var lang: Bundle { settings.bundle }

    private var languageBinding: Binding<LanguageSettings.Language> {
        Binding(
            get: { settings.language },
            set: { settings.setLanguage($0) }
        )
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Picker(selection: languageBinding) {
                        ForEach(LanguageSettings.Language.allCases) { language in
                            Text(verbatim: language.nativeName).tag(language)
                        }
                    } label: {
                        Text("Language", bundle: lang)
                    }
                }

                Section {
                    row("Paste a message, an email or a link.", icon: "doc.on.clipboard")
                    row("URLShield finds every link and checks its real domain.", icon: "magnifyingglass")
                    row("A machine learning model and clear rules judge it, without opening the link.", icon: "cpu")
                } header: {
                    Text("How it works", bundle: lang)
                }

                Section {
                    row("Everything happens on your iPhone. Nothing you paste is sent anywhere.", icon: "lock.shield")
                    row("No account, no tracking, works offline.", icon: "wifi.slash")
                } header: {
                    Text("Your privacy", bundle: lang)
                }

                Section {
                    Text("No tool can guarantee that a link is safe. Hacked websites and brand-new tricks can look normal. When in doubt, contact the company through its official app or website.", bundle: lang)
                } header: {
                    Text("Limits", bundle: lang)
                }

                Section {
                    Text("Trained on 800,484 web addresses from three public sources: the PhiUSIIL research dataset (UCI, CC BY 4.0), Phishing.Database (© Mitchell Krog, MIT License) and the Tranco list of popular sites. On websites it had never seen, when it is very sure it catches about 6 phishing sites in 10, with about 1 false alarm per 1,000 normal sites.", bundle: lang)
                } header: {
                    Text("The model", bundle: lang)
                }

                Section {
                    LabeledContent {
                        Text(verbatim: appVersion)
                    } label: {
                        Text("Version", bundle: lang)
                    }
                    LabeledContent {
                        Text(verbatim: "\(ModelStore.currentVersion)")
                    } label: {
                        Text("Model version", bundle: lang)
                    }
                    Button {
                        Task { await checkForUpdates() }
                    } label: {
                        if isChecking {
                            ProgressView()
                        } else {
                            Text("Check for model updates", bundle: lang)
                        }
                    }
                    .disabled(isChecking)
                    if let updateStatus {
                        Text(updateStatus)
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                } footer: {
                    Text("Updates are only downloaded and verified on your iPhone. Nothing is uploaded.", bundle: lang)
                }
            }
            .navigationTitle(Text("About URLShield", bundle: lang))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button {
                        dismiss()
                    } label: {
                        Text("Done", bundle: lang)
                    }
                }
            }
        }
    }

    private func row(_ key: LocalizedStringKey, icon: String) -> some View {
        Label {
            Text(key, bundle: lang)
        } icon: {
            Image(systemName: icon)
        }
    }

    private func checkForUpdates() async {
        isChecking = true
        defer { isChecking = false }
        do {
            switch try await ModelUpdater.check() {
            case .upToDate:
                updateStatus = String(localized: "The model is up to date.", bundle: lang)
            case .updated(let version):
                updateStatus = String(localized: "Model version \(version) installed. It will be used the next time you open URLShield.", bundle: lang)
            case .notConfigured:
                updateStatus = String(localized: "Model updates are not available yet.", bundle: lang)
            }
        } catch {
            updateStatus = String(localized: "The update could not be verified or downloaded. Try again later.", bundle: lang)
        }
    }

    private var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0"
    }
}

#Preview {
    AboutView()
}
