//
//  ProtectionSetupView.swift
//  URLShield1
//
//  Lets the user choose where URLShield protects them.
//  iOS does not allow apps to enable extensions themselves,
//  so each card explains the steps and remembers the user's choice.
//

import SwiftUI
import UIKit

struct ProtectionSetupView: View {
    private var lang: Bundle { LanguageSettings.shared.bundle }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    Text("Choose where URLShield protects you. For your privacy, iOS lets only you turn these on.", bundle: lang)
                        .foregroundStyle(.secondary)

                    SetupCard(
                        icon: "message.fill",
                        title: "Messages (SMS)",
                        subtitle: "Automatically moves SMS with dangerous links from unknown senders to Junk.",
                        steps: [
                            "Open Settings, then Apps, then Messages.",
                            "Turn on “Screen Unknown Senders”.",
                            "Tap “Text Message Filter” and choose URLShield.",
                        ],
                        note: "Works only for senders who are not in your contacts. Screening also moves messages from unknown senders to a separate list in Messages.",
                        showsSettingsButton: true
                    )

                    SetupCard(
                        icon: "square.and.arrow.up",
                        title: "Safari, Mail, WhatsApp and other apps",
                        subtitle: "Check any link or text with the Share button, without leaving the app you are in.",
                        steps: [
                            "In any app, tap Share (or long-press a link, then Share).",
                            "Swipe the row of apps to the end and tap More.",
                            "Turn on URLShield, then tap Done.",
                        ],
                        note: nil,
                        showsSettingsButton: false
                    )

                    Label {
                        Text("Everything stays on your iPhone. Nothing you check is sent anywhere.", bundle: lang)
                    } icon: {
                        Image(systemName: "lock.shield")
                    }
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                }
                .padding()
            }
            .background(Brand.background)
            .navigationTitle(Text("Protection", bundle: lang))
        }
    }
}

private struct SetupCard: View {
    let icon: String
    let title: LocalizedStringKey
    let subtitle: LocalizedStringKey
    let steps: [LocalizedStringKey]
    let note: LocalizedStringKey?
    let showsSettingsButton: Bool

    @Environment(\.openURL) private var openURL
    private var lang: Bundle { LanguageSettings.shared.bundle }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                Image(systemName: icon)
                    .foregroundStyle(.tint)
                Text(title, bundle: lang)
                    .font(.headline)
            }

            Text(subtitle, bundle: lang)
                .font(.subheadline)

            VStack(alignment: .leading, spacing: 6) {
                ForEach(Array(steps.enumerated()), id: \.offset) { index, step in
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Text(verbatim: "\(index + 1).")
                            .bold()
                        Text(step, bundle: lang)
                    }
                    .font(.subheadline)
                }
            }

            if let note {
                Text(note, bundle: lang)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }

            if showsSettingsButton {
                Button {
                    if let url = URL(string: UIApplication.openSettingsURLString) {
                        openURL(url)
                    }
                } label: {
                    Text("Open Settings", bundle: lang)
                }
                .buttonStyle(.bordered)
            }
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(Brand.surface)
        )
    }
}

#Preview {
    ProtectionSetupView()
}
