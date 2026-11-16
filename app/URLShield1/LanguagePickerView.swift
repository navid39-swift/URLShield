//
//  LanguagePickerView.swift
//  URLShield1
//
//  First screen on first launch.
//

import SwiftUI

struct LanguagePickerView: View {
    let onDone: () -> Void
    private let settings = LanguageSettings.shared

    var body: some View {
        VStack(spacing: 28) {
            Spacer()

            Image(systemName: "globe")
                .font(.system(size: 56))
                .foregroundStyle(.tint)

            Text(verbatim: "Choose your language\nScegli la lingua")
                .font(.title2.bold())
                .multilineTextAlignment(.center)

            VStack(spacing: 12) {
                ForEach(LanguageSettings.Language.allCases) { language in
                    Button {
                        settings.setLanguage(language)
                        settings.markChosen()
                        onDone()
                    } label: {
                        Text(verbatim: language.nativeName)
                            .font(.title3.weight(.semibold))
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 6)
                    }
                    .buttonStyle(.borderedProminent)
                }
            }

            Text(verbatim: "You can change it later in Info (ⓘ).\nPuoi cambiarla in seguito da Info (ⓘ).")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            Spacer()
        }
        .padding(24)
        .interactiveDismissDisabled()
    }
}

#Preview {
    LanguagePickerView { }
}
