//
//  ResultCard.swift
//  URLShield1
//

import SwiftUI

/// One analyzed link.
struct ResultCard: View {
    let analysis: LinkAnalysis

    private var lang: Bundle { LanguageSettings.shared.bundle }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {

            Label(analysis.level.title, systemImage: analysis.level.systemImage)
                .font(.headline)
                .foregroundStyle(analysis.level.color)

            // The real domain, big and clear
            Text(analysis.host)
                .font(.title2.monospaced().bold())
                .textSelection(.enabled)

            Text(analysis.level.explanation)
                .font(.subheadline)

            if !analysis.redFlags.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(analysis.redFlags, id: \.self) { flag in
                        Label(flag.message, systemImage: flag.isStrong ? "exclamationmark.circle.fill" : "info.circle")
                            .font(.subheadline)
                    }
                }
            }

            if let p = analysis.phishingProbability {
                let percent = p.formatted(
                    .percent.precision(.fractionLength(0)).locale(LanguageSettings.shared.locale)
                )
                Text("Model score: \(percent) phishing likelihood", bundle: lang)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }

            Text("Link in message: \(analysis.link)", bundle: lang)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(2)
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(analysis.level.color.opacity(0.08))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 16)
                .stroke(analysis.level.color.opacity(0.4), lineWidth: 1)
        )
        .accessibilityElement(children: .combine)
    }
}
