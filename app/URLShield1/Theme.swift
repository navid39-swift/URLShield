//
//  Theme.swift
//  URLShield1
//
//  The pangolin brand: navy night, bronze scales, warm sand.
//  Safety colors (red / orange / green) stay standard on purpose:
//  a warning must never look like decoration.
//

import SwiftUI
import UIKit

enum Brand {
    /// Deep navy - the night the pangolin hunts in.
    static let navy = Color(red: 0.078, green: 0.129, blue: 0.239)          // #14213D
    /// Bronze - the scales. Used for buttons, tabs and highlights.
    static let bronze = Color(red: 0.784, green: 0.529, blue: 0.227)        // #C8873A
    static let bronzeLight = Color(red: 0.929, green: 0.722, blue: 0.400)   // #EDB866

    /// Tint for buttons and tabs: darker bronze in light mode so white text stays readable.
    static let accent = Color(UIColor { trait in
        trait.userInterfaceStyle == .dark
            ? UIColor(red: 0.784, green: 0.529, blue: 0.227, alpha: 1)      // #C8873A
            : UIColor(red: 0.612, green: 0.353, blue: 0.102, alpha: 1)      // #9C5A1A
    })

    /// Page background: warm sand in light mode, navy in dark mode.
    static let background = Color(UIColor { trait in
        trait.userInterfaceStyle == .dark
            ? UIColor(red: 0.051, green: 0.090, blue: 0.188, alpha: 1)      // #0D1730
            : UIColor(red: 0.973, green: 0.949, blue: 0.914, alpha: 1)      // #F8F2E9
    })

    /// Cards and the text field.
    static let surface = Color(UIColor { trait in
        trait.userInterfaceStyle == .dark
            ? UIColor(red: 0.098, green: 0.153, blue: 0.290, alpha: 1)      // #19274A
            : UIColor.white
    })
}

// MARK: - Scale pattern

/// One pangolin scale: rounded back, pointed tip (it looks like a small shield).
struct ScaleShape: Shape {
    func path(in rect: CGRect) -> Path {
        let w = rect.width / 2, h = rect.height
        let cx = rect.midX, top = rect.minY + h * 0.35
        var p = Path()
        p.move(to: CGPoint(x: cx - w, y: top))
        p.addCurve(to: CGPoint(x: cx + w, y: top),
                   control1: CGPoint(x: cx - w, y: rect.minY - h * 0.05),
                   control2: CGPoint(x: cx + w, y: rect.minY - h * 0.05))
        p.addCurve(to: CGPoint(x: cx, y: rect.maxY),
                   control1: CGPoint(x: cx + w, y: top + h * 0.3),
                   control2: CGPoint(x: cx + w * 0.3, y: rect.maxY - h * 0.1))
        p.addCurve(to: CGPoint(x: cx - w, y: top),
                   control1: CGPoint(x: cx - w * 0.3, y: rect.maxY - h * 0.1),
                   control2: CGPoint(x: cx - w, y: top + h * 0.3))
        p.closeSubpath()
        return p
    }
}

/// Overlapping rows of scales, like the pangolin's armor.
struct ScalePattern: View {
    var scaleWidth: CGFloat = 26
    var color: Color = Brand.bronze

    var body: some View {
        Canvas { context, size in
            let w = scaleWidth, h = scaleWidth * 1.3
            let rowStep = h * 0.62
            let rows = Int(size.height / rowStep) + 2
            let cols = Int(size.width / w) + 2
            // Bottom rows first, so every scale's tip lies over the row below.
            for row in stride(from: rows, through: -1, by: -1) {
                let shift = row.isMultiple(of: 2) ? 0 : w / 2
                for col in -1...cols {
                    let rect = CGRect(x: CGFloat(col) * w + shift - w / 2,
                                      y: CGFloat(row) * rowStep - h / 2,
                                      width: w * 0.96, height: h)
                    let path = ScaleShape().path(in: rect)
                    context.fill(path, with: .color(color.opacity(0.18 + 0.05 * Double(row % 3))))
                    context.stroke(path, with: .color(Brand.navy.opacity(0.55)), lineWidth: 1.2)
                }
            }
        }
        .accessibilityHidden(true)
    }
}

// MARK: - Header

/// The navy banner with the pangolin at the top of the Check screen.
struct BrandHeader: View {
    private var lang: Bundle { LanguageSettings.shared.bundle }

    var body: some View {
        HStack(alignment: .center, spacing: 14) {
            VStack(alignment: .leading, spacing: 6) {
                Text("Check before you tap.", bundle: lang)
                    .font(.title3.weight(.bold))
                    .foregroundStyle(.white)
                Text("Paste a message, an email or a link. URLShield checks every link on your iPhone, without opening it.", bundle: lang)
                    .font(.subheadline)
                    .foregroundStyle(.white.opacity(0.8))
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
            Image("PangolinMark")
                .resizable()
                .scaledToFit()
                .frame(width: 96)
                .accessibilityHidden(true)
        }
        .padding(16)
        .background {
            ZStack {
                Brand.navy
                ScalePattern(scaleWidth: 22, color: Brand.bronze)
                    .opacity(0.35)
                    .mask(LinearGradient(colors: [.clear, .black], startPoint: .leading, endPoint: .trailing))
            }
        }
        .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
    }
}

#Preview {
    VStack(spacing: 20) {
        BrandHeader()
        ScalePattern().frame(height: 120)
    }
    .padding()
    .background(Brand.background)
}
