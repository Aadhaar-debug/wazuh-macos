// Renders the app icon (1024x1024 PNG). Usage: swift make_icon.swift out.png
import AppKit

let size: CGFloat = 1024
let img = NSImage(size: NSSize(width: size, height: size))
img.lockFocus()
let ctx = NSGraphicsContext.current!.cgContext

// Rounded-square background with a blue gradient.
let inset: CGFloat = 100
let rect = CGRect(x: inset, y: inset, width: size - 2 * inset, height: size - 2 * inset)
let bg = NSBezierPath(roundedRect: rect, xRadius: 185, yRadius: 185)
ctx.saveGState()
bg.addClip()
let grad = NSGradient(colors: [NSColor(red: 0.16, green: 0.30, blue: 0.86, alpha: 1),
                               NSColor(red: 0.30, green: 0.52, blue: 1.00, alpha: 1)])!
grad.draw(in: rect, angle: 90)
ctx.restoreGState()

// Shield glyph.
let cx = size / 2
let top: CGFloat = 790, bottom: CGFloat = 220, half: CGFloat = 230
let shield = NSBezierPath()
shield.move(to: NSPoint(x: cx, y: top))
shield.curve(to: NSPoint(x: cx + half, y: top - 70), controlPoint1: NSPoint(x: cx + 90, y: top - 45), controlPoint2: NSPoint(x: cx + 170, y: top - 60))
shield.curve(to: NSPoint(x: cx, y: bottom), controlPoint1: NSPoint(x: cx + half, y: 450), controlPoint2: NSPoint(x: cx + 150, y: 300))
shield.curve(to: NSPoint(x: cx - half, y: top - 70), controlPoint1: NSPoint(x: cx - 150, y: 300), controlPoint2: NSPoint(x: cx - half, y: 450))
shield.curve(to: NSPoint(x: cx, y: top), controlPoint1: NSPoint(x: cx - 170, y: top - 60), controlPoint2: NSPoint(x: cx - 90, y: top - 45))
shield.close()
NSColor.white.setFill()
shield.fill()

// "W" monogram inside the shield.
let para = NSMutableParagraphStyle(); para.alignment = .center
let attrs: [NSAttributedString.Key: Any] = [
    .font: NSFont.systemFont(ofSize: 300, weight: .heavy),
    .foregroundColor: NSColor(red: 0.18, green: 0.34, blue: 0.90, alpha: 1),
    .paragraphStyle: para,
]
NSString(string: "W").draw(in: NSRect(x: 0, y: 330, width: size, height: 360), withAttributes: attrs)
img.unlockFocus()

let rep = NSBitmapImageRep(data: img.tiffRepresentation!)!
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
