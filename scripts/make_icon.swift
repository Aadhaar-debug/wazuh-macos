// Renders the 1024x1024 app icon from scripts/assets/logo.json (vector geometry fitted from
// logo-source.png by fit_logo.swift): white macOS-style tile, logo centered.
// Usage: swift make_icon.swift <logo.json> <out.png>
import AppKit

let a = CommandLine.arguments
let spec = try! JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: a[1]))) as! [String: Any]
let poly = (spec["w_polygon"] as! [[Double]]).map { CGPoint(x: $0[0], y: $0[1]) }
let dotSpec = spec["dot"] as! [String: Any]
let dot = (x: dotSpec["cx"] as! Double, y: dotSpec["cy"] as! Double, r: dotSpec["r"] as! Double)
let source = (spec["source"] as! [String: Any])["width"] as! Double

func color(_ hex: String) -> NSColor {
    let v = Int(hex.dropFirst(), radix: 16)!
    return NSColor(srgbRed: CGFloat((v >> 16) & 0xFF) / 255, green: CGFloat((v >> 8) & 0xFF) / 255,
                   blue: CGFloat(v & 0xFF) / 255, alpha: 1)
}

let size: CGFloat = 1024
let tileInset: CGFloat = 100                       // Apple icon grid: 824pt tile on a 1024 canvas
let tile = CGRect(x: tileInset, y: tileInset, width: size - 2 * tileInset, height: size - 2 * tileInset)

// Logo bounds (w polygon ∪ dot) in source pixels, y down.
let minX = min(poly.map(\.x).min()!, dot.x - dot.r), maxX = max(poly.map(\.x).max()!, dot.x + dot.r)
let minY = min(poly.map(\.y).min()!, dot.y - dot.r), maxY = max(poly.map(\.y).max()!, dot.y + dot.r)
let center = CGPoint(x: (minX + maxX) / 2, y: (minY + maxY) / 2)
let scale = tile.width / source                     // same logo-to-tile proportion as the source image
func map(_ p: CGPoint) -> CGPoint {                 // source (y down) → icon (y up), logo centered on tile
    CGPoint(x: tile.midX + (p.x - center.x) * scale, y: tile.midY - (p.y - center.y) * scale)
}

let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(size), pixelsHigh: Int(size), bitsPerSample: 8,
                           samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                           bytesPerRow: 0, bitsPerPixel: 0)!
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
NSGraphicsContext.current!.shouldAntialias = true

// Tile with a soft drop shadow, like system icons.
let tilePath = NSBezierPath(roundedRect: tile, xRadius: 185, yRadius: 185)
NSGraphicsContext.saveGraphicsState()
let shadow = NSShadow()
shadow.shadowColor = NSColor.black.withAlphaComponent(0.28)
shadow.shadowOffset = NSSize(width: 0, height: -12)
shadow.shadowBlurRadius = 24
shadow.set()
NSColor.white.setFill()
tilePath.fill()
NSGraphicsContext.restoreGraphicsState()
NSColor.black.withAlphaComponent(0.08).setStroke()
tilePath.lineWidth = 2
tilePath.stroke()

// "w"
let w = NSBezierPath()
w.move(to: map(poly[0]))
for p in poly.dropFirst() { w.line(to: map(p)) }
w.close()
color(spec["w_color"] as! String).setFill()
w.fill()

// Dot
let c = map(CGPoint(x: dot.x, y: dot.y)), r = dot.r * scale
color(dotSpec["color"] as! String).setFill()
NSBezierPath(ovalIn: CGRect(x: c.x - r, y: c.y - r, width: 2 * r, height: 2 * r)).fill()

NSGraphicsContext.restoreGraphicsState()
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: a[2]))

let lx = map(CGPoint(x: minX, y: 0)).x, rx = map(CGPoint(x: maxX, y: 0)).x
let ty = map(CGPoint(x: 0, y: minY)).y, by = map(CGPoint(x: 0, y: maxY)).y
print(String(format: "logo on tile: left margin %.1f, right %.1f, top %.1f, bottom %.1f",
             lx - tile.minX, tile.maxX - rx, tile.maxY - ty, by - tile.minY))
