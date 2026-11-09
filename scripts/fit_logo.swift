// Fits the logo in logo-source.png as exact geometry: the "w" as a 13-point polygon built from 8
// least-squares edge lines (sub-pixel, from anti-aliasing), the dot as a circle (area + centroid).
// Usage: swift fit_logo.swift <logo-source.png> <out.json>
import AppKit

let a = CommandLine.arguments
let img = NSBitmapImageRep(data: try! Data(contentsOf: URL(fileURLWithPath: a[1])))!
let W = img.pixelsWide, H = img.pixelsHigh

var dark = [[Double]](repeating: [Double](repeating: 0, count: W), count: H)   // coverage of black
var blue = [[Double]](repeating: [Double](repeating: 0, count: W), count: H)   // coverage of the dot
var blueRGB = (0.0, 0.0, 0.0, 0.0)
for y in 0..<H { for x in 0..<W {
    let c = img.colorAt(x: x, y: y)!.usingColorSpace(.sRGB)!
    let (r, g, b) = (Double(c.redComponent), Double(c.greenComponent), Double(c.blueComponent))
    if b > r + 0.15 {                         // bluish: dot (blended with white at its rim)
        let cov = min(1, max(0, (1 - r) / (1 - 0.0235)))  // dot red channel ≈ 0x06
        blue[y][x] = cov
        if cov > 0.95 { blueRGB = (blueRGB.0 + r, blueRGB.1 + g, blueRGB.2 + b, blueRGB.3 + 1) }
    } else {
        dark[y][x] = 1 - (0.299 * r + 0.587 * g + 0.114 * b)
    }
}}

// Per row: sub-pixel edges of each dark run.
func edges(_ y: Int) -> [Double] {
    var out: [Double] = []
    var x = 0
    let row = dark[y]
    while x < W {
        if row[x] > 0.5 {
            let xs = x
            while x < W && row[x] > 0.5 { x += 1 }
            let xe = x - 1
            out.append(Double(xs) - (xs > 0 ? row[xs - 1] : 0) + (1 - row[xs]) * 0 )
            out.append(Double(xe + 1) + (xe + 1 < W ? row[xe + 1] : 0))
        } else { x += 1 }
    }
    return out
}

// Rows where the four strokes are separate (8 edges) give all eight edge lines.
var samples = [[(Double, Double)]](repeating: [], count: 8)   // (y, x)
var top = Int.max, bottom = 0
for y in 0..<H {
    let e = edges(y)
    if !e.isEmpty { top = min(top, y); bottom = max(bottom, y) }
    if e.count == 8 { for i in 0..<8 { samples[i].append((Double(y) + 0.5, e[i])) } }
}
// Least squares x = m*y + c, skipping the 2 rows at each end of the band (corner influence).
func fit(_ s: [(Double, Double)]) -> (m: Double, c: Double) {
    let pts = s.count > 8 ? Array(s.dropFirst(2).dropLast(2)) : s
    let n = Double(pts.count)
    let sy = pts.reduce(0) { $0 + $1.0 }, sx = pts.reduce(0) { $0 + $1.1 }
    let syy = pts.reduce(0) { $0 + $1.0 * $1.0 }, syx = pts.reduce(0) { $0 + $1.0 * $1.1 }
    let m = (n * syx - sy * sx) / (n * syy - sy * sy)
    return (m, (sx - m * sy) / n)
}
let L = samples.map(fit)
// Sub-pixel top/bottom: partial coverage of the rows just outside the solid band, inside stroke 1.
func colCov(_ y: Int) -> Double {
    let x0 = Int(L[0].m * (Double(y) + 0.5) + L[0].c) + 2, x1 = Int(L[1].m * (Double(y) + 0.5) + L[1].c) - 2
    guard x1 > x0, y >= 0, y < H else { return 0 }
    return (x0...x1).reduce(0) { $0 + dark[y][$1] } / Double(x1 - x0 + 1)
}
let topY = Double(top) + 1 - colCov(top)
let botY = Double(bottom) + colCov(bottom)
func xAt(_ l: (m: Double, c: Double), _ y: Double) -> Double { l.m * y + l.c }
func cross(_ p: (m: Double, c: Double), _ q: (m: Double, c: Double)) -> (Double, Double) {
    let y = (q.c - p.c) / (p.m - q.m); return (xAt(p, y), y)
}
// S1L S1R S2L S2R S3L S3R S4L S4R = L[0...7]
let poly: [(Double, Double)] = [
    (xAt(L[0], topY), topY), (xAt(L[1], topY), topY), cross(L[1], L[2]),
    (xAt(L[2], topY), topY), (xAt(L[5], topY), topY), cross(L[5], L[6]),
    (xAt(L[6], topY), topY), (xAt(L[7], topY), topY),
    (xAt(L[7], botY), botY), (xAt(L[4], botY), botY), cross(L[3], L[4]),
    (xAt(L[3], botY), botY), (xAt(L[0], botY), botY),
]

var area = 0.0, mx = 0.0, my = 0.0
for y in 0..<H { for x in 0..<W where blue[y][x] > 0 {
    area += blue[y][x]; mx += blue[y][x] * (Double(x) + 0.5); my += blue[y][x] * (Double(y) + 0.5)
}}
let dot = (x: mx / area, y: my / area, r: (area / Double.pi).squareRoot())
let n = blueRGB.3
let hex = String(format: "#%02X%02X%02X", Int((blueRGB.0 / n * 255).rounded()), Int((blueRGB.1 / n * 255).rounded()), Int((blueRGB.2 / n * 255).rounded()))

let json: [String: Any] = [
    "source": ["width": W, "height": H],
    "w_polygon": poly.map { [($0.0 * 1000).rounded() / 1000, ($0.1 * 1000).rounded() / 1000] },
    "dot": ["cx": (dot.x * 1000).rounded() / 1000, "cy": (dot.y * 1000).rounded() / 1000, "r": (dot.r * 1000).rounded() / 1000, "color": hex],
    "w_color": "#000000",
]
try! JSONSerialization.data(withJSONObject: json, options: [.prettyPrinted, .sortedKeys]).write(to: URL(fileURLWithPath: a[2]))
print("rows with 8 edges:", samples[0].count, " top", topY, " bottom", botY)
print("slopes:", L.map { String(format: "%.3f", $0.m) }.joined(separator: " "))
print("dot", dot, hex)
