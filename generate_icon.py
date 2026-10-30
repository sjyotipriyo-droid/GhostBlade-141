import sys
from pathlib import Path
from PySide6.QtGui import QGuiApplication, QImage, QPainter, QColor, QPolygon, QPen, QFont, QLinearGradient
from PySide6.QtCore import Qt, QPoint, QRect

def build_luxury_icon():
    app = QGuiApplication(sys.argv)
    size = 256
    img = QImage(size, size, QImage.Format_ARGB32)
    img.fill(Qt.transparent)

    p = QPainter(img)
    p.setRenderHint(QPainter.Antialiasing, True)

    # 1. Outer Champagne Gold Hexagonal Shield
    gold_grad = QLinearGradient(0, 0, size, size)
    gold_grad.setColorAt(0.0, QColor("#E5C158"))
    gold_grad.setColorAt(0.5, QColor("#C5A059"))
    gold_grad.setColorAt(1.0, QColor("#8A6B2F"))

    outer_hex = QPolygon([
        QPoint(128, 10), QPoint(234, 66), QPoint(234, 190),
        QPoint(128, 246), QPoint(22, 190), QPoint(22, 66)
    ])
    p.setBrush(gold_grad)
    p.setPen(QPen(QColor("#FFF3D1"), 3))
    p.drawPolygon(outer_hex)

    # 2. Inner Deep Obsidian Core
    obsidian_grad = QLinearGradient(0, 20, 0, 236)
    obsidian_grad.setColorAt(0.0, QColor("#16181E"))
    obsidian_grad.setColorAt(1.0, QColor("#090A0D"))

    inner_hex = QPolygon([
        QPoint(128, 24), QPoint(220, 74), QPoint(220, 182),
        QPoint(128, 232), QPoint(36, 182), QPoint(36, 74)
    ])
    p.setBrush(obsidian_grad)
    p.setPen(QPen(QColor("#2E323D"), 2))
    p.drawPolygon(inner_hex)

    # 3. Crossed Tactical Katana Blades
    blade_pen = QPen(QColor(197, 160, 89, 75), 8, Qt.SolidLine, Qt.RoundCap)
    p.setPen(blade_pen)
    p.drawLine(64, 188, 192, 68)
    p.drawLine(64, 68, 192, 188)

    # 4. Crisp "GB" Monogram & "141" Badge
    p.setPen(QColor("#F4F4F6"))
    f_main = QFont("Segoe UI", 64, QFont.Weight.Black)
    p.setFont(f_main)
    p.drawText(QRect(0, 42, size, 110), Qt.AlignCenter, "GB")

    p.setPen(QColor("#C5A059"))
    f_sub = QFont("Consolas", 28, QFont.Weight.Bold)
    p.setFont(f_sub)
    p.drawText(QRect(0, 142, size, 60), Qt.AlignCenter, "// 141")

    p.end()

    out_dir = Path("assets")
    out_dir.mkdir(exist_ok=True)
    ico_path = out_dir / "ghostblade.ico"
    img.save(str(ico_path), "ICO")
    print(f"[+] Successfully generated luxury icon: {ico_path.resolve()}")

if __name__ == "__main__":
    build_luxury_icon()
