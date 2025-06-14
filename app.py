# Flask ve ihtiyacımız olan kütüphaneleri içe aktarıyoruz
from flask import Flask, render_template, request, redirect, session
import sqlite3
import bcrypt

# Flask uygulamasını başlatıyoruz
app = Flask(__name__)
app.secret_key = "gizli_anahtar"  # oturum (session) için gizli anahtar

# Veritabanına bağlan fonksiyonu
def baglan():
    return sqlite3.connect("kullanicilar.db")

# Kullanıcılar tablosunu oluştur
def tablo_olustur():
    conn = baglan()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS kullanicilar (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kullanici_adi TEXT NOT NULL UNIQUE,
            sifre BLOB NOT NULL
        )
    """)
    conn.commit()
    conn.close()

# Ana sayfa / Giriş ekranı
@app.route("/", methods=["GET", "POST"])
def giris():
    mesaj = request.args.get("kayit")  # Kayıttan sonra mesaj göstermek için (login.html içinde)

    if request.method == "POST":
        # Kullanıcıdan gelen verileri al
        kullanici = request.form["kullanici_adi"]
        sifre = request.form["sifre"].encode("utf-8")  # Şifreyi byte türüne çevir

        # Veritabanına bağlan ve kullanıcıyı sorgula
        conn = baglan()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM kullanicilar WHERE kullanici_adi=?", (kullanici,))
        sonuc = cursor.fetchone()  # Kullanıcı bulunduysa satır olarak gelir
        conn.close()

        # Kullanıcı varsa ve şifre doğruysa giriş başarılı
        if sonuc and bcrypt.checkpw(sifre, sonuc[2]):
            session["kullanici"] = kullanici  # Oturum başlatılır

            # Eğer giriş yapan admin ise admin paneline yönlendir
            if kullanici == "admin":
                return redirect("/admin")
            else:
                return redirect("/panel")  # Diğer kullanıcılar için normal panel

        else:
            return "❌ Hatalı giriş yaptın. Lütfen tekrar dene."

    # GET isteğiyle gelindiyse sadece login sayfası gösterilir
    return render_template("login.html", mesaj=mesaj)


# Kayıt olma sayfası
@app.route("/kayit", methods=["GET", "POST"])
def kayit():
    if request.method == "POST":
        kullanici = request.form["kullanici_adi"]
        sifre = request.form["sifre"].encode("utf-8")

        # Şifreyi hashliyoruz
        sifreli = bcrypt.hashpw(sifre, bcrypt.gensalt())

        conn = baglan()
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO kullanicilar (kullanici_adi, sifre) VALUES (?, ?)", (kullanici, sifreli))
            conn.commit()
        except sqlite3.IntegrityError:
            return "⚠️ Bu kullanıcı zaten var!"
        conn.close()
        return redirect("/?kayit=basarili")

    return render_template("kayit.html")

# Admin paneli - sadece "admin" girerse görülür
@app.route("/admin")
def admin_panel():
    if "kullanici" not in session:
        return redirect("/")
    if session["kullanici"] != "admin":
        return "❌ Bu sayfa sadece admin'e aittir."

    conn = baglan()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM kullanicilar")
    kullanicilar = cursor.fetchall()
    conn.close()

    return render_template("admin.html", kullanicilar=kullanicilar)

# Kullanıcı paneli (admin olmayanlar için)
@app.route("/panel")
def panel():
    if "kullanici" in session:
        return render_template("panel.html", kullanici=session["kullanici"])
    else:
        return redirect("/")

# Kullanıcı çıkış (logout)
@app.route("/logout", methods=["POST"])
def logout():
    session.pop("kullanici", None)
    return redirect("/")

# Kullanıcı silme (admin panelinden)
@app.route("/sil/<int:id>", methods=["POST"])
def kullanici_sil(id):
    if "kullanici" not in session or session["kullanici"] != "admin":
        return redirect("/")

    conn = baglan()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM kullanicilar WHERE id = ?", (id,))
    conn.commit()
    conn.close()

    return redirect("/admin")

# Uygulamayı başlat
if __name__ == "__main__":
    tablo_olustur()  # veritabanı hazırla
    app.run(debug=True)