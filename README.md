# CyberFi Releases

CyberFi’ın Windows ve macOS dağıtım deposu.

- [Windows x64 — 0.0.126](https://github.com/CyberfiTechh/CyberFi-Releases/releases/tag/v0.0.126)
- [macOS Intel — 0.0.126 DMG](https://github.com/CyberfiTechh/CyberFi-Releases/releases/download/macos-v0.0.126/CyberFi-0.0.126-x64.dmg)
- [macOS Apple Silicon — 0.0.126 DMG](https://github.com/CyberfiTechh/CyberFi-Releases/releases/download/macos-v0.0.126/CyberFi-0.0.126-arm64.dmg)
- [Kararlı ajan motoru — 0.4.119](https://github.com/CyberfiTechh/CyberFi-Engine/releases/tag/v0.4.119)
- [CyberFi hesap yönetimi](https://pdrkocum.com/cyberai/)
- [Doğrulananlar ve sınırlar](audit/0.0.126.md)

Windows ve macOS 0.0.126 paketleri yayımlandı. Intel ve Apple Silicon Mac’te 125 → 126 otomatik indirme, kurulum, açılış ve profil koruma testleri geçti. Windows’ta kurulum ve otomatik yeni süreç gözlendi; gizli test penceresi kuralı nedeniyle sonraki giriş/profil kabulü tamamlanamadı. Önceki 0.0.125 paketleri korunuyor.

Bu sürüm MCP sunucularının teknik kimlikleri ile görünen adlarını doğru eşleştirir. Hesabı tanımlı olmayan arama hizmetleri “kullanılamıyor; arama yapılmadı” bilgisi verir; gerçek bağlantı ve izin hataları görünür kalır. Python ve dosya arama aracı, doğrulanan bağımsız paketlerle arka planda hazırlanır. Bu düzeltmeler için ajan motorunu da 0.4.119’a güncelleyin.

Uygulama **Ayarlar → Genel → Masaüstü uygulaması** bölümünde sürümleri ve indirme ilerlemesini gösterir. “Beni hatırla” oturum anahtarını işletim sisteminin güvenli deposuyla şifreler; şifrenizi dosyaya yazmaz. Windows, Intel Mac ve Apple Silicon Mac’te gerçek giriş, oturumu hatırlama, yeniden açılış ve çıkış kontrolleri geçti.

Masaüstü paketleri önizlemedir. Windows kurucusu yerel CyberFi sertifikasıyla imzalanır; Windows güven uyarısı gösterebilir. Windows ajan motoru imzasızdır. Mac paketleri ve motorları ad hoc imzalıdır; Apple Developer ID ve noter onayı yoktur. macOS güvenlik denetimleri kapatılmaz.

Her paketin `.sha256` dosyası bütünlük özeti, `.update.json` dosyası CyberFi güncelleme imza bildirimidir. Bu bildirim işletim sisteminin dağıtım güvenini veya Apple noter onayını temsil etmez.

CyberFi, MIT lisanslı [Happy Desktop](https://github.com/slopus/happy-desktop) projesini temel alır. [Özgün lisans ve telif bildirimi](LICENSE-Happy-Desktop.txt) kurulum paketinde de yer alır.
