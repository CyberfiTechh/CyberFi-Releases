# CyberFi Releases

CyberFi’nin Windows ve macOS dağıtım deposu.

- [Windows x64 — 0.0.128](https://github.com/CyberfiTechh/CyberFi-Releases/releases/tag/v0.0.128)
- [macOS Intel — 0.0.128 DMG](https://github.com/CyberfiTechh/CyberFi-Releases/releases/download/macos-v0.0.128/CyberFi-0.0.128-x64.dmg)
- [macOS Apple Silicon — 0.0.128 DMG](https://github.com/CyberfiTechh/CyberFi-Releases/releases/download/macos-v0.0.128/CyberFi-0.0.128-arm64.dmg)
- [Kararlı ajan motoru — 0.4.120](https://github.com/CyberfiTechh/CyberFi-Engine/releases/tag/v0.4.120)
- [CyberFi hesap yönetimi](https://pdrkocum.com/cyberai/)
- [Doğrulananlar ve sınırlar](audit/0.0.128.md)

Windows ve macOS 0.0.128 paketleri yayımlandı. Üç platformda gerçek giriş, oturumu hatırlama, uygulamayı yeniden açma ve hafıza kaydını geri okuma kontrolleri geçti. Yayımlanan paketlerle otomatik güncelleme denetimleri [doğrulama kaydında](audit/0.0.128.md) izlenebilir.

Ajan motoru 0.4.120, Tam erişimi alt ajanlara ve MCP çağrılarına aktarır. Sonradan sizin verdiğiniz daha kısıtlı izin korunur. Terminal, gerekli Python ve dosya arama araçlarının hazırlanmasını bekler. **Yeni genel kural:** veya **Yeni proje kuralı:** ile gönderdiğiniz kurallar ayrı hafıza kaydına yazılır.

Uygulama **Ayarlar → Genel → Masaüstü uygulaması** bölümünde sürümleri ve indirme ilerlemesini gösterir. “Beni hatırla” oturum anahtarını işletim sisteminin güvenli deposuyla şifreler; şifrenizi dosyaya yazmaz. Windows, Intel Mac ve Apple Silicon Mac’te gerçek giriş, oturumu hatırlama, yeniden açılış ve çıkış kontrolleri geçti.

Masaüstü paketleri önizlemedir. Windows kurucusu yerel CyberFi sertifikasıyla imzalanır; Windows güven uyarısı gösterebilir. Windows ajan motoru imzasızdır. Mac paketleri ve motorları ad hoc imzalıdır; Apple Developer ID ve noter onayı yoktur. macOS güvenlik denetimleri kapatılmaz.

Her paketin `.sha256` dosyası bütünlük özeti, `.update.json` dosyası CyberFi güncelleme imza bildirimidir. Bu bildirim işletim sisteminin dağıtım güvenini veya Apple noter onayını temsil etmez.

CyberFi, MIT lisanslı [Happy Desktop](https://github.com/slopus/happy-desktop) projesini temel alır. [Özgün lisans ve telif bildirimi](LICENSE-Happy-Desktop.txt) kurulum paketinde de yer alır.
