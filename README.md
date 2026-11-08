# CyberFi Releases

CyberFi’ın Windows ve macOS dağıtım deposu.

- [Windows x64 — 0.0.125](https://github.com/CyberfiTechh/CyberFi-Releases/releases/tag/v0.0.125)
- [macOS Intel — 0.0.125 DMG](https://github.com/CyberfiTechh/CyberFi-Releases/releases/download/macos-v0.0.125/CyberFi-0.0.125-x64.dmg)
- [macOS Apple Silicon — 0.0.125 DMG](https://github.com/CyberfiTechh/CyberFi-Releases/releases/download/macos-v0.0.125/CyberFi-0.0.125-arm64.dmg)
- [CyberFi hesap yönetimi](https://pdrkocum.com/cyberai/)
- [Kararlı ajan motoru — 0.4.118](https://github.com/CyberfiTechh/CyberFi-Engine/releases/tag/v0.4.118)
- [Doğrulananlar ve sınırlar](audit/0.0.125.md)

Windows ve Mac yayınları aynı depoda, ayrı etiketlerle sunulur. Yeni Windows ve macOS yayınları hazırdır. Önceki yayınlar, Windows güncelleme doğrulaması tamamlandıktan sonra kaldırılacaktır.

Uygulama **Ayarlar → Genel → Masaüstü uygulaması** bölümünde sürümleri ve indirme ilerlemesini gösterir. Intel ve Apple Silicon Mac üzerinde otomatik indirme, kurulum ve yeniden açılış doğrulandı. Windows otomatik güncellemesinin son kontrolü sürüyor. Hesabınız yönetici tarafından oluşturulur; “Beni hatırla” oturum anahtarını işletim sisteminin güvenli deposunda şifreleyerek saklar, şifrenizi dosyaya yazmaz.

Bu paketler önizlemedir. Windows kurucusu yerel CyberFi sertifikasıyla imzalanır; Windows güven uyarısı gösterebilir. Intel ve Apple Silicon Mac paketleri ad hoc imzalıdır; Apple Developer ID ve noter onayı yoktur. macOS güvenlik denetimleri kapatılmaz.

Her paketin `.sha256` dosyası bütünlük özeti, `.update.json` dosyası CyberFi güncelleme imza bildirimidir. İmzalar işletim sistemi dağıtım güvenini veya Apple noter onayını temsil etmez.

CyberFi, MIT lisanslı [Happy Desktop](https://github.com/slopus/happy-desktop) projesini temel alır. [Özgün lisans ve telif bildirimi](LICENSE-Happy-Desktop.txt) kurulum paketinde de yer alır.
