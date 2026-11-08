# CyberFi için sonraki geliştirmeler

Bu liste tasarım ve ürün önerisidir; yayınlanan özelliklerin listesi değildir.

## Ana panel için üç yön

| Seçenek | Görünüm | Kullanım |
| --- | --- | --- |
| Grafit stüdyo | Mat koyu gri, turkuaz yalnız seçili öğe ve önemli eylemlerde, ince ayraçlar | Uzun kodlama ve çoklu ajan işleri için ilk tercihim |
| Aydınlık çalışma masası | Kırık beyaz yüzeyler, lacivert metin, ölçülü turkuaz, hafif kenarlıklar | Belge, eğitim ve PDF ağırlıklı işler |
| Odak görünümü | Geniş sohbet; yan menü daraltılmış; çalışma merkezi gerektiğinde açık | Tek bir sonuç veya belge üzerinde yoğunlaşma |

Üçünde de aynı simgeler ve aynı yerleşim korunmalı. Metin için 14–15 px, yardımcı bilgiler için 12–13 px, bölüm başlıkları için 18–20 px başlangıç ölçeği uygun olur. Okunabilirlik için satır aralığı yaklaşık 1,5–1,6; sohbet satırı uzunluğu yaklaşık 70–85 karakter hedeflenebilir. Bunlar kullanıcı ölçeklendirmesini engelleyen sabit sınırlar olmamalı.

Ana panelde yoğun parlama veya sürekli hareket yerine açılışta kısa vurgu, etkileşim sırasında ölçülü renk ve belirgin odak çizgisi öneriyorum. Sağ panelde durum simgesiyle birlikte kısa durum metni bulunmalı; bilgi yalnız renge bağlanmamalı.

## Öncelikli ürün fikirleri

1. **Tek teslim kartı.** Görev sonunda sonuç, dosyalar, geçen doğrulamalar ve açık kalanlar tek bir kısa kartta yer alsın. Kart gerçek görev/çıktı kayıtlarından oluşsun; yanıt metninden tahmin edilmesin.
2. **Değişiklik önizlemesi ve geri dönüş noktası.** Büyük düzenleme öncesinde otomatik bir geri dönüş noktası; sonrasında dosya farkını inceleme ve seçerek geri alma. Git geçmişi ile geçici geri dönüş noktaları kullanıcıya ayrı anlatılmalı. Cursor'ın [checkpoint yaklaşımı](https://cursor.com/docs/agent/overview#checkpoints) yerel, Git'ten ayrı kayıtlar kullanıyor; Codex'in [proje ve değişiklik inceleme yaklaşımı](https://openai.com/index/introducing-the-codex-app/) da bu akış için yararlı bir referans.
3. **Belgeden hedefli soru.** PDF'de bir bölümü veya görselde bir alanı seçip, sayfa numarası ve kaynak bağlantısıyla sohbete ekleme. Özellikle soru inceleme ve eğitim belgesi hazırlama işlerini hızlandırabilir.
4. **Görev başına kaynak denetimi.** Aynı anda çalışan ajan sayısını ve süre sınırını görev başından belirleme; bekleyen işleri kısa bir sırada görme. Yeni görev ekleme ile çalışan görevi yönlendirme eylemlerini görünür biçimde ayırma. Cursor'ın [kuyruk ve yönlendirme ayrımı](https://cursor.com/docs/agent/overview#queued-messages) bu etkileşim için iyi bir referans.

Benim sıralamam: önce tek teslim kartı ve grafit/aydınlık görünümün ortak yazı ölçeği; sonra geri dönüş noktaları; ardından belge seçimi ve kaynak denetimi. Mevcut yayınların kurulum güvenilirliği ve gerçek test sonuçları bu görsel değişikliklerden önce gelmeli.
