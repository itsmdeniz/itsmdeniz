# Cloudflare Timeline Kurulumu

Bu site Cloudflare Worker + KV ile çalışır.

## Gerekli secret'lar

Cloudflare Worker içinde şu iki secret olmalı:

| Type | Name |
| --- | --- |
| Secret | `ADMIN_PASSWORD` |
| Secret | `TOKEN_SECRET` |

## KV Namespace oluşturma

1. Cloudflare Dashboard'a gir.
2. Sol menüden **Storage & Databases** kısmına gir.
3. **KV** seç.
4. **Create namespace** butonuna bas.
5. Namespace adı olarak şunu yaz:

```text
TIMELINE_KV
```

6. Oluştur.

## KV'yi Worker'a bağlama

1. Sol menüden **Workers & Pages** kısmına gir.
2. Siteyi çalıştıran Worker'ı aç.
3. **Settings** sekmesine gir.
4. **Bindings** kısmını bul.
5. **Add binding** veya **Add** butonuna bas.
6. Binding type olarak **KV namespace** seç.
7. Variable name / Binding name alanına şunu yaz:

```text
TIMELINE_KV
```

8. KV namespace seçiminde oluşturduğun **TIMELINE_KV** namespace'ini seç.
9. Kaydet.
10. Worker'ı redeploy et.

## Kontrol

Sitede admin girişi yaptıktan sonra post atabiliyorsan kurulum tamamdır.
