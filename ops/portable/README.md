# SlipNet Portable Server Packs

این پوشه دو بسته قابل‌حمل برای تعویض سریع سرورهای SlipNet A1 نگه می‌دارد:

- `foreign/`: نقش سرور خارج Product XHTTP.
- `national/`: نقش سرور داخل شبیه National95 شامل Gateway، Product client، Arvan allowlist و return-route.

## اصل امنیت

اسکریپت‌های عمومی داخل Git هیچ UUID، private key یا credential زنده‌ای ندارند.
فایل‌های `export-live.sh` روی سرور زنده یک bundle خصوصی mode 0600 می‌سازند که secrets و certificate لازم را در خود دارد.
bundle خصوصی نباید commit یا عمومی شود.

## Foreign

Exporter روی Foreign زنده:

```bash
sudo /root/slipnet-portable-src/foreign/export-live.sh
```

پس از انتقال bundle به سرور جدید، نصب و شروع سرویس با یک فرمان:

```bash
tar -xzf /root/slipnet-foreign-portable-current.tgz -C /root && sudo /root/slipnet-foreign-portable/install.sh
```

Installer دو حالت را تشخیص می‌دهد:

- **standalone**: اگر 443 آزاد باشد، front TLS مستقل را بالا می‌آورد.
- **coexist**: اگر `slipgate-mobile.service` و Caddy موجود باشند، Product را به‌صورت vhost دوم اضافه می‌کند؛ candidate قبل از restart validate می‌شود، backup گرفته می‌شود و failure rollback دارد.

اعتبارسنجی:

```bash
sudo /root/slipnet-foreign-portable/validate.sh
```

Rollback:

```bash
sudo /root/slipnet-foreign-portable/rollback.sh
```

## National

Exporter روی National زنده:

```bash
sudo /root/slipnet-portable-src/national/export-live.sh
```

نصب و شروع سرویس روی سرور داخل جدید:

```bash
tar -xzf /root/slipnet-national-portable-current.tgz -C /root && sudo /root/slipnet-national-portable/install.sh
```

National installer default route سرور را تصاحب نمی‌کند. فقط Gateway، Product client، Arvan origin allowlist و rule لازم برای پاسخ‌های source-port 443 را می‌سازد.

اعتبارسنجی:

```bash
sudo /root/slipnet-national-portable/validate.sh
```

## Cutover rule

هیچ Origin/DNS/CDN cutover قبل از PASS شدن validate و E2E واقعی انجام نشود.
سرور قبلی تا پایان soak به‌عنوان rollback نگه داشته شود.
Production `/home/reos/projects/SlipNet-Hardened` از این پک‌ها مستقل و ممنوع‌التغییر است.
