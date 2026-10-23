# SlipNet Provider-Direct Routes

## هدف

افزودن مسیرهای مستقیم Provider بدون وابستگی به سرور ملی 95، در کنار مسیرهای فعلی Cloudflare Worker، بدون تغییر کلاینت اندروید و بدون شکستن enrollment فعلی.

## معماری نهایی

### مسیرهای موجود Cloudflare

Client -> per-user Cloudflare Worker Primary/Backup -> foreign origin 155 -> VLESS -> Internet

این دو مسیر همان managed enrollment فعلی باقی می‌مانند. فایل one-time enrollment همچنان دقیقاً دو پروفایل Primary/Backup دارد.

### ParsPack Direct

Client -> ParsPack public domain -> fixed-destination ParsPack relay -> hidden 155 backend path -> dedicated Xray inbound -> Internet

### Arvan Direct

Client -> Arvan public domain -> fixed-destination Arvan relay -> hidden 155 backend path -> dedicated Xray inbound -> Internet

سرور 95 در هیچ‌کدام از دو مسیر Direct حضور ندارد.

## جداسازی Failure Domain

هر Provider باید دامنه عمومی مستقل داشته باشد. ParsPack و Arvan نباید یک root domain مشترک داشته باشند. Workerهای Cloudflare نیز روی hostnameهای مستقل Worker باقی می‌مانند.

## اصل امنیتی Origin

کانفیگ کاربر فقط دامنه عمومی Provider، پورت 443 و public relay path را می‌بیند. IP یا hostname خصوصی origin 155 و backend path فقط در env همان Provider relay نگهداری می‌شوند و هرگز وارد فایل Direct کاربر نمی‌شوند.

## مدیریت کاربران

هویت اصلی کاربر همان VLESS UUID موجود است. برای هر Direct route یک Xray inbound مستقل روی 155 وجود دارد.

نمونه tagها:

- vless-parspack-direct
- vless-arvan-direct

وقتی مسیر برای یک کاربر فعال می‌شود، همان UUID و email کاربر به inbound مربوط اضافه می‌شود. وقتی مسیر خاموش می‌شود، عضویت runtime و persistent از همان inbound حذف می‌شود.

بنابراین Disable در مانیتور واقعی است و فقط ظاهر UI نیست.

## Global Disable

خاموش‌کردن یک Direct route در مانیتور تمام کاربران مدیریت‌شده را از inbound همان مسیر حذف می‌کند. Assignmentهای کاربران ذخیره می‌مانند تا در صورت Enable مجدد، عضویت‌ها با UUID جاری بازیابی شوند.

## Reset Device

هنگام چرخش UUID با Reset Device، UUID کاربر در تمام Direct inboundهایی که عضو آن‌هاست نیز transactionally به‌روز می‌شود. اگر sync Direct شکست بخورد، credential اصلی rollback می‌شود.

## Direct Config

Direct config از managed enrollment جداست، چون کلاینت فعلی enrollment را فقط با دو پروفایل Primary/Backup معتبر می‌داند.

فایل Direct:

- از همان UUID کاربر استفاده می‌کند.
- همان expiry و profile lock را دارد.
- فقط بعد از device binding قابل دانلود است.
- failure-domain metadata ندارد و وارد failover خودکار Primary/Backup نمی‌شود.
- هر Direct profile توسط کاربر به‌صورت مستقل انتخاب می‌شود.

## فایل تنظیم مسیرها

مسیر پیش‌فرض:

/etc/slipnet-ea/direct-routes.json

هر route شامل این موارد است:

- id
- label
- provider
- host
- port
- path
- inbound_tag
- enabled

این فایل نباید origin خارجی یا credential Provider را در خود داشته باشد.

## State

Global route state:

/var/lib/slipnet-monitor/direct-route-state.json

Per-user assignments:

/var/lib/slipnet-monitor/direct-user-routes.json

هر دو فایل با نوشتن atomic و permission محدود نگهداری می‌شوند.

## ترتیب Release

1. Backup کامل Xray و Caddy روی 155.
2. ایجاد دو inbound مستقل loopback-only روی 155، بدون دست‌زدن به inbound فعلی.
3. ایجاد دو backend path مستقل و غیرعمومی در Caddy.
4. تست loopback هر inbound.
5. Deploy همان fixed-destination relay موجود ParsPack روی Arvan با env مستقل.
6. تست health و WebSocket هر Provider بدون کاربر Production.
7. قراردادن دامنه‌ها و public relay pathها در direct-routes.json با enabled=false.
8. Deploy نسخه جدید monitor/admin.
9. Assign فقط یک test user به ParsPack Direct و E2E.
10. Assign همان test user به Arvan Direct و E2E.
11. پس از PASS، Enable برای کاربران انتخاب‌شده.

Production مسیرهای فعلی تا پایان این مراحل دست‌نخورده می‌مانند.
