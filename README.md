# web-parser

Автоматический сборщик прокси-ссылок из веб-подписок и API. Результат записывается в `configs.txt`; основная LIKVID VPN сможет забирать его по RAW-ссылке.

## Как добавить источники

1. Откройте `sources.txt`.
2. Добавьте **по одной полной HTTP(S)-ссылке на строку**.
3. Сохраните изменения в ветке `main`. Можно вручную запустить workflow через **Actions → Update web subscription configs → Run workflow**.

`sources.txt` — единственный источник истины для списка ссылок. Во время запуска парсер синхронизирует список в `sources.json`:

- новая ссылка автоматически добавляется в JSON с настройками по умолчанию;
- существующая ссылка сохраняет свои дополнительные настройки в JSON;
- удаление ссылки из `sources.txt` удаляет её запись из `sources.json` при следующем запуске;
- дубликаты ссылок игнорируются.

По умолчанию используется `User-Agent: Happ/3.0.0`. JSON-конвертация включена (`defaults.convert_json: true`) и выполняется **локально** внутри `main.py` через модуль `local_converter.py`. Исходный JSON разбирается на поддерживаемые outbounds и преобразуется в обычные share-ссылки. JSON-конфиги не отправляются в `p.kfwl.lol`, `c.kfwl.lol` или другие сторонние конвертеры. Можно отключить функцию через `convert_json: false`.

Для конкретного источника можно изменить `user_agent`, `headers`, `mode`, `os`, `hwid`, `timeout_seconds` и `retries` в соответствующей записи `sources.json`. Чтобы эта настройка сохранилась, URL должен оставаться в `sources.txt`.

`mode: "direct"` используется по умолчанию. `mode: "p_kfwl"` отдельно включает получение источника через прокси-обёртку `p.kfwl.lol` (например, если источнику необходим определённый User-Agent/HWID). Это не связано с JSON-конвертацией: сам JSON в URL-ссылки преобразуется локально.

## Что парсер умеет

- получать HTTP(S)-ответы с перенаправлениями и повторами при ошибках;
- извлекать `vless://`, `vmess://`, `trojan://`, `ss://`, `ssr://`, `hysteria2://`, `tuic://`, SOCKS/HTTP и другие поддерживаемые схемы;
- декодировать Base64-подписки, в том числе вложенные;
- автоматически определять Xray/sing-box JSON-конфиги и локально преобразовывать поддерживаемые прокси-outbound в URL-ключи;
- удалять дубликаты и сохранять результат по одному конфигу на строку;
- продолжать обработку других источников, если один не отвечает;
- не заменять непустой известный результат пустым файлом, если все источники завершились ошибкой.

## Важные ограничения

Локальный конвертер поддерживает распространённые прокси-outbound Xray и sing-box: VLESS, VMess, Trojan, Shadowsocks, SOCKS/HTTP, Hysteria2, TUIC и AnyTLS. Не каждый протокол или нестандартное поле JSON имеет универсальный share-link формат; неподдерживаемые outbound пропускаются с предупреждением.

Если ссылка возвращает только HTML-интерфейс без конфигов, нужно определить настоящий API/endpoint, который запрашивает клиент. Парсер не обходит CAPTCHA, авторизацию или другие механизмы ограничения доступа. Добавляйте только источники, которыми вы вправе пользоваться.

## RAW-результат

`https://raw.githubusercontent.com/cheesyx-rudy/web-parser/main/configs.txt`

В GitHub Actions для `GITHUB_TOKEN` должно быть разрешение **Read and write permissions**, чтобы workflow мог сохранять изменившийся `configs.txt` и синхронизированный `sources.json`.

## Проверка локально

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python main.py
```

В логах не печатаются полные URL с query-токенами или авторизационные заголовки.


### Filtering ordinary links

The parser extracts recognized proxy URI schemes (such as `vless://`, `vmess://`, `trojan://`, `ss://`, and supported SOCKS/Hysteria/TUIC forms). Ordinary `http://` and `https://` links are intentionally ignored, so website, Telegram, support, and channel links are not included in `configs.txt`.
