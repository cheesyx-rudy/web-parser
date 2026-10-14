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

По умолчанию используется `User-Agent: Happ/3.0.0`. Для конкретного источника можно изменить `user_agent`, `headers`, `mode`, `os`, `hwid`, `timeout_seconds` и `retries` в соответствующей записи `sources.json`. Чтобы эта настройка сохранилась, URL должен оставаться в `sources.txt`.

`mode: "direct"` используется по умолчанию. `mode: "p_kfwl"` включает обёртку через `p.kfwl.lol` для источников, которым нужен поддерживаемый этим сервисом формат запроса.

## Что парсер умеет

- получать HTTP(S)-ответы с перенаправлениями и повторами при ошибках;
- извлекать `vless://`, `vmess://`, `trojan://`, `ss://`, `ssr://`, `hysteria2://`, `tuic://`, SOCKS/HTTP и другие поддерживаемые схемы;
- декодировать Base64-подписки, в том числе вложенные;
- удалять дубликаты и сохранять результат по одному конфигу на строку;
- продолжать обработку других источников, если один не отвечает;
- не заменять непустой известный результат пустым файлом, если все источники завершились ошибкой.

## Важное ограничение

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
