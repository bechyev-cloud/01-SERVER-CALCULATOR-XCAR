# XCAR Server

Express + SQLite backend for XCAR.

## Конфигурация без .env

Сервер теперь использует файл `config.js`. Его можно хранить в GitHub вместе с проектом — отдельный `.env` для запуска не требуется.

Порядок приоритета настроек:
1. Environment Variables Render (если заданы)
2. `server/config.js`
3. встроенные значения сервера

Это позволяет оставить текущую логику приложения и одновременно запускать сервер из GitHub без `.env`.

### Что изменить в config.js

- `adminUser` — логин администратора
- `adminPassword` — пароль администратора
- `clientServerUrl` — адрес сервера
- `monthPrice` — цена подписки
- `payBank`, `payCard`, `payRecipient`, `payPhone` — реквизиты
- `dbFile`, `backupDir` — пути SQLite и резервных копий

**Важно:** если пароль уже задан в Render → Environment, он будет использован вместо `config.js`. Это безопаснее, чем хранить пароль в GitHub.

## Автоматическое резервное копирование

Ежедневная резервная копия запускается в 03:00 по времени сервера.

## Оплата / QR

Super Admin сохраняет `pay_qr_mode` (`text` или `image`) и `pay_qr_image`. Пользовательское приложение получает эти значения через `/api/public/subscription`.
