# pqtool

`pqtool` создаёт записи в хранилище ключей и шифрует файлы в формате PQL1. Используется
глобальный реестр, `SystemRng` и 600 000 итераций PBKDF2 для новых записей. Список
доступных алгоритмов выводит `pqbench --list`. Каталог хранилища выбирается через
`PQLAB_HOME`, по умолчанию это `~/.pqlab`.

Пример для существующих файлов `password.bin` и `message.bin`:

```bash
tool=./build/release/apps/pqtool/pqtool
key_id=$("$tool" create ML-KEM-768 demo --password-file password.bin)
"$tool" encrypt ML-KEM-768 AES-256 message.bin message.pql
"$tool" rotate "$key_id" --password-file password.bin
"$tool" list
"$tool" rewrap message.pql migrated.pql --password-file password.bin
"$tool" decrypt migrated.pql restored.bin --password-file password.bin
cmp message.bin restored.bin
```

Пароль читается как непустая последовательность байтов из файла размером до 1 МиБ.
Перевод строки входит в пароль. Для ротации принимается также уникальный префикс
идентификатора ключа от четырёх шестнадцатеричных цифр.

Команды обрабатывают один обычный файл в памяти. При расшифровании сначала проверяются
подлинность заголовка и теги всех частей данных. Выход публикуется атомарно по новому пути
с правами `0600`. При занятом пути команда сообщает об ошибке.

`rewrap` проверяет упаковку DEK и переносит зашифрованные данные побитово. Их теги
проверяет `decrypt`. Для переноса к активному ключу другого KEM укажите его имя между
выходным путём и `--password-file`.
