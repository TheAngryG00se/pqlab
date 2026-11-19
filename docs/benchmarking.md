# Как собрать стенд, измерить скорость и посмотреть графики

Команды запускаются из корня репозитория. В рабочем реестре доступны три набора ML-KEM,
AES-128/192/256, «Кузнечик» и режимы ECB/CBC/CTR/GCM.

## Графики для показа

```bash
CXX=g++-13 python3 scripts/present_results.py
```

После успешного запуска актуальный **пятистраничный PDF** доступен по одному и тому же пути
`output/pdf/pqlab.pdf`. Первые три страницы показывают смену получателя PQL1, скорость ML-KEM
и лавинный эффект при генерации ключей ML-KEM. На четвёртой странице приведены измеренные
расстояния Хэмминга для HQC-1/3/5. На пятой — выводы о применимости KyberSlash2 и ISD.
Скрипт сохраняет также отдельную копию PDF, PNG и SVG в каталоге запуска под `results/`
и печатает путь к нему последней строкой.

При запуске без аргументов скрипт заново собирает Release, проводит пять прогонов замеров
ML-KEM и лавинный эксперимент с 256 парами на компоненту входа. Для HQC он читает результат
обычного запуска `scripts/run_hqc_avalanche.py` из `results/hqc-avalanche/`. Если такого
каталога ещё нет, выполняет эталонный эксперимент с 768 парами на каждый набор и сохраняет
его в каталоге презентации. При первом запуске эталону нужен доступ к архиву HQC и заголовки
OpenSSL для генератора тест-векторов. [Методика и требования](hqc_avalanche.md)

Следующая команда берёт для PDF данные отдельного опыта из `results/hqc-repeat/`.

```bash
python3 scripts/present_results.py --hqc-dir results/hqc-repeat
```

При пересборке по сохранённым данным ML-KEM укажите вместе `--bench-csv` и `--analysis-csv`.
В этом режиме без `--hqc-dir` используется обычный каталог опыта HQC, а при его отсутствии —
опубликованные результаты из `results/final/hqc-avalanche/`. Перед построением графика
скрипт проверяет контрольные суммы CSV, версию эталона, подтверждение 300 KAT и количество пар.
Опция `--output-dir` направляет весь экспорт в отдельный новый каталог. Для обновления общего
PDF запускайте команду с обычным каталогом вывода по умолчанию.

## Инструменты

Требуются CMake ≥ 3.24, GCC ≥ 13, Ninja и Python 3. Для графиков нужен matplotlib,
для проверки форматирования — clang-format. На текущей машине установлены
GCC/G++ 13.4.0, CMake 3.31.10 и clang-format 18.1.8; Python и matplotlib уже доступны.
В CI для Debug и ASan используется GCC 13, для статического анализа — clang-tidy 18.
Путь к анализатору при конфигурации можно указать через `-DCLANG_TIDY_EXE=/путь/к/clang-tidy`.
Пользовательские инструменты CMake и clang-format находятся в `~/.local/bin`.

```bash
cd ~/ZashekuInformation
export PATH="$HOME/.local/bin:$PATH"
g++-13 --version
cmake --version
clang-format --version
```

Первая конфигурация скачивает уже предусмотренные проектом GoogleTest и nlohmann/json.
Если компилятор меняется с GCC 11 на GCC 13, один раз используйте `--fresh`.
Эта опция пересоздаёт кеш CMake, сохраняя загруженные исходники зависимостей.
При последующих конфигурациях её можно опустить.

## Debug и проверки

```bash
cmake --preset debug --fresh -DCMAKE_C_COMPILER=gcc-13 -DCMAKE_CXX_COMPILER=g++-13
cmake --build --preset debug --parallel 4
ctest --preset debug --output-on-failure --parallel 4
cmake --build --preset debug --target format-check
python3 -m unittest discover -s scripts -p 'test_*.py'
```

ASan/UBSan с проверкой утечек:

```bash
cmake --preset asan --fresh -DCMAKE_C_COMPILER=gcc-13 -DCMAKE_CXX_COMPILER=g++-13
cmake --build --preset asan --parallel 4
ctest --preset asan --output-on-failure --parallel 4
```

Запускайте эту проверку из обычного терминала: LeakSanitizer не работает под ptrace,
в том числе в песочнице агента. Санитайзеры не надо отключать для обхода этого ограничения.

## Release и список алгоритмов

Измерения разрешены только в Release:

```bash
cmake --preset release --fresh -DCMAKE_C_COMPILER=gcc-13 -DCMAKE_CXX_COMPILER=g++-13
cmake --build --preset release --parallel 4
./build/release/apps/pqbench/pqbench --list
```

После любого коммита или изменения кода повторите конфигурацию и сборку, чтобы
метаданные исполняемого файла соответствовали измеряемому коду:

```bash
cmake --preset release
cmake --build --preset release --parallel 4
```

## Пять запусков, отчёт и графики одной командой

```bash
python3 scripts/run_bench.py --suite all --repeats 5
```

В начале команда выведет новый каталог вида
`results/2026-10-11/series-2026-10-11T12-30-00-123456Z/`.
Откройте этот каталог в файловом менеджере: графики лежат в `report/plots/`,
таблица — в `report/report.md`, сводные числа — в `report/summary.csv`.
В основном графике `kem_repeated_latency.png` столбцы показывают медиану медиан
запусков, точки — медианы отдельных прогонов, вертикальные отрезки — min/max.
SVG подходит для отчёта и масштабируется без потери качества.

Для каталога с заранее известным именем, например на 11 октября 2026:

```bash
python3 scripts/run_bench.py --suite all --repeats 5 --output-dir results/2026-10-11/my-bench
xdg-open results/2026-10-11/my-bench/report/plots/kem_repeated_latency.png
xdg-open results/2026-10-11/my-bench/report
```

Каталог `my-bench` должен быть новым. Для следующей серии выберите другое имя
или опустите `--output-dir`, чтобы имя было создано автоматически. Укажите свою дату,
если запускаете эксперимент позже.

Внутри серии сохраняются отдельные CSV и логи каждого прогона; `environment.json`
содержит команду, SHA-256 программы и выбранный CPU. По умолчанию используется первый
разрешённый логический CPU; `--cpu 4` выбирает другой, `--cpu none` отменяет привязку.
Перед замерами закройте тяжёлые задачи и используйте одинаковые настройки питания.

Более длинная серия только для ML-KEM-768:

```bash
python3 scripts/run_bench.py --suite kem --filter ML-KEM-768 --repeats 5 --iterations 50000
```

Для режимов и гибридного шифрования можно сравнить скорость на нескольких размерах сообщения.

```bash
python3 scripts/run_bench.py --suite mode --filter AES-256-CTR --sizes 256,4096,65536
python3 scripts/run_bench.py --suite aead --filter AES --seconds 3 --repeats 5 --sizes 16,256,4096,65536,1048576
python3 scripts/run_bench.py --suite hybrid --seconds 3 --repeats 5 --sizes 4096,65536,1048576
```

## Один прогон вручную

Если повторные запуски сейчас не нужны:

```bash
./build/release/apps/pqbench/pqbench --suite all --output results/2026-10-11/single.csv
python3 scripts/plot_bench.py results/2026-10-11/single.csv
xdg-open results/2026-10-11/plots/kem_latency.png
```

Явный `--output` у `pqbench` перезаписывает файл; для хранения истории выбирайте новые имена.
`plot_bench.py` строит графики одного CSV; `compare_bench.py` анализирует серию отдельных CSV.

## Сравнение «до» и «после»

Сначала сохраните серию `before`, затем измените код или настройки сборки,
пересоберите Release и сохраните серию `after` на той же машине:

```bash
python3 scripts/compare_bench.py results/2026-10-11/after/run-*.csv --baseline results/2026-10-11/before/run-*.csv --label after --baseline-label before --output-dir results/2026-10-11/comparison
xdg-open results/2026-10-11/comparison/plots/kem_repeated_latency.png
```

`comparison.csv` и Markdown показывают времена обеих серий и их отношение.
Отношение времени > 1 означает, что текущая серия быстрее; изменение времени < 0
означает ускорение. Скрипт проверяет одинаковую конфигурацию внутри каждой серии
и одинаковую модель CPU и набор операций между сериями. Сопоставимость питания,
прогрева, длительности и фоновой нагрузки остаётся частью методики эксперимента.

## Что использовать в своей главе отчёта

1. Из `environment.json` и CSV: машина, компилятор, флаги, commit, команда и число повторов.
2. Для KEM: время `keygen`, `encaps` и `decaps` в микросекундах и число операций в секунду.
3. Для шифров и AEAD: скорость в МиБ/с на разных размерах сообщений; настройка ключа отдельно.
4. Для KEM-DEM: полное время шифрования/расшифрования и влияние размера сообщения.
5. Разброс между прогонами: min/max и CV медиан; разброс внутри прогона: p5/p95 и stddev из CSV.

Время KEM описывает согласование ключа; скорость обработки файла измеряется шифром
или полным KEM-DEM. Не называйте min/max доверительным интервалом и не выводите
причину ускорения из сравнения, в котором одновременно менялись код, компилятор и нагрузка.
Графики и таблицы строятся из первичных CSV одной командой; результаты остаются в
игнорируемом `results/`, а не в Git. Подробная методика: [`bench/README.md`](../bench/README.md).
