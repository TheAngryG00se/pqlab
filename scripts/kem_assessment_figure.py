"""Presentation page for the documented ML-KEM and HQC attack assessments."""

from presentation_style import BLUE, INK, MUTED, TEAL, slide


def assessment_figure(plt):
    fig = slide(plt, "Применимость атак на ML-KEM и HQC",
                "Для ML-KEM проверен машинный код pqlab. Для HQC использована модель авторов схемы.")
    left, right = .057, .535
    fig.text(left, .74, "ML-KEM · KyberSlash2", size=24, weight="bold", color=BLUE)
    fig.text(right, .74, "HQC 5.1 · метод ISD", size=24, weight="bold", color=TEAL)

    fig.text(left, .62, "0 инструкций DIV/IDIV", size=27, weight="bold", color=INK)
    fig.text(left, .546, "в объектных файлах kpke.cpp.o и mlkem.cpp.o", size=16, color=INK)
    fig.text(left, .493, "Проверка 19.11.2026 · x86-64 · GCC 13.4.0 · Release", size=14, color=MUTED)
    fig.text(left, .38, "В проверенной сборке сжатие обходится\n"
             "без деления, вызывающего эту утечку.", size=17, color=INK, va="top", linespacing=1.4)
    fig.text(left, .237, "В опыте авторов на Arm Cortex-M4 ключ уязвимой\n"
             "реализации Kyber768 восстанавливался за 4 минуты\n"
             "или быстрее во всех 10 испытаниях.", size=15, color=MUTED, va="top", linespacing=1.4)

    fig.text(right, .655, "Суммарный вес секретной пары", size=17, color=INK)
    for x, name, weight in ((.535, "HQC-1", 134), (.683, "HQC-3", 202), (.831, "HQC-5", 264)):
        fig.text(x, .558, str(weight), size=29, weight="bold", color=INK)
        fig.text(x, .505, name, size=15, color=MUTED)
    fig.text(right, .38, "Декодирование по информационному множеству\n"
             "ищет разреженную секретную пару по открытому ключу.", size=16,
             color=INK, va="top", linespacing=1.4)
    fig.text(right, .237, "По оценке авторов при фиксированной скорости кода\n"
             "трудоёмкость растёт экспоненциально с весом пары.\n"
             "Время восстановления ключа на стенде не измерялось.", size=15,
             color=MUTED, va="top", linespacing=1.4)

    fig.text(left, .046, "Bernstein и др. · KyberSlash, § 1.2", size=12, color=BLUE,
             url="https://eprint.iacr.org/2024/1049.pdf")
    fig.text(right, .046, "Команда HQC · спецификация 5.1, §§ 4.1 и 6.3", size=12, color=TEAL,
             url="https://pqc-hqc.org/doc/hqc_specifications_v5.1.pdf")
    return fig
