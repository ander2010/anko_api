import random

SINGLE_CHOICE_TEMPLATES = [
    {
        "template": "¿Cuál es el propósito principal de {topic}?",
        "options": [
            "Proporcionar una estructura base para el desarrollo",
            "Facilitar la comunicación entre componentes",
            "Optimizar el rendimiento del sistema",
            "Gestionar el estado de la aplicación",
        ],
    },
]

MULTI_SELECT_TEMPLATES = [
    {
        "template": "Selecciona todas las afirmaciones correctas sobre {topic}:",
        "options": [
            "Es fundamental para la arquitectura del sistema",
            "Mejora la experiencia del usuario",
            "Reduce la complejidad del código",
            "Facilita las pruebas automatizadas",
        ],
        "correctCount": 2,
    },
]

TRUE_FALSE_TEMPLATES = [
    {"template": "{topic} es fundamental para el diseño de interfaces modernas."},
]


def generate_questions_for_rule(*, rule, topic, count: int):
    """
    Genera EXACTAMENTE `count` preguntas del tipo rule.distribution_strategy
    """
    if count <= 0:
        return []

    points = round(100 / count, 2)
    qtype = rule.distribution_strategy

    out = []
    for i in range(count):
        if qtype == "singleChoice":
            tpl = random.choice(SINGLE_CHOICE_TEMPLATES)
            qtext = tpl["template"].replace("{topic}", topic.name)

            opts = list(tpl["options"])
            correct_idx = random.randrange(len(opts))

            options = [
                {"option_id": chr(97 + idx), "text": txt, "correct": idx == correct_idx, "order": idx}
                for idx, txt in enumerate(opts)
            ]

        elif qtype == "multiSelect":
            tpl = random.choice(MULTI_SELECT_TEMPLATES)
            qtext = tpl["template"].replace("{topic}", topic.name)

            opts = list(tpl["options"])
            random.shuffle(opts)

            correct_count = int(tpl.get("correctCount", 2))
            options = [
                {"option_id": chr(97 + idx), "text": txt, "correct": idx < correct_count, "order": idx}
                for idx, txt in enumerate(opts)
            ]

        else:  # trueFalse
            tpl = random.choice(TRUE_FALSE_TEMPLATES)
            qtext = tpl["template"].replace("{topic}", topic.name)

            correct_true = random.random() > 0.5
            options = [
                {"option_id": "true", "text": "Verdadero", "correct": correct_true, "order": 0},
                {"option_id": "false", "text": "Falso", "correct": not correct_true, "order": 1},
            ]

        out.append(
            {
                "type": qtype,
                "topic": topic,
                "question": qtext,
                "options": options,
                "points": points,
                "explanation": f"Generated for {topic.name}",
                "order": i,
            }
        )

    return out
