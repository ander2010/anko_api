import random

SINGLE_CHOICE_TEMPLATES = [
    {
        "template": "¿Cuál es el propósito principal de {topic}?",
        "options": [
            {"text": "Proporcionar una estructura base para el desarrollo", "is_correct_candidate": True},
            {"text": "Facilitar la comunicación entre componentes", "is_correct_candidate": False},
            {"text": "Optimizar el rendimiento del sistema", "is_correct_candidate": False},
            {"text": "Gestionar el estado de la aplicación", "is_correct_candidate": False},
        ],
        "explanation": "El propósito principal suele describirse en la definición general del concepto.",
    },
    {
        "template": "¿Qué describe mejor a {topic}?",
        "options": [
            {"text": "Un concepto o técnica usada para resolver un problema específico", "is_correct_candidate": True},
            {"text": "Un lenguaje de programación", "is_correct_candidate": False},
            {"text": "Un sistema operativo", "is_correct_candidate": False},
            {"text": "Un tipo de base de datos", "is_correct_candidate": False},
        ],
        "explanation": "La mejor descripción debe ser la más general y correcta para el concepto.",
    },
    {
        "template": "¿Cuál es un beneficio clave de {topic}?",
        "options": [
            {"text": "Mejorar la claridad y mantenibilidad del código", "is_correct_candidate": True},
            {"text": "Eliminar la necesidad de pruebas", "is_correct_candidate": False},
            {"text": "Evitar el uso de patrones", "is_correct_candidate": False},
            {"text": "Garantizar cero errores en producción", "is_correct_candidate": False},
        ],
        "explanation": "Los beneficios clave suelen estar ligados a mantenibilidad y consistencia.",
    },
]

MULTI_SELECT_TEMPLATES = [
    {
        "template": "Selecciona todas las afirmaciones correctas sobre {topic}:",
        "options": [
            {"text": "Puede ser parte de la arquitectura del sistema", "is_correct_candidate": True},
            {"text": "Puede mejorar la experiencia del usuario si se aplica bien", "is_correct_candidate": True},
            {"text": "Siempre elimina por completo la complejidad", "is_correct_candidate": False},
            {"text": "Puede facilitar pruebas y mantenimiento", "is_correct_candidate": True},
            {"text": "Hace innecesaria la documentación", "is_correct_candidate": False},
        ],
        "correctCount": 2,
        "explanation": "Busca las afirmaciones generales que suelen ser verdaderas en la práctica.",
    },
    {
        "template": "¿Cuáles de estas afirmaciones son típicamente ciertas respecto a {topic}?",
        "options": [
            {"text": "Ayuda a organizar responsabilidades", "is_correct_candidate": True},
            {"text": "Puede reducir errores si se usa correctamente", "is_correct_candidate": True},
            {"text": "Obliga a usar un único framework", "is_correct_candidate": False},
            {"text": "Puede incrementar la claridad del diseño", "is_correct_candidate": True},
        ],
        "correctCount": 2,
        "explanation": "Selecciona afirmaciones generales y no absolutas.",
    },
]

TRUE_FALSE_TEMPLATES = [
    {
        "template": "{topic} puede contribuir a un diseño más mantenible cuando se aplica correctamente.",
        "default_truth": True,
        "explanation_true": "Aplicado correctamente, suele mejorar mantenibilidad/claridad.",
        "explanation_false": "Depende del contexto; no siempre aporta mantenibilidad.",
    },
    {
        "template": "{topic} siempre garantiza mejor rendimiento sin importar el caso.",
        "default_truth": False,
        "explanation_true": "Es raro que algo garantice rendimiento en todos los casos.",
        "explanation_false": "No hay garantías absolutas; depende del caso de uso.",
    },
]


def _pick_templates(pool, count, avoid_repeat=True):
    """
    Devuelve una lista de templates elegidos para `count`.
    Si count > len(pool), se permite repetir pero intentando evitar repetición seguida.
    """
    if not pool:
        return []

    chosen = []
    last_idx = None

    for _ in range(count):
        if len(pool) == 1:
            idx = 0
        else:
            idx = random.randrange(len(pool))
            if avoid_repeat and last_idx is not None and idx == last_idx:
                # reintenta una vez
                idx = (idx + random.randrange(1, len(pool))) % len(pool)

        chosen.append(pool[idx])
        last_idx = idx

    return chosen


def generate_questions_for_rule(*, rule, topic, count: int):
    """
    Genera EXACTAMENTE `count` preguntas del tipo rule.distribution_strategy
    con mayor variación (templates múltiples) y respuestas coherentes.
    """
    if count <= 0:
        return []

    points = round(100 / count, 2)
    qtype = rule.distribution_strategy

    out = []

    if qtype == "singleChoice":
        tpls = _pick_templates(SINGLE_CHOICE_TEMPLATES, count)
        for i, tpl in enumerate(tpls):
            qtext = tpl["template"].replace("{topic}", topic.name)

            # opciones
            opts = [o["text"] for o in tpl["options"]]
            # elige la opción correcta basada en candidates
            correct_candidates = [idx for idx, o in enumerate(tpl["options"]) if o.get("is_correct_candidate")]
            if not correct_candidates:
                correct_candidates = [0]  # fallback
            correct_idx = random.choice(correct_candidates)

            # mezcla opciones pero mantén cuál era la correcta
            idxs = list(range(len(opts)))
            random.shuffle(idxs)

            options = []
            for order, original_idx in enumerate(idxs):
                options.append({
                    "option_id": chr(97 + order),
                    "text": opts[original_idx],
                    "correct": original_idx == correct_idx,
                    "order": order,
                })

            out.append({
                "type": qtype,
                "topic": topic,
                "question": qtext,
                "options": options,
                "points": points,
                "explanation": tpl.get("explanation") or f"Generated for {topic.name}",
                "order": i,
            })

    elif qtype == "multiSelect":
        tpls = _pick_templates(MULTI_SELECT_TEMPLATES, count)
        for i, tpl in enumerate(tpls):
            qtext = tpl["template"].replace("{topic}", topic.name)

            all_opts = tpl["options"][:]  # list of dicts
            random.shuffle(all_opts)

            correct_count = int(tpl.get("correctCount", 2))

            # selecciona correctas reales por el flag
            correct_pool = [o for o in all_opts if o.get("is_correct_candidate")]
            wrong_pool = [o for o in all_opts if not o.get("is_correct_candidate")]

            # si no hay suficientes correctas, ajusta
            picked_correct = random.sample(correct_pool, k=min(correct_count, len(correct_pool)))
            remaining_needed = max(0, correct_count - len(picked_correct))

            # si faltan correctas, rellena con wrong (para no romper)
            if remaining_needed > 0:
                picked_correct += random.sample(wrong_pool, k=min(remaining_needed, len(wrong_pool)))

            # arma set de textos correctos
            correct_texts = set([o["text"] for o in picked_correct])

            # arma opciones finales (todas), marcando correctas por pertenencia
            options = []
            for order, o in enumerate(all_opts):
                options.append({
                    "option_id": chr(97 + order),
                    "text": o["text"],
                    "correct": o["text"] in correct_texts,
                    "order": order,
                })

            out.append({
                "type": qtype,
                "topic": topic,
                "question": qtext,
                "options": options,
                "points": points,
                "explanation": tpl.get("explanation") or f"Generated for {topic.name}",
                "order": i,
            })

    else:  # trueFalse
        tpls = _pick_templates(TRUE_FALSE_TEMPLATES, count)
        for i, tpl in enumerate(tpls):
            qtext = tpl["template"].replace("{topic}", topic.name)

            # 70/30 para no ser siempre random sin sentido (ajústalo)
            default_truth = bool(tpl.get("default_truth", True))
            truth = default_truth if random.random() < 0.7 else (not default_truth)

            options = [
                {"option_id": "true", "text": "Verdadero", "correct": truth, "order": 0},
                {"option_id": "false", "text": "Falso", "correct": not truth, "order": 1},
            ]

            explanation = tpl.get("explanation_true") if truth else tpl.get("explanation_false")
            out.append({
                "type": qtype,
                "topic": topic,
                "question": qtext,
                "options": options,
                "points": points,
                "explanation": explanation or f"Generated for {topic.name}",
                "order": i,
            })

    return out
