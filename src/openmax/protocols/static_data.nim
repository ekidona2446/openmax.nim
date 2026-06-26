## Static constants ported from Python OpenMAX `src/common/static.py`.
## Kept as raw JSON to preserve exact parity with the reference server.

const
  ## Complaint reasons returned by COMPLAIN_REASONS_GET (opcode 162).
  ComplainReasonsJson* = """[
    {"typeId": 5, "reasons": [
      {"reasonTitle": "Мошенничество", "reasonId": 8},
      {"reasonTitle": "Спам", "reasonId": 9},
      {"reasonTitle": "Порнографический контент", "reasonId": 23},
      {"reasonTitle": "Насилие", "reasonId": 18},
      {"reasonTitle": "Оскорбления", "reasonId": 11},
      {"reasonTitle": "Экстремизм", "reasonId": 20},
      {"reasonTitle": "Запрещенные товары", "reasonId": 21},
      {"reasonTitle": "Мне не нравится", "reasonId": 22},
      {"reasonTitle": "Другое", "reasonId": 7}
    ]},
    {"typeId": 4, "reasons": [
      {"reasonTitle": "Мошенничество", "reasonId": 8},
      {"reasonTitle": "Спам", "reasonId": 9},
      {"reasonTitle": "Порнографический контент", "reasonId": 23},
      {"reasonTitle": "Насилие", "reasonId": 18},
      {"reasonTitle": "Оскорбления", "reasonId": 11},
      {"reasonTitle": "Экстремизм", "reasonId": 20},
      {"reasonTitle": "Запрещенные товары", "reasonId": 21},
      {"reasonTitle": "Другое", "reasonId": 7}
    ]},
    {"typeId": 3, "reasons": [
      {"reasonTitle": "Мошенничество", "reasonId": 8},
      {"reasonTitle": "Спам", "reasonId": 9},
      {"reasonTitle": "Порнографический контент", "reasonId": 23},
      {"reasonTitle": "Насилие", "reasonId": 18},
      {"reasonTitle": "Оскорбления", "reasonId": 11},
      {"reasonTitle": "Экстремизм", "reasonId": 20},
      {"reasonTitle": "Запрещенные товары", "reasonId": 21},
      {"reasonTitle": "Другое", "reasonId": 7}
    ]},
    {"typeId": 7, "reasons": [
      {"reasonTitle": "Мошенничество", "reasonId": 8},
      {"reasonTitle": "Спам", "reasonId": 9},
      {"reasonTitle": "Порнографический контент", "reasonId": 23},
      {"reasonTitle": "Насилие", "reasonId": 18},
      {"reasonTitle": "Оскорбления", "reasonId": 11},
      {"reasonTitle": "Экстремизм", "reasonId": 20},
      {"reasonTitle": "Запрещенные товары", "reasonId": 21},
      {"reasonTitle": "Другое", "reasonId": 7}
    ]},
    {"typeId": 8, "reasons": [
      {"reasonTitle": "Спам", "reasonId": 9},
      {"reasonTitle": "Шантаж", "reasonId": 10},
      {"reasonTitle": "Оскорбления", "reasonId": 11},
      {"reasonTitle": "Другое", "reasonId": 7}
    ]},
    {"typeId": 2, "reasons": [
      {"reasonTitle": "Мошенничество", "reasonId": 8},
      {"reasonTitle": "Спам", "reasonId": 9},
      {"reasonTitle": "Порнографический контент", "reasonId": 23},
      {"reasonTitle": "Насилие", "reasonId": 18},
      {"reasonTitle": "Оскорбления", "reasonId": 11},
      {"reasonTitle": "Экстремизм", "reasonId": 20},
      {"reasonTitle": "Запрещенные товары", "reasonId": 21},
      {"reasonTitle": "Мне не нравится", "reasonId": 22},
      {"reasonTitle": "Другое", "reasonId": 7}
    ]},
    {"typeId": 6, "reasons": [
      {"reasonTitle": "Мошенничество", "reasonId": 8},
      {"reasonTitle": "Спам", "reasonId": 9},
      {"reasonTitle": "Порнографический контент", "reasonId": 23},
      {"reasonTitle": "Насилие", "reasonId": 18},
      {"reasonTitle": "Оскорбления", "reasonId": 11},
      {"reasonTitle": "Экстремизм", "reasonId": 20},
      {"reasonTitle": "Запрещенные товары", "reasonId": 21},
      {"reasonTitle": "Другое", "reasonId": 7}
    ]},
    {"typeId": 1, "reasons": [
      {"reasonTitle": "Мошенничество", "reasonId": 8},
      {"reasonTitle": "Спам", "reasonId": 9},
      {"reasonTitle": "Порнографический контент", "reasonId": 23},
      {"reasonTitle": "Насилие", "reasonId": 18},
      {"reasonTitle": "Оскорбления", "reasonId": 11},
      {"reasonTitle": "Экстремизм", "reasonId": 20},
      {"reasonTitle": "Запрещенные товары", "reasonId": 21},
      {"reasonTitle": "Другое", "reasonId": 7}
    ]}
  ]"""
