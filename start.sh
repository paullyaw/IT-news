#!/bin/bash

# Установка виртуального окружения (если необходимо)
# virtualenv venv
# source venv/bin/activate

# Установка зависимостей
pip install -r requirements.txt

# Запуск Flask-приложения
python server.py