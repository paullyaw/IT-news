from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, session, flash, make_response, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, Length
import os
from flask_restful import abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests
import json
import schedule
import time
from bs4 import BeautifulSoup
