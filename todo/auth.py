import functools 

from flask import (
    Blueprint, flash, g, render_template, request, url_for, session, redirect
)

from werkzeug.security import check_password_hash, generate_password_hash

from todo.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db, c = get_db()
        error = None
        c.execute(
            'select id from user where username = %s', (username,)
        )
        if not username:
            error = 'Username es requerido'
        if not password:
            error= 'Password es requerido'
        elif c.fetchone() is not None:
            error = 'Usuario {} se encuentra registrado.'.format(username)  #Las llaves son para indicar que username va allí, solo se usa con .format
        
        if error is None:
            c.execute(
                'insert into user (username, password) values (%s, %s)',
                (username, generate_password_hash(password))  #generate_password_hash sirve para encriptar la contraseña
            )
            db.commit()

            return redirect(url_for('auth.login'))
        
        flash(error)  #mensaje flash

    return render_template('auth/register.html') #Esto se va a mandar al usuario en caso que no haga una peticion POST, es deir GET

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db, c = get_db()        
        error = None
        c.execute(
            'select * from user where username = %s', (username,)
        )
        user = c.fetchone()

        if user is None:
            error = 'Usuario y/o contraseña invalida'
        elif not check_password_hash(user['password'], password):
            error = 'Usuario y/o contraseña invalida'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('todo.index'))

        flash(error)

    return render_template('auth/login.html')

# Asiganamos el usuario a g
@bp.before_app_request
def load_logger_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        db, c = get_db()
        c.execute(
            'select * from user where id = %s', (user_id,)
        )
        g.user = c.fetchone()  #Retorna una lista de diccionario y solo nos manda el primero que encuentre




#Protegemos nuestro inicio de sesión
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return render_template(url_for('auth.login'))
        
        return view(**kwargs)

    return wrapped_view

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))