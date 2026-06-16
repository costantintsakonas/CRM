from flask import Flask, request, render_template, flash, session, redirect
import sqlite3 
import hashlib 
from functools import wraps

app = Flask(__name__)
app.config['SESSION_TYPE'] = 'filesystem'
app.secret_key = "akjdsbkjas&^absdjkajbdkasbdksajbdksadbkbj"


def roles_permitted(roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if 'uid' in session and session['role'] in roles:
                return f(*args, **kwargs)
            else:
                flash(f'ERROR: you need {roles} role to access this page')
                return redirect('/login')
        return wrapper
    return decorator

def get_db_conn():
    db = sqlite3.connect('crm.db')
    db.row_factory = sqlite3.Row
    return db 


def initialize_db():
    db = get_db_conn()
    cursor = db.cursor() 

    cursor.execute("PRAGMA foreign_keys=ON")

    # Users table
    cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        uid INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL, 
                        password TEXT NOT NULL,
                        role TEXT DEFAULT 'employee',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        is_active TEXT DEFAULT 'active'
                    )
                   """)
  # Customers table
    cursor.execute("""
                    CREATE TABLE IF NOT EXISTS customers (
                        cid INTEGER PRIMARY KEY AUTOINCREMENT,
                        created_by_user_id INTEGER,
                        first_name TEXT NOT NULL,
                        last_name TEXT NOT NULL,
                        email TEXT NOT NULL,
                        phone TEXT,
                        company TEXT,
                        address TEXT,
                        status TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP,
                        last_contact_date TIMESTAMP
                        )
                    """)

    
    # interactions table 
    cursor.execute("""
                    CREATE TABLE IF NOT EXISTS interactions (
                        interaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        customer_id INTEGER,
                        user_id INTEGER,
                        type TEXT,
                        interaction_date TIMESTAMP,
                        subject TEXT,
                        notes TEXT,
                        customer_responded TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                   """)
    
    # Comments table 
    cursor.execute("""
                    CREATE TABLE IF NOT EXISTS comments (
                        comment_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        interaction_id INTEGER,
                        customer_id INTEGER,
                        user_id INTEGER,
                        comment_text TEXT,
                        no_response_flag TEXT,
                        created_at TIMESTAMP,
                        updated_at TIMESTAMP
                    )        
                   """)
    
    db.commit()
    db.close()


def hash_password(username, password):
    pw = username + password
    hashed = hashlib.sha512(pw.encode('utf-8')).hexdigest()
    return hashed


@app.route('/')
def home():
    return  render_template("home.html")


@app.route('/register', methods=[ 'GET', 'POST' ])
@roles_permitted(['admin'])
def register():
    username = ''
    db = get_db_conn()
    cursor = db.cursor()
    if request.method == 'POST':
        #return(f"{request.form['username']} {request.form['password']} {request.form['password2']} {request.form['role']}")
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        password2 = request.form.get('password2', '')
        role = request.form.get('role', 'employee') 
        if password != password2:
            flash("ERROR: Passwords do not match")
            return render_template('register_form.html', username=username)
        else:
            user = cursor.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if user:
                flash("ERROR: Username is taken")
                return render_template('register_form.html', username=username)
            else: 
                if role=='employee': 
                    hashed_password = hash_password(username, password)
                    cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                               (username, hashed_password, role))
                    db.commit()
                    return redirect('/admin')
                elif role=='manager':
                    hashed_password = hash_password(username, password)
                    cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                               (username, hashed_password, role))
                    db.commit()
                    return redirect('/admin')
                else:
                    flash("ERROR: Not permitted role. Select 'employee' or 'manager'")
                    return render_template('register_form.html', username=username)
                
    else:
        return render_template('register_form.html', username=username)


@app.route('/login', methods=[ 'GET', 'POST' ])
def login():
    username = ''
    db = get_db_conn()
    cursor = db.cursor()
    if request.method == 'POST':
        form = request.form
        username = form['username']
        password = form['password']
        user = cursor.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and user['is_active']=='blocked':
            flash('ERROR: This user is blocked! Please contact the Administrator')
            return redirect('/login')
        else:    
            if user:
                hashed_password = hash_password(username, password)
                if user['password'] == hashed_password:
                    session['uid'] = user['uid']
                    session['username'] = user['username']
                    session['role'] = user['role']
                    if user['role'] == 'employee':
                        return redirect('/employee')
                    elif user['role'] == 'admin':
                        return redirect('/admin')
                    elif user['role'] == 'manager':
                        return redirect('/manager')
                else:
                    flash('ERROR: wrong creedentials')
                    return render_template('login_form.html', username=username)
            else:
                flash('ERROR: username not found')
                return render_template('login_form.html', username=username)
    else: 
        return render_template('login_form.html', username=username)



@app.route('/employee')
@roles_permitted(['employee'])
def employee():
    return render_template('employee_dashboard.html')

@app.route('/manager')
@roles_permitted(['manager'])
def manager():
    return render_template('manager_dashboard.html')

@app.route('/admin')
@roles_permitted(['admin'])
def admin():
    return render_template('admin_dashboard.html')

@app.route('/users')
@roles_permitted(['admin'])
def users():
    db = get_db_conn()
    cursor = db.cursor()
    all_users = cursor.execute("SELECT * FROM users").fetchall()
    return render_template('users.html', users=all_users)

@app.route('/blocked/users')
@roles_permitted(['admin'])
def blocked_users():
    db = get_db_conn()
    cursor = db.cursor()
    blocked_users = cursor.execute("SELECT * FROM users WHERE is_active=?",('blocked',)).fetchall()
    return render_template('blocked_users.html', blocked_users=blocked_users)


@app.route('/delete/user/<int:uid>')
@roles_permitted(['admin'])
def delete_user(uid):
    try:
        db = get_db_conn()
        cursor = db.cursor()
        cursor.execute("DELETE FROM users WHERE uid = ?", (uid,))
        db.commit()
        db.close()
        return redirect('/users')
    except:
        return "ERROR: Unable to delete user"

@app.route('/edit/user/<int:uid>', methods=[ 'GET', 'POST' ])
@roles_permitted(['admin'])
def edit_user(uid):
    username = ''
    db = get_db_conn()
    cursor = db.cursor()
    if request.method == 'POST':
        username = request.form.get('username', '')
        role = request.form.get('role', 'employee') 
        status = request.form.get('status','active')
        user = cursor.execute("SELECT * FROM users WHERE uid=?", (uid,)).fetchone()
        if user:
            cursor.execute("UPDATE users SET username = ?, role=?, is_active=? WHERE uid = ?", (username, role, status, uid))
            db.commit()
            return redirect('/users')
                
        else: 
            flash("ERROR: Unable to edit user")
            return redirect('/users')
                
    else:
        db = get_db_conn()
        db.row_factory = sqlite3.Row
        cursor = db.cursor()
        user = cursor.execute("SELECT * FROM users WHERE uid = ?", (uid,)).fetchone()
        return render_template('edit_user.html', user=user)



    
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


@app.route('/add/customer', methods=[ 'GET', 'POST' ])
@roles_permitted(['employee'])
def add_customer():
    db = get_db_conn()
    cursor = db.cursor() 
    if request.method == 'POST':
        form = request.form
        name = form['first_name']
        surname = form['last_name'] 
        email = form['email'] 
        phone = form['phone'] 
        address = form['address'] 
        company = form['company'] 
        status = form['status'] 
        cursor.execute("INSERT INTO customers (first_name, last_name, created_by_user_id, email, phone,address,company,status) VALUES (?,?,?,?,?,?,?,?)",
                        (name, surname, session['uid'], email, phone, address, company, status))
        db.commit()
        return redirect('/customers')
    else:
        return render_template('add_customer.html')
    
  
@app.route('/customers')
@roles_permitted(['employee'])  
def customers():
    db = get_db_conn()
    cursor = db.cursor()
    my_customers = cursor.execute("SELECT * FROM customers WHERE created_by_user_id=?", (session['uid'],)).fetchall()
    return render_template('customers.html', my_customers=my_customers)

@app.route('/delete/customer/<int:cid>')
@roles_permitted(['employee'])
def delete_customer(cid):
    try:
        db = get_db_conn()
        cursor = db.cursor()
        cursor.execute("DELETE FROM customers WHERE cid = ?", (cid,))
        db.commit()
        db.close()
        return redirect('/customers')
    except:
        return "ERROR: Unable to delete customer"

@app.route('/edit/customer/<int:cid>', methods=[ 'GET', 'POST' ])
@roles_permitted(['employee'])
def edit_customer(cid):
    username = ''
    db = get_db_conn()
    cursor = db.cursor()
    if request.method == 'POST':
        name = request.form.get('first_name', '')
        surname = request.form.get('last_name', '')
        email = request.form.get('email', '') 
        phone = request.form.get('phone','')
        address = request.form.get('address','')
        company = request.form.get('company','')
        status = request.form.get('status','lead')
        customer = cursor.execute("SELECT * FROM customers WHERE cid=?", (cid,)).fetchone()
        if customer:
            cursor.execute("UPDATE customers SET first_name = ?, last_name=?, email=?, phone=?, address=?, company=?, status=?   WHERE cid = ?", 
                           (name, surname, email, phone, address, company,status, cid ))
            db.commit()
            return redirect('/customers')
                
        else: 
            flash("ERROR: Unable to edit customer")
            return redirect('/customers')
                
    else:
        db = get_db_conn()
        db.row_factory = sqlite3.Row
        cursor = db.cursor()
        customer = cursor.execute("SELECT * FROM customers WHERE cid = ?", (cid,)).fetchone()
        return render_template('edit_customer.html', customer=customer)

@app.route('/customer/history/<int:cid>')
@roles_permitted(['employee'])
def customer_history(cid):
    db = get_db_conn()
    cursor = db.cursor()
    interactions = cursor.execute("SELECT * FROM interactions WHERE customer_id=?", (cid,)).fetchall()
    return render_template('customer_history.html', interactions=interactions, cid=cid)

@app.route('/add/interaction/<int:cid>', methods=[ 'GET', 'POST' ])
@roles_permitted(['employee'])
def add_interaction(cid):
    db = get_db_conn()
    cursor = db.cursor() 
    if request.method == 'POST':
        form = request.form
        user_id = form.get('user_id','')
        type = form.get('type','') 
        interaction_date = form.get('interaction_date','')
        subject = form.get('subject','')
        notes = form.get('notes','')
        customer_responded = form.get('customer_responded','') 
        
        cursor.execute("INSERT INTO interactions (customer_id, user_id, type, interaction_date, subject, notes,customer_responded) VALUES (?,?,?,?,?,?,?)",
                        (cid, session['uid'], type, interaction_date, subject, notes, customer_responded))
        db.commit()
        interactions = cursor.execute("SELECT * FROM interactions WHERE customer_id=?", (cid,)).fetchall()
        return render_template('customer_history.html', interactions=interactions, cid=cid)
    else:
        return render_template('add_interaction.html', cid=cid)
    
@app.route('/edit/interaction/<int:iid>', methods=[ 'GET', 'POST' ])
@roles_permitted(['employee'])
def edit_interaction(iid):
    db = get_db_conn()
    cursor = db.cursor()
    if request.method == 'POST':
        form = request.form
        user_id = form.get('user_id','')
        customer_id=form.get('customer_id','')
        type = form.get('type','') 
        interaction_date = form.get('interaction_date','')
        subject = form.get('subject','')
        notes = form.get('notes','')
        customer_responded = form.get('customer_responded','') 
        interaction = cursor.execute("SELECT * FROM interactions WHERE interaction_id=?", (iid,)).fetchone()
        if interaction:
            cursor.execute("UPDATE interactions SET user_id = ?, customer_id=?, type=?, interaction_date=?, subject=?, notes=?, customer_responded=?   WHERE interaction_id = ?", 
                           (user_id, customer_id, type, interaction_date, subject, notes,customer_responded, iid ))
            db.commit()
            return redirect('/customers')
                
        else: 
            flash("ERROR: Unable to edit interaction")
            return redirect('/customers')
                
    else:
        db = get_db_conn()
        db.row_factory = sqlite3.Row
        cursor = db.cursor()
        interactions = cursor.execute("SELECT * FROM interactions WHERE interaction_id=?", (iid,)).fetchone()
        return render_template('edit_interaction.html', interactions=interactions)

if __name__ == '__main__':
    initialize_db()
    app.run(debug=True)