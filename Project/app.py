from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import logging
import uuid
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inventory.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your-secret-key-here'

# Extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

logging.basicConfig(level=logging.INFO)

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Product(db.Model):
    product_id = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, default=0)
    price = db.Column(db.Float, default=0.0)

class Location(db.Model):
    location_id = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(100), nullable=False)

class ProductMovement(db.Model):
    movement_id = db.Column(db.String(50), primary_key=True)
    product_id = db.Column(db.String(50), db.ForeignKey('product.product_id'))
    from_location_id = db.Column(db.String(50), db.ForeignKey('location.location_id'))
    to_location_id = db.Column(db.String(50), db.ForeignKey('location.location_id'))
    qty = db.Column(db.Integer, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

    product = db.relationship('Product', backref=db.backref('product_movements', lazy=True))
    from_location = db.relationship('Location', foreign_keys=[from_location_id], backref=db.backref('from_movements', lazy=True))
    to_location = db.relationship('Location', foreign_keys=[to_location_id], backref=db.backref('to_movements', lazy=True))

class BuyMovement(db.Model):
    movement_id = db.Column(db.String(50), primary_key=True)
    product_id = db.Column(db.String(50), db.ForeignKey('product.product_id'))
    to_location_id = db.Column(db.String(50), db.ForeignKey('location.location_id'))
    movement_qty = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

    product = db.relationship('Product', backref=db.backref('buy_movements', lazy=True))
    to_location = db.relationship('Location', backref=db.backref('buy_movements', lazy=True))

class SaleMovement(db.Model):
    movement_id = db.Column(db.String(50), primary_key=True)
    product_id = db.Column(db.String(50), db.ForeignKey('product.product_id'))
    from_location_id = db.Column(db.String(50), db.ForeignKey('location.location_id'))
    movement_qty = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)

    product = db.relationship('Product', backref=db.backref('sale_movements', lazy=True))
    from_location = db.relationship('Location', foreign_keys=[from_location_id], backref=db.backref('sale_movements', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def get_product_quantity(product_id, location_id):
    total_in = db.session.query(db.func.sum(ProductMovement.qty)).filter_by(product_id=product_id, to_location_id=location_id).scalar() or 0
    total_out = db.session.query(db.func.sum(ProductMovement.qty)).filter_by(product_id=product_id, from_location_id=location_id).scalar() or 0
    total_buys = db.session.query(db.func.sum(BuyMovement.movement_qty)).filter_by(product_id=product_id, to_location_id=location_id).scalar() or 0
    total_sales = db.session.query(db.func.sum(SaleMovement.movement_qty)).filter_by(product_id=product_id, from_location_id=location_id).scalar() or 0
    return total_in - total_out + total_buys - total_sales

def update_product_quantity(product_id):
    product = Product.query.get(product_id)
    if product:
        total_quantity = sum(get_product_quantity(product_id, loc.location_id) for loc in Location.query.all())
        product.quantity = total_quantity
        db.session.commit()

# Auth Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not all([username, password, confirm_password]):
            flash('All fields are required.', 'danger')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already taken.', 'danger')
            return redirect(url_for('register'))

        try:
            user = User(username=username)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Registration failed: {str(e)}', 'danger')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(request.args.get('next') or url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Main Routes
@app.route('/')
@app.route('/home')
@login_required
def home():
    product_count = Product.query.count()
    location_count = Location.query.count()
    total_movements = (
        ProductMovement.query.count() +
        BuyMovement.query.count() +
        SaleMovement.query.count()
    )
    return render_template(
        'home.html',
        product_count=product_count,
        location_count=location_count,
        total_movements=total_movements
    )

@app.route('/products', methods=['GET', 'POST'])
@login_required
def products():
    if request.method == 'POST':
        name = request.form['name'].strip()
        quantity = request.form['quantity']
        price = request.form['price']

        if not name:
            flash('Product name cannot be empty.', 'danger')
            return redirect(url_for('products'))

        if Product.query.filter_by(name=name).first():
            flash('Product name already exists.', 'danger')
            return redirect(url_for('products'))

        try:
            quantity = int(quantity)
            if quantity < 0:
                raise ValueError("Quantity cannot be negative.")
        except ValueError:
            flash('Enter a valid non-negative integer for quantity.', 'danger')
            return redirect(url_for('products'))

        try:
            price = float(price)
            if price < 0:
                raise ValueError("Price cannot be negative.")
        except ValueError:
            flash('Enter a valid non-negative number for price.', 'danger')
            return redirect(url_for('products'))

        product_id = f"Pid___{Product.query.count() + 1:05d}"
        product = Product(product_id=product_id, name=name, quantity=quantity, price=price)
        db.session.add(product)
        db.session.commit()
        flash('Product added!', 'success')
        return redirect(url_for('products'))

    products = Product.query.order_by(Product.name).all()
    return render_template('products.html', products=products)

@app.route('/edit_product/<product_id>', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)
    if request.method == 'POST':
        new_name = request.form['name'].strip()
        new_quantity = request.form['quantity']
        new_price = request.form['price']

        if not new_name:
            flash('Product name cannot be empty.', 'danger')
            return redirect(url_for('edit_product', product_id=product_id))

        if new_name != product.name and Product.query.filter_by(name=new_name).first():
            flash('Product name already exists.', 'danger')
            return redirect(url_for('edit_product', product_id=product_id))

        try:
            new_quantity = int(new_quantity)
            new_price = float(new_price)
            if new_quantity < 0 or new_price < 0:
                raise ValueError("Values cannot be negative.")
        except ValueError as e:
            flash(f'Invalid input: {str(e)}', 'danger')
            return redirect(url_for('edit_product', product_id=product_id))

        product.name = new_name
        product.quantity = new_quantity
        product.price = new_price
        db.session.commit()
        flash('Product updated!', 'success')
        return redirect(url_for('products'))

    return render_template('edit_product.html', product=product)

@app.route('/delete_product/<product_id>', methods=['POST'])
@login_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    has_movements = any([
        ProductMovement.query.filter_by(product_id=product_id).first(),
        BuyMovement.query.filter_by(product_id=product_id).first(),
        SaleMovement.query.filter_by(product_id=product_id).first()
    ])

    if has_movements:
        flash('Cannot delete product with movement records.', 'danger')
    else:
        db.session.delete(product)
        db.session.commit()
        flash('Product deleted.', 'success')
    return redirect(url_for('products'))

@app.route('/locations', methods=['GET', 'POST'])
@login_required
def locations():
    if request.method == 'POST':
        name = request.form['name'].strip()

        if not name:
            flash('Location name cannot be empty.', 'danger')
            return redirect(url_for('locations'))

        if Location.query.filter_by(name=name).first():
            flash('Location name already exists.', 'danger')
            return redirect(url_for('locations'))

        location = Location(
            location_id=f"Lid___{Location.query.count() + 1:05d}",
            name=name
        )
        db.session.add(location)
        db.session.commit()
        flash('Location added!', 'success')
        return redirect(url_for('locations'))

    locations = Location.query.order_by(Location.name).all()
    return render_template('locations.html', locations=locations)

@app.route('/edit_location/<location_id>', methods=['GET', 'POST'])
@login_required
def edit_location(location_id):
    location = Location.query.get_or_404(location_id)
    if request.method == 'POST':
        new_name = request.form['name'].strip()

        if not new_name:
            flash('Location name cannot be empty.', 'danger')
            return redirect(url_for('edit_location', location_id=location_id))

        if new_name != location.name and Location.query.filter_by(name=new_name).first():
            flash('Location name already exists.', 'danger')
            return redirect(url_for('edit_location', location_id=location_id))

        location.name = new_name
        db.session.commit()
        flash('Location updated.', 'success')
        return redirect(url_for('locations'))

    return render_template('edit_location.html', location=location)

@app.route('/delete_location/<location_id>', methods=['POST'])
@login_required
def delete_location(location_id):
    location = Location.query.get_or_404(location_id)
    has_movements = any([
        ProductMovement.query.filter(
            (ProductMovement.from_location_id == location_id) |
            (ProductMovement.to_location_id == location_id)
        ).first(),
        BuyMovement.query.filter_by(to_location_id=location_id).first(),
        SaleMovement.query.filter_by(from_location_id=location_id).first()
    ])

    if has_movements:
        flash('Cannot delete location with movement records.', 'danger')
    else:
        db.session.delete(location)
        db.session.commit()
        flash('Location deleted.', 'success')
    return redirect(url_for('locations'))

# ---------- Movement Routes ----------
@app.route('/movements', methods=['GET', 'POST'])
@login_required
def movements():
    if request.method == 'POST':
        movement_type = request.form['movement_type']

        try:
            if movement_type == 'buy':
                movement = BuyMovement(
                    movement_id=str(uuid.uuid4()),
                    product_id=request.form['product_id'],
                    to_location_id=request.form['to_location'],
                    movement_qty=int(request.form['qty']),
                    price=float(request.form['price']),
                    date=datetime.utcnow()
                )
            elif movement_type == 'sale':
                available = get_product_quantity(
                    request.form['product_id'],
                    request.form['from_location']
                )
                if available < int(request.form['qty']):
                    flash(f'Only {available} units available!', 'danger')
                    return redirect(url_for('movements'))

                movement = SaleMovement(
                    movement_id=str(uuid.uuid4()),
                    product_id=request.form['product_id'],
                    from_location_id=request.form['from_location'],
                    movement_qty=int(request.form['qty']),
                    price=float(request.form['price']),
                    date=datetime.utcnow()
                )
            elif movement_type == 'transfer':
                from_location = request.form['from_location']
                to_location = request.form['to_location']

                if from_location == to_location:
                    flash('Cannot transfer to the same location!', 'danger')
                    return redirect(url_for('movements'))

                available = get_product_quantity(
                    request.form['product_id'],
                    request.form['from_location']
                )

                if available < int(request.form['qty']):
                    flash(f'Only {available} units available!', 'danger')
                    return redirect(url_for('movements'))

                movement = ProductMovement(
                    movement_id=str(uuid.uuid4()),
                    product_id=request.form['product_id'],
                    from_location_id=request.form['from_location'],
                    to_location_id=request.form['to_location'],
                    qty=int(request.form['qty']),
                    date=datetime.utcnow()
                )

            db.session.add(movement)
            db.session.commit()
            update_product_quantity(request.form['product_id'])
            flash(f'{movement_type.capitalize()} recorded successfully!', 'success')
            return redirect(url_for('movements'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'danger')

    transfers = ProductMovement.query.all()
    buys = BuyMovement.query.all()
    sales = SaleMovement.query.all()

    all_movements = []
    all_movements.extend([('transfer', m) for m in transfers])
    all_movements.extend([('buy', m) for m in buys])
    all_movements.extend([('sale', m) for m in sales])

    all_movements.sort(key=lambda x: x[1].date, reverse=True)

    return render_template('movements.html',
                           movements=all_movements,
                           products=Product.query.all(),
                           locations=Location.query.all())

@app.route('/delete_sale/<movement_id>', methods=['POST'])
@login_required
def delete_sale(movement_id):
    try:
        movement = SaleMovement.query.get_or_404(movement_id)
        product_id = movement.product_id
        db.session.delete(movement)
        db.session.commit()
        update_product_quantity(product_id)
        flash('Sale deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting sale: {str(e)}', 'danger')
    return redirect(url_for('movements'))

@app.route('/delete_buy/<movement_id>', methods=['POST'])
@login_required
def delete_buy(movement_id):
    try:
        movement = BuyMovement.query.get_or_404(movement_id)
        product_id = movement.product_id
        db.session.delete(movement)
        db.session.commit()
        update_product_quantity(product_id)
        flash('Purchase deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting purchase: {str(e)}', 'danger')
    return redirect(url_for('movements'))

@app.route('/delete_transfer/<movement_id>', methods=['POST'])
@login_required
def delete_transfer(movement_id):
    try:
        movement = ProductMovement.query.get_or_404(movement_id)
        product_id = movement.product_id
        db.session.delete(movement)
        db.session.commit()
        update_product_quantity(product_id)
        flash('Transfer deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting transfer: {str(e)}', 'danger')
    return redirect(url_for('movements'))

@app.route('/report')
@login_required
def report():
    try:
        products = Product.query.all()
        locations = Location.query.all()
        stock_data = {location.name: {product.name: 0 for product in products} for location in locations}

        product_movements = ProductMovement.query.all()
        buy_movements = BuyMovement.query.all()
        sale_movements = SaleMovement.query.all()

        for move in product_movements:
            if move.to_location and move.product and move.qty > 0:
                if move.to_location.name in stock_data and move.product.name in stock_data[move.to_location.name]:
                    stock_data[move.to_location.name][move.product.name] += move.qty
            if move.from_location and move.product and move.qty > 0:
                if move.from_location.name in stock_data and move.product.name in stock_data[move.from_location.name]:
                    stock_data[move.from_location.name][move.product.name] -= move.qty

        for buy in buy_movements:
            if buy.to_location and buy.product and buy.movement_qty > 0:
                if buy.to_location.name in stock_data and buy.product.name in stock_data[buy.to_location.name]:
                    stock_data[buy.to_location.name][buy.product.name] += buy.movement_qty

        for sale in sale_movements:
            if sale.from_location and sale.product and sale.movement_qty > 0:
                if sale.from_location.name in stock_data and sale.product.name in stock_data[sale.from_location.name]:
                    stock_data[sale.from_location.name][sale.product.name] -= sale.movement_qty

        return render_template('report.html', products=products, locations=locations, stock_data=stock_data)
    except Exception as e:
        logging.error(f"Error generating report: {e}", exc_info=True)
        flash(f"Error generating the stock report: {str(e)}", 'danger')
        return render_template('report.html', products=[], locations=[], stock_data={})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)