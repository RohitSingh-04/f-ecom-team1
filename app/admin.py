from flask import Blueprint, request, jsonify, get_flashed_messages, redirect, url_for, render_template
from datetime import datetime, timezone, timedelta
from flask_login import login_required, current_user
from .models import db, User, Product, Order, ProductAddLogs
from .decorators import is_admin
from .forms import AddItemForm
from .methods import send_approval_email
from werkzeug.security import generate_password_hash
from .visualization import Visualize
import base64
from sqlalchemy import func

import random
import string
from sqlalchemy.exc import IntegrityError

# Define the admin blueprint
admin = Blueprint('admin', __name__)

#Define the Visualization Object
visualize = Visualize()

# Define the route to add shop items
@admin.route('/add-shop-items', methods=['POST'])
def add_shop_items():
    form = AddItemForm(meta={'csrf': False})  # Disable CSRF for API requests

    if not form.validate_on_submit():
        return jsonify({'message': 'Validation failed', 'errors': form.errors}), 400

    try:
        # Create a new product from form data
        new_product = Product(
            name=form.name.data,
            description=form.description.data,
            price=form.price.data,
            stock_quantity=form.stock_quantity.data,
            brand=form.brand.data,
            category=form.category.data,
            updated_at=form.updated_at.data if form.updated_at.data else datetime.utcnow(),
            rating=form.rating.data,
            ratting=form.ratting.data
        )

        # Add the product to the database
        db.session.add(new_product)
        db.session.commit()

        return jsonify({'message': 'Product added successfully'}), 201
    except Exception as e:
        db.session.rollback()  # Rollback transaction in case of error
        return jsonify({'message': f'An error occurred: {str(e)}'}), 500
    finally:
        db.session.close()  # Ensure the session is closed


# Define the route to remove shop items
@admin.route('/remove-shop-items/<int:product_id>', methods=['DELETE'])
@login_required
def remove_shop_items(product_id):
    try:
        # Query the product by ID
        product = Product.query.get(product_id)

        # Check if the product exists
        if not product:
            return jsonify({'message': 'Product not found'}), 404

        # Remove the product from the database
        db.session.delete(product)
        db.session.commit()

        return jsonify({'message': 'Product removed successfully'}), 200
    except Exception as e:
        db.session.rollback()  # Rollback transaction in case of error
        return jsonify({'message': f'An error occurred: {str(e)}'}), 500
    finally:
        db.session.close()  # Ensure the session is closed

@admin.route('/approve-delivery-dashboard')
@login_required
@is_admin
def approve_delivery_dashboard():
    delivery_user_request = User.query.filter_by(role='delivery', approved = False).all()
    get_flashed_messages()
    return render_template('approve_delivery.html', delivery_persons=delivery_user_request)

@admin.route("/delete-user/<int:user_id>", methods = ["DELETE"])
@login_required
@is_admin
def delete_user(user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'message': 'User not found'}), 404

        db.session.delete(user)
        db.session.commit()
        send_approval_email(user.email, user.firstname, False)
        return jsonify({'message': 'User deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'An error occurred: {str(e)}'}), 500
    finally:
        db.session.close()

@admin.route("/approve-user/<int:user_id>", methods = ["POST"])
@login_required
@is_admin
def approve_user(user_id):
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'message': 'User not found'}), 404

        user.approved = True
        db.session.commit()
        send_approval_email(user.email, user.firstname, True)
        return jsonify({'message': 'User approved successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'An error occurred: {str(e)}'}), 500
    finally:
        db.session.close()

#view for chart dashboards
@admin.route("/stats")
@login_required
@is_admin
def stats():
    return render_template('stats.html')

#chart 1 : new and returning customers records
@admin.route('/chart1')
@login_required
@is_admin
def show_chart1():

    first_order_dates = db.session.query(
        Order.customer_id,
        func.min(func.date(Order.order_date)).label('first_order_date')
    ).group_by(Order.customer_id).subquery()

    # Query to calculate new and returning customers per order_date
    stats = db.session.query(
        func.date(Order.order_date).label('order_date'),
        func.count(func.distinct(Order.customer_id)).filter(
            Order.customer_id.in_(
                db.session.query(first_order_dates.c.customer_id).filter(
                    func.date(Order.order_date) == first_order_dates.c.first_order_date
                )
            )
        ).label('new_customers'),
        func.count(func.distinct(Order.customer_id)).filter(
            Order.customer_id.notin_(
                db.session.query(first_order_dates.c.customer_id).filter(
                    func.date(Order.order_date) == first_order_dates.c.first_order_date
                )
            )
        ).label('returning_customers')
    ).group_by(func.date(Order.order_date)).all()

    data = [[] for _ in range(3)]

    for row in stats:
        data[0].append(str(row.order_date))
        data[1].append(row.new_customers)
        data[2].append(row.returning_customers)

    img = visualize.generate_new_old_customers_graph(data[0], data[1], data[2])

    img = base64.b64encode(img.getvalue()).decode('utf8')

    return render_template('show_graph.html', img = img, context = {"graph_name" : "New and Returning Customers", "data" : [[data[0][i], data[1][i], data[2][i]] for i in range(len(data[0]))],  "Attributes": ["Order Date", "New Customers", "Returning Customers"]})

@admin.route('/chart2')
@login_required
@is_admin
def show_chart2():
    sales_data = db.session.query(
        func.date(Order.order_date).label('date'),
        func.sum(Order.price).label('total_sales')
    ).group_by(
        func.date(Order.order_date)
    ).order_by(
        func.date(Order.order_date)
    ).all()

    data = [[],[]]

    for row in sales_data:
        data[0].append(str(row.date))
        data[1].append(row.total_sales)
    
    img = visualize.generate_revenue_overtime_graph(data[0], data[1])
    img = base64.b64encode(img.getvalue()).decode('utf8')
    return render_template('show_graph.html', img = img, context = {"graph_name" : "Revenue Over Time", "data" : [[data[0][i], round(data[1][i], 2)] for i in range(len(data[0]))], "Attributes": ["Date", "Total Sales"]})

@admin.route('/chart3')
@login_required
@is_admin
def show_chart3():
    results = (
    db.session.query(Order.status, func.count(Order.status))
    .group_by(Order.status)
    .order_by(Order.status)
    .all()
    )

    status = [result[0] for result in results]
    count = [result[1] for result in results]

    img = visualize.generate_order_status_graph(status, count)
    img = base64.b64encode(img.getvalue()).decode('utf8')
    return render_template('show_graph.html', img = img, context = {"graph_name" : "Order Status", "data" : [[status[i], count[i]] for i in range(len(status))], "Attributes": ["Status", "Count"]})

@admin.route('/chart4')
@login_required
@is_admin
def show_chart4():
    results = (
    db.session.query(Product.category, func.sum(Product.stock_quantity))
    .group_by(Product.category).all())

    products = []
    stocks = []

    for row in results:
        products.append(row[0])
        stocks.append(row[1])
    
    img = visualize.generate_inventory_stocks_graph(products, stocks)
    img = base64.b64encode(img.getvalue()).decode('utf8')
    return render_template('inventory_stocks_insights.html', img = img, context = {"graph_name" : "Inventory Stock Levels", "data" : [[products[i], stocks[i]] for i in range(len(products))], "Attributes": ["Category", "Stock"]})

@admin.route('/chart5')
@login_required
@is_admin
def show_chart5():
    results_expenses = db.session.query(
        func.date(ProductAddLogs.date_added).label('date'),  # Group by date only (ignore time part)
        func.sum(ProductAddLogs.cost).label('total_cost')
    ).group_by(func.date(ProductAddLogs.date_added)).all()
    sales_data = db.session.query(
        func.date(Order.order_date).label('date'),
        func.sum(Order.price).label('total_sales')
    ).group_by(
        func.date(Order.order_date)
    ).order_by(
        func.date(Order.order_date)
    ).all()

    dates = [str(result.date) for result in results_expenses]
    expenses = [round(result.total_cost, 2) for result in results_expenses]
    revenue = [round(result.total_sales, 2) for result in sales_data]

    img = visualize.generate_finantial_overview_graph(dates, expenses, revenue)
    img = base64.b64encode(img.getvalue()).decode('utf8')

    return render_template("show_graph.html", img = img, context = {"graph_name" : "Finantial Overview", "data" : [[dates[i], expenses[i], revenue[i], round(revenue[i]-expenses[i],2)] for i in range(len(dates))], "Attributes": ["Date", "Expenses", "Revenue", "Profits"]} )


@admin.route('/get-stock-chart/<category>', methods = ["GET"])
@login_required
@is_admin
def get_chart(category):
    if request.method == "GET":
        products = Product.query.filter(Product.category == category).all()
        products_name = [product.name for product in products]
        products_stocks = [product.stock_quantity for product in products]

        img = visualize.generate_inventory_stocks_graph(products_name, products_stocks, category)
        img = base64.b64encode(img.getvalue()).decode('utf8')

        return jsonify({"image": img, "data": [products_name, products_stocks]})


# dummy to be removed later
@admin.route('/make_me_admin')
@login_required
def make_me_admin():
    if not current_user.isAdmin():
        current_user.role = 'admin'
        db.session.commit()
    return redirect(url_for('views.home'))


# Generate random data for users
def generate_random_user_data():
    firstname = ''.join(random.choices(string.ascii_letters, k=8)).capitalize()
    lastname = ''.join(random.choices(string.ascii_letters, k=10)).capitalize()
    email = f"{firstname.lower()}.{lastname.lower()}@example.com"
    address_line_1 = f"{random.randint(1, 999)} {random.choice(['Main St', 'Second St', 'Broadway'])}"
    state = random.choice(['State1', 'State2', 'State3', 'State4'])
    city = random.choice(['CityA', 'CityB', 'CityC', 'CityD'])
    role = "user"
    pincode = f"{random.randint(10000, 99999)}"
    password = generate_password_hash('password123')  # You can change the password
    return firstname, lastname, email, address_line_1, state, city, role, pincode, password

# Helper function to generate random product data
def generate_random_product_data():
    name = f"Product {''.join(random.choices(string.ascii_uppercase, k=3))}"
    price = round(random.uniform(10, 1000), 2)
    stock_quantity = random.randint(1, 100)
    brand = random.choice(["BrandA", "BrandB", "BrandC"])
    size = random.choice(["Small", "Medium", "Large"])
    target_user = random.choice(["Men", "Women", "Kids"])
    type_ = random.choice(["Type1", "Type2", "Type3"])
    image = "https://via.placeholder.com/150"
    description = "Lorem ipsum dolor sit amet."
    details = "Detailed description here."
    colour = random.choice(["Red", "Blue", "Green", "Black"])
    category = random.choice(["Category1", "Category2", "Category3"])
    return name, price, stock_quantity, brand, size, target_user, type_, image, description, details, colour, category

#add dummy users
@admin.route('/add-dummy-users')
@login_required
@is_admin
def addusers():
    dummy_users = []
    failed_users = []
    for _ in range(100):
        firstname, lastname, email, address_line_1, state, city, role, pincode, password = generate_random_user_data()
        user = User(
            firstname=firstname,
            lastname=lastname,
            email=email,
            address_line_1=address_line_1,
            state=state,
            city=city,
            role=role,
            pincode=pincode,
            password=password
        )
        try:
            db.session.add(user)
            db.session.commit()  # Commit inside try to catch IntegrityError
            dummy_users.append(email)
        except IntegrityError:
            db.session.rollback()  # Roll back the session to handle the exception
            failed_users.append(email)

    return jsonify({
        "message": "100 dummy users attempted to be created.",
        "created_users": dummy_users,
        "failed_users": failed_users
    })


created_product_ids = []
created_order_ids = []
# Route to create 50 dummy products
@admin.route('/create-dummy-products')
def create_dummy_products():

    global created_product_ids

    dummy_products = []
    
    for _ in range(50):
        name, price, stock_quantity, brand, size, target_user, type_, image, description, details, colour, category = generate_random_product_data()
        product = Product(name=name, price=price, stock_quantity=stock_quantity, brand=brand, size=size,
                          target_user=target_user, type=type_, image=image, description=description,
                          details=details, colour=colour, category=category)
        try:
            db.session.add(product)
            db.session.commit()
            created_product_ids.append(product.id)  # Track the created product ID
            dummy_products.append(name)
        except IntegrityError:
            db.session.rollback()
    
    return jsonify({"message": f"{len(dummy_products)} dummy products attempted to be created.", "created_products": dummy_products})


@admin.route('/create-dummy-orders')
@login_required
@is_admin
def create_dummy_orders():
    # Get all users and products to pick from randomly
    users = User.query.all()
    products = Product.query.all()

    if not users or not products:
        return jsonify({"message": "No users or products available to create orders."})

    # Track orders created
    global create_dummy_orders
    
    # Generate orders for every date in the last 3 months
    today = datetime.now(timezone.utc)
    start_date = today - timedelta(days=90)  # 3 months ago

    for delta in range(91):  # Generate orders for each day in the last 3 months
        order_date = start_date + timedelta(days=delta)
        
        for _ in range(random.randint(30, 40)):  # 30 to 40 orders per day
            # Randomly select a user and a product
            customer = random.choice(users)
            product = random.choice(products)
            
            # Randomly generate price and status
            price = round(random.uniform(10, 500), 2)  # Random price between 10 and 500
            status = random.choice(['Pending', 'Shipped', 'Delivered', 'Cancelled'])  # Random status
            
            # Create the order
            order = Order(customer_id=customer.id, product_id=product.id, price=price, status=status, order_date=order_date)
            
            try:
                db.session.add(order)
                db.session.commit()
                created_order_ids.append(order.id)  # Track created order IDs
            except IntegrityError:
                db.session.rollback()

    return jsonify({"message": "Dummy orders created.", "created_orders": created_order_ids})


# Route to create dummy entries for ProductAddLogs for products within the past 90 days
@admin.route('/create-dummy-product-add-logs')
@login_required
@is_admin
def create_dummy_product_add_logs():
    # Track dummy log entries created
    created_logs = []

    # Get all products created in the past 90 days
    today = datetime.now(timezone.utc)
    start_date = today - timedelta(days=90)
    products = Product.query.all()

    for product in products:
        # Create random log entries for each product within the last 90 days
        for _ in range(random.randint(1, 5)):  # Randomly create 1 to 5 log entries per product
            quantity = random.randint(1, 50)  # Random quantity added
            cost = round(random.uniform(5, 1000), 2)  # Random cost between 5 and 1000

            log = ProductAddLogs(
                product_id=product.id,
                quantity=quantity,
                cost=cost,
                date_added=random.choice([start_date + timedelta(days=i) for i in range(90)])  # Random date within the last 90 days
            )

            try:
                db.session.add(log)
                db.session.commit()
                created_logs.append(f"Product ID {product.id}, Quantity {quantity}, Cost {cost}")
            except IntegrityError:
                db.session.rollback()  # In case of a database error

    return jsonify({
        "message": f"Dummy product add logs created for {len(created_logs)} entries.",
        "created_logs": created_logs
    })
