from flask import Blueprint, render_template, get_flashed_messages, redirect, url_for, Response, flash, request, session, jsonify
from flask_login import login_required, current_user
from .models import db
from .forms import UpdateUserForm
from .decorators import is_delivery_person, is_admin
from .constants import STATES_CITY
bp = Blueprint('views', __name__)
from .models import Product, Order, Stats
import os
import logging
from werkzeug.utils import secure_filename



# Dummy Product Data (for rendering)
products = [
    {
        'id': 1,
        'name': 'Classic White Shirt',
        'price': 1999,
        'image': 'static/Products/white.jpeg',
        'description': 'A timeless classic for any wardrobe, perfect for both formal and casual occasions.',
        'details': [
            'Made from 100% premium cotton.',
            'Breathable and comfortable for all-day wear.',
            'Available in multiple sizes for the perfect fit.',
            'Machine washable and easy to maintain.',
            'Perfect for office, events, and everyday use.'
        ],
        'stock': 2,
        'category': 'Clothing',
        'brand':'Wrogn',
        'colour': 'White',
        'target_user':'Men',
        'type': 'Shirt'
    },
    {
        'id': 2,
        'name': 'Denim Jacket',
        'price': 3499,
        'image': 'static/Products/dDenim Jacket.jpeg',
        'description': 'A stylish denim jacket that adds an edgy touch to your outfit.',
        'details': [
            'Durable and soft denim fabric.',
            'Slim-fit design with button closure.',
            'Features side pockets and a classic collar.',
            'Perfect for layering in any season.',
            'Hand-wash recommended for extended durability.'
        ],
        'stock': 2,
        'category': 'Clothing',
        'brand':'Levis',
        'colour': 'Blue',
        'target_user':'Men',
        'type': 'Jacket'
    },
    {
        'id': 3,
        'name': 'Summer Floral Dress',
        'price': 2799,
        'image': 'static/Products/dSummer Floral Dress.jpeg',
        'description': 'A breezy floral dress ideal for summer outings and vacations.',
        'details': [
            'Lightweight, flowy material for comfort.',
            'Beautiful floral prints with vibrant colors.',
            'Adjustable straps for a customized fit.',
            'Perfect for brunches, picnics, or beach outings.',
            'Machine washable and fade-resistant.'
        ],
        'stock': 2,
        'category': 'Clothing',
        'brand':'Zara',
        'colour': 'orange',
        'target_user':['Women','girls'],
        'type': 'Dress'
    },
    {
        'id': 4,
        'name': 'Leather Wallet',
        'price': 1299,
        'image': 'static/Products/Leather Wallet.jpeg',
        'description': 'A sleek and functional leather wallet for everyday use.',
        'details': [
            'Crafted from genuine leather for durability.',
            'Multiple compartments for cards and cash.',
            'Compact design to fit in any pocket.',
            'Available in black and brown colors.',
            'A great gift for friends and family.'
        ],
        'stock': 2,
        'category': 'Accessories',
        'brand':'Puma',
        'colour': 'Brown',
        'target_user':'Men',
        'type': 'Wallet'
    },
    {
        'id': 5,
        'name': 'Running Shoes',
        'price': 3999,
        'image': 'static/Products/shoes.jpeg',
        'description': 'High-performance running shoes for athletes and fitness enthusiasts.',
        'details': [
            'Breathable mesh upper for ventilation.',
            'Cushioned sole for maximum comfort.',
            'Slip-resistant outsole for stability.',
            'Lightweight design for enhanced speed.',
            'Available in various sizes and colors.'
        ],
        'stock': 0,
        'category': 'Footwear',
        'brand':'Campus',
        'colour': 'Blue',
        'target_user':'Men',
        'type': 'Shoes'
    },
    # Additional 10 dummy products
    {
        'id': 6,
        'name': 'Silk Tie Set',
        'price': 999,
        'image': 'static/Products/tie.jpeg',
        'description': 'A premium silk tie set for formal occasions.',
        'details': [
            'Includes matching pocket square.',
            'Made from high-quality silk fabric.',
            'Perfect for weddings, parties, and office wear.',
            'Easy to clean and maintain.'
        ],
        'stock': 5,
        'category': 'Accessories',
        'brand':'levis',
        'colour': 'White',
        'target_user':'Men',
        'type': 'Tie'
    },
    {
        'id': 7,
        'name': 'Smartwatch',
        'price': 7999,
        'image': 'static/Products/smartwatch.jpeg',
        'description': 'A feature-packed smartwatch for health and connectivity.',
        'details': [
            'Tracks heart rate, steps, and sleep patterns.',
            'Water-resistant and durable design.',
            'Syncs with your smartphone for notifications.',
            'Available in multiple strap colors.'
        ],
        'stock': 3,
        'category': 'Electronics',
        'brand':'Apple',
        'colour': 'Black',
        'target_user':'Unisex',
        'type': 'Watch'
    },
    {
        'id': 8,
        'name': 'Backpack',
        'price': 2499,
        'image': 'static/Products/backpack.jpeg',
        'description': 'A stylish and spacious backpack for work or travel.',
        'details': [
            'Made from water-resistant material.',
            'Multiple compartments for organized storage.',
            'Comfortable shoulder straps.',
            'Available in multiple colors.'
        ],
        'stock': 4,
        'category': 'Accessories',
        'brand':'Safari',
        'colour': 'Black',
        'target_user':['Unisex'],
        'type': 'Bag'
    },
    {
        'id': 9,
        'name': 'Wireless Earbuds',
        'price': 3499,
        'image': 'static/Products/earbuds.jpeg',
        'description': 'Premium wireless earbuds with noise cancellation.',
        'details': [
            'Superior sound quality with deep bass.',
            'Long battery life for all-day use.',
            'Comes with a compact charging case.',
            'Sweat and splash resistant.'
        ],
        'stock': 6,
        'category': 'Electronics',
        'brand':'Boat',
        'colour': 'Black',
        'target_user':['Unisex'],
        'type': 'Earbuds'
    },
    {
        'id': 10,
        'name': 'Yoga Mat',
        'price': 1299,
        'image': 'static/Products/yogamat.jpeg',
        'description': 'Non-slip yoga mat for fitness and relaxation.',
        'details': [
            'Made from eco-friendly materials.',
            'Offers excellent grip and cushioning.',
            'Lightweight and easy to carry.',
            'Ideal for yoga, Pilates, and workouts.'
        ],
        'stock': 7,
        'category': 'Fitness',
        'brand':'Boldfit',
        'colour': 'Pink',
        'target_user':'Unisex',
        'type': 'Mat'
    },
    {
        'id': 11,
        'name': 'Formal Black Blazer',
        'price': 4999,
        'image': 'static/Products/blazer.jpeg',
        'description': 'A tailored blazer for formal events and office wear.',
        'details': [
            'Made from high-quality fabric.',
            'Slim-fit design with classic lapels.',
            'Available in multiple sizes.',
            'Dry clean recommended.'
        ],
        'stock': 2,
        'category': 'Clothing',
        'brand':'levis',
        'colour': 'Black',
        'target_user':['Men'],
        'type': 'Blazer'
    },
    {
        'id': 12,
        'name': 'Gaming Mouse',
        'price': 1999,
        'image': 'static/Products/gaming_mouse.jpeg',
        'description': 'Ergonomic gaming mouse with customizable buttons.',
        'details': [
            'Adjustable DPI for precision.',
            'RGB lighting for a cool aesthetic.',
            'Compatible with all major operating systems.',
            'Plug-and-play setup.'
        ],
        'stock': 8,
        'category': 'Electronics',
        'brand':'Asus',
        'colour': 'Black',
        'target_user':['Unisex'],
        'type': 'Mouse'
    },
    {
        'id': 13,
        'name': 'Cotton Bedsheet',
        'price': 1499,
        'image': 'static/Products/bedsheet.jpeg',
        'description': 'A soft and comfortable bedsheet for a good night’s sleep.',
        'details': [
            'Made from 100% cotton.',
            'Available in vibrant patterns.',
            'Machine washable and durable.',
            'Perfect for all bed sizes.'
        ],
        'stock': 10,
        'category': 'Home',
        'brand':'levis',
        'colour': 'Red',
        'target_user':'Unisex',
        'type': 'Bedsheet'
    },
    {
        'id': 14,
        'name': 'Bluetooth Speaker',
        'price': 2599,
        'image': 'static/Products/speaker.jpeg',
        'description': 'Compact Bluetooth speaker with superior sound quality.',
        'details': [
            'Long battery life and quick charging.',
            'Supports hands-free calls.',
            'Water-resistant and durable.',
            'Compatible with all Bluetooth devices.'
        ],
        'stock': 5,
        'category': 'Electronics',
        'brand': 'OnePlus',
        'colour': 'Boat',
        'colour': 'Black',
        'target_user':'Unisex',
        'type': 'Speaker'
    },
    {
        'id': 15,
        'name': 'Wrist Watch',
        'price': 3499,
        'image': 'static/Products/wristwatch.jpeg',
        'description': 'A classic wristwatch with an elegant design.',
        'details': [
            'Quartz movement for precise timekeeping.',
            'Stainless steel strap.',
            'Water-resistant up to 50 meters.',
            'Available in gold and silver tones.'
        ],
        'stock': 3,
        'category': 'Accessories',
        'brand': 'Boat',
        'colour': 'Boat',
        'colour': 'Brown',
        'target_user':['Unisex'],
        'type': 'Watch'
    }
]

@bp.route("/")
@bp.route('/home')
@login_required
def home():
    print("going to render homepage...")
    return render_template('home.html', products=products)


@bp.route('/product/<int:product_id>')
def product_details(product_id):
    product = next((p for p in products if p['id'] == product_id), None)
    if product is None:
        return "Product not found", 404
    return render_template('product.html', product=product)


@bp.route('/update', methods=['GET', 'POST'])
@login_required
def update():
    get_flashed_messages()
    form = UpdateUserForm(obj=current_user)  # Populate the form with the current user's data
    if form.state.data in STATES_CITY:
        form.city.choices = [(city, city) for city in STATES_CITY[form.state.data]]
    else:
        form.city.choices = []

    if request.method == 'POST' and form.validate_on_submit():
        try:
            current_user.firstname = form.firstname.data
            current_user.lastname = form.lastname.data
            current_user.address_line_1 = form.address_line_1.data
            current_user.state = form.state.data
            current_user.city = form.city.data
            current_user.role = form.role.data
            current_user.pincode = form.pincode.data

            db.session.commit()
            flash('Details updated successfully!', 'success')
            return redirect(url_for('auth.update_user'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'danger')
    
    return render_template(
        'update_user.html',
        form=form,
        STATES_CITY=STATES_CITY
    )


@bp.route('/auth_error')
def auth_error():
    return render_template('notAuthorized.html')

@bp.route('/add_to_cart/<product_id>', methods=['POST'])
def add_to_cart(product_id):
    # Ensure product_id is an integer
    try:
        product_id = int(product_id)
    except ValueError:
        return "Invalid product ID", 400

    # Initialize cart in session if not already present
    if 'cart' not in session:
        session['cart'] = {}

    # Initialize cart to hold products as integers
    cart = {int(k): v for k, v in session['cart'].items()}

    # Get the product from the products list
    product = next((p for p in products if p['id'] == product_id), None)

    if product:
        # If product is already in the cart, increment the quantity, but not exceeding stock
        if product_id in cart:
            if cart[product_id] < product['stock']:
                cart[product_id] += 1  # Increment quantity by 1
            else:
                # If the cart quantity reaches stock, don't increase it further
                cart[product_id] = product['stock']
        else:
            # Add the product to the cart with a quantity of 1 if it's not already in the cart
            cart[product_id] = 1

    # Save the updated cart back to the session
    session['cart'] = cart

    # Redirect to the product details page or referrer
    return redirect(request.referrer)


@bp.route("/cart")
def cart():
    cart = session.get("cart", {})
    cart_items = []
    total_price = 0  # Initialize total price
    total_items = 0  # Initialize total items count

    # Loop through the cart to get each product and calculate totals
    for product_id, quantity in cart.items():
        product_id = int(product_id)

        product = next((p for p in products if p["id"] == product_id), None)
        if product:
            product_copy = product.copy()
            product_copy["quantity"] = quantity
            cart_items.append(product_copy)

            # Calculate total price for this product
            total_price += product["price"] * quantity
            total_items += quantity  # Add quantity to total items

    # Pass total price and total items to the template
    return render_template("cart.html", cart_items=cart_items, total_price=total_price, total_items=total_items)

@bp.route("/update_quantity/<int:product_id>", methods=["POST"])
def update_quantity(product_id):
    cart = session.get("cart", {})
    try:
        # Parse new quantity from request data
        new_quantity = int(request.json.get('quantity', 1))
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': 'Invalid quantity'}), 400

    product = next((p for p in products if p['id'] == product_id), None)

    if not product:
        return jsonify({'success': False, 'message': 'Product not found'}), 404

    if new_quantity > product['stock']:
        new_quantity = product['stock']  # Cap quantity to available stock

    if new_quantity < 1:
        cart.pop(str(product_id), None)  # Remove product if quantity is 0 or less
    else:
        cart[str(product_id)] = new_quantity

    session['cart'] = cart

    # Calculate new total price and total items
    total_price = sum(product["price"] * quantity for product_id, quantity in cart.items() if (product := next((p for p in products if p["id"] == int(product_id)), None)))
    total_items = sum(cart.values())  # Total items is the sum of all quantities

    return jsonify({'success': True, 'new_quantity': new_quantity, 'total_price': total_price, 'total_items': total_items})

@bp.route('/remove-from-cart/<int:product_id>', methods=['POST'])
def remove_from_cart(product_id):
    cart = session.get('cart', {})
    if str(product_id) in cart:
        del cart[str(product_id)]
        session['cart'] = cart
        flash("Item removed from cart!", "success")
    return redirect(url_for('views.cart'))



@bp.route('/search')
def search():
    query = request.args.get('query', '').lower()  # Get the search query from the URL parameters
    query_words = query.split()  # Split the query into individual words
    
    if query:
        results = []
        
        # Loop through each product and check if it matches the individual words or combined query
        for p in products:
            try:
                # Combine product attributes into one string for easier matching
                product_str = (
                    str(p.get('name', '')).lower() + ' ' + 
                    str(p.get('description', '')).lower() + ' ' + 
                    str(p.get('brand', '')).lower() + ' ' + 
                    str(p.get('colour', '')).lower() + ' ' + 
                    str(p.get('category', '')).lower() + ' ' + 
                    str(p.get('target_user', '')).lower() + ' ' + 
                    str(p.get('type', '')).lower()
                )
                
                # Check for exact matches for each word in the query
                individual_match = all(word in product_str.split() for word in query_words)
                
                # Check if the entire query (combined) exists in the product attributes (combined search)
                combined_match = query in product_str
                
                if individual_match or combined_match:
                    results.append(p)
            except Exception as e:
                print(f"Error processing product: {p}. Error: {e}")
                continue  # Skip any products that cause an error
                
    else:
        results = []  # No results if query is empty
    
    return render_template('search_results.html', query=query, results=results)


@bp.route('/category/<category>')
def category(category):
    category = category.lower()
    results = [p for p in products if p['category'].lower() == category]
    return render_template('category_results.html', category=category.capitalize(), results=results)

@bp.route('/deliver')
@is_delivery_person
def deliver():
    return Response("Delivered", status=200)

## Team 3

@bp.route('/admin')
@login_required
@is_admin
def index():
    return render_template('admin.html')

@bp.route('/product/new', methods=['GET', 'POST'])
@login_required
@is_admin
def new_product():
    if request.method == 'POST':
        try:
            # Extract form fields
            name = request.form['name']
            description = request.form['description']
            details = request.form['details']
            price = float(request.form['price'])
            stock_quantity = int(request.form['stock_quantity'])
            brand = request.form['brand']
            size = request.form['size']
            target_user = request.form['target_user']
            type_ = request.form['type']
            rating = request.form.get('rating', 'not rated')
            category = request.form['category']

            # Validate required fields
            if not all([name, description, brand, category, size, target_user, type_]):
                return "Missing required fields", 400

            # Handle image upload (if exists)
            image = request.files.get('image')
            image_filename = None
            if image:
                # Ensure the 'static/uploads' directory exists
                uploads_dir = os.path.join('static', 'uploads')
                if not os.path.exists(uploads_dir):
                    os.makedirs(uploads_dir)  # Create the directory if it doesn't exist

                # Sanitize the image filename and save it
                image_filename = secure_filename(image.filename)
                image_path = os.path.join(uploads_dir, image_filename)
                image.save(image_path)

            # Create the product object
            new_product = Product(
                name=name,
                description=description,
                details=details,
                price=price,
                stock_quantity=stock_quantity,
                brand=brand,
                size=size,
                target_user=target_user,
                type=type_,
                rating=rating,
                category=category,
                colour="nocolour",
                image=image_filename
            )

            # Commit to the database
            db.session.add(new_product)
            db.session.commit()

            flash("Product added successfully!", "success")
            return redirect(url_for('views.product_list'))

        except Exception as e:
            db.session.rollback()
            print(f"Error while adding product: {e}")  # Log the error to the console
            return f"Error while adding product: {e}", 500  # Return the error message

    return render_template('add-shop-items.html')
##########
@bp.route('/product/edit/<int:id>', methods=['GET', 'POST'])
@login_required
@is_admin
def update_product(id):
    # Fetch the product from the database by its ID
    product = Product.query.get_or_404(id)

    if request.method == 'POST':
        try:
            # Extract form fields
            name = request.form['name']
            description = request.form['description']
            details = request.form['details']
            price = float(request.form['price'])
            stock_quantity = int(request.form['stock_quantity'])
            brand = request.form['brand']
            size = request.form['size']
            target_user = request.form['target_user']
            type_ = request.form['type']
            category = request.form['category']

            # Validate required fields
            if not all([name, description, brand, category, size, target_user, type_]):
                return "Missing required fields", 400

            # Handle image upload (if exists)
            image_filename = product.image  # Retain the old image filename if no new image is uploaded
            image = request.files.get('image')
            if image:
                # Ensure the 'static/uploads' directory exists
                uploads_dir = os.path.join('static', 'uploads')
                if not os.path.exists(uploads_dir):
                    os.makedirs(uploads_dir)  # Create the directory if it doesn't exist

                # Sanitize the image filename and save it
                image_filename = secure_filename(image.filename)
                image_path = os.path.join(uploads_dir, image_filename)
                image.save(image_path)

            # Update the product object with new data
            product.name = name
            product.description = description
            product.details = details
            product.price = price
            product.stock_quantity = stock_quantity
            product.brand = brand
            product.size = size
            product.target_user = target_user
            product.type = type_
            product.category = category
            product.image = image_filename  # Update the image (if new image uploaded)

            # Commit to the database
            db.session.commit()

            flash("Product updated successfully!", "success")
            return redirect(url_for('views.product_list'))  # Redirect to the product list page

        except Exception as e:
            db.session.rollback()
            print(f"Error occurred while updating product: {e}")
            return f"Error while updating product: {e}", 500  # Internal error

    # If it's a GET request, render the form with the current product data
    return render_template('update-product.html', product=product)
# @bp.route('/product/edit/<int:id>', methods=['GET', 'POST'])
# @login_required
# def update_product(id):
#     # Fetch the product from the database by its ID
#     try:
#         print(f"Fetching product with ID: {id}")
#         product = Product.query.get_or_404(id)
#     except Exception as e:
#         print(f"Error fetching product: {e}")
#         return f"Error fetching product: {e}", 500

#     if request.method == 'POST':
#         try:
#             print("Request method is POST")
#             print("Form data received:", request.form)

#             # Extract form fields
#             name = request.form['name']
#             description = request.form['description']
#             details = request.form['details']
#             price = float(request.form['price'])  # Check if this field exists and is valid
#             stock_quantity = int(request.form['stock_quantity'])  # Same here
#             brand = request.form['brand']
#             size = request.form['size']
#             target_user = request.form['target_user']
#             type_ = request.form['type']
#             rating = float(request.form['rating'])
#             category = request.form['category']

#             print(f"Extracted fields: name={name}, description={description}, price={price}, ...")

#             # Validate required fields
#             if not all([name, description, brand, category, size, target_user, type_]):
#                 print("Missing required fields")
#                 return "Missing required fields", 400

#             # Handle image upload (if exists)
#             image_filename = product.image  # Retain the old image filename if no new image is uploaded
#             try:
#                 image = request.files.get('image')
#                 if image:
#                     print(f"Image file received: {image.filename}")
#                     uploads_dir = os.path.join('static', 'uploads')
#                     if not os.path.exists(uploads_dir):
#                         os.makedirs(uploads_dir)
#                         print(f"Created directory: {uploads_dir}")

#                     # Save the image
#                     image_filename = secure_filename(image.filename)
#                     image_path = os.path.join(uploads_dir, image_filename)
#                     image.save(image_path)
#                     print(f"Saved image at: {image_path}")
#             except Exception as e:
#                 print(f"Error handling image upload: {e}")
#                 return f"Error handling image upload: {e}", 500

#             # Update the product object
#             product.name = name
#             product.description = description
#             product.details = details
#             product.price = price
#             product.stock_quantity = stock_quantity
#             product.brand = brand
#             product.size = size
#             product.target_user = target_user
#             product.type = type_
#             product.rating = rating
#             product.category = category
#             product.image = image_filename

#             # Commit to the database
#             try:
#                 db.session.commit()
#                 print("Product updated successfully!")
#                 flash("Product updated successfully!", "success")
#                 return redirect(url_for('views.product_list'))
#             except Exception as e:
#                 print(f"Error committing to database: {e}")
#                 db.session.rollback()
#                 return f"Database error: {e}", 500

#         except KeyError as e:
#             print(f"Missing field in form: {e}")
#             return f"Missing field in form: {e}", 400
#         except ValueError as e:
#             print(f"Invalid value provided: {e}")
#             return f"Invalid value provided: {e}", 400
#         except Exception as e:
#             print(f"General error: {e}")
#             return f"Error: {e}", 500

#     # If it's a GET request, render the form with the current product data
#     print(f"Rendering update form for product ID: {id}")
#     return render_template('update-product.html', product=product)

# @bp.route('/product/edit/<int:id>', methods=['GET', 'POST'])
# @login_required
# def update_product(id):
#     # Fetch the product from the database by its ID
#     print(request.form)
#     product = Product.query.get_or_404(id)

#     if request.method == 'POST':
#         try:
#             # Extract form fields
#             name = request.form['name']
#             description = request.form['description']
#             details = request.form['details']
#             price = float(request.form['price'])
#             stock_quantity = int(request.form['stock_quantity'])
#             brand = request.form['brand']
#             size = request.form['size']
#             target_user = request.form['target_user']
#             type_ = request.form['type']
#             rating = float(request.form['rating'])
#             category = request.form['category']

#             print("")

#             # Validate required fields
#             if not all([name, description, brand, category, size, target_user, type_]):
#                 print("Missing required Fields...")
#                 return "Missing required fields", 400

#             # Handle image upload (if exists)
#             image_filename = product.image  # Retain the old image filename if no new image is uploaded
#             image = request.files.get('image')
#             if image:
#                 # Ensure the 'static/uploads' directory exists
#                 uploads_dir = os.path.join('static', 'uploads')
#                 if not os.path.exists(uploads_dir):
#                     os.makedirs(uploads_dir)  # Create the directory if it doesn't exist

#                 # Sanitize the image filename and save it
#                 image_filename = secure_filename(image.filename)
#                 image_path = os.path.join(uploads_dir, image_filename)
#                 image.save(image_path)
#             print("It's fine upto here...")
#             # Update the product object with new data
#             product.name = name
#             product.description = description
#             product.details = details
#             product.price = price
#             product.stock_quantity = stock_quantity
#             product.brand = brand
#             product.size = size
#             product.target_user = target_user
#             product.type = type_
#             product.rating = rating
#             product.category = category
#             product.image = image_filename  # Update the image (if new image uploaded)

#             # Commit to the database
#             db.session.commit()

#             flash("Product updated successfully!", "success")
#             return redirect(url_for('views.product_list'))  # Redirect to the product list page

#         except Exception as e:
#             db.session.rollback()
#             print(f"Error occurred while updating product: {e}")
#             return f"Error while updating product: {e}", 500  # Internal error

#     # If it's a GET request, render the form with the current product data
#     return render_template('update-product.html', product=product)
############
@bp.route('/products', methods=['GET'])
@login_required
@is_admin
def product_list():

    products = Product.query.all()

    # Render the template to display all products
    return render_template('product-list.html', products=products)

###################################
@bp.route('/product/delete/<int:id>', methods=['POST'])
@login_required
@is_admin
def delete_product(id):
    # Fetch the product from the database by its ID
    product = Product.query.get_or_404(id)

    try:
        # Delete the product
        db.session.delete(product)
        db.session.commit()

        print(f"Product {id} deleted successfully")
        return redirect(url_for('views.product_list'))  # Redirect back to the product list page

    except Exception as e:
        print(f"Error occurred while deleting product: {e}")
        db.session.rollback()
        return "Error while deleting product", 500  # Internal server error






#<a href="{{ url_for('views.view_product', id=product.id) }}" class="btn btn-info btn-sm">View</a>




@bp.route('/partner_dash')
# @is_delivery_person
def dashboard():
    # Fetch user info (hardcoded for now, you can change this later)
    user = {'name': current_user.firstname, 'pincode':current_user.pincode}

    # Fetch stats from the database
    stats = Stats.query.first()  # Assuming there's only one stats row for simplicity
    if not stats:
        stats = Stats(total_orders=0, delivered=0, in_transit=0, failed=0)
        db.session.add(stats)
        db.session.commit()

    # Fetch orders from the database
    orders = Order.query.filter_by(pincode=user['pincode']).all()

    # Only allow orders in the user's state (California in this case) to be viewed or delivered
    return render_template('delivery_person_dashboard.html', user=user, stats=stats, orders=orders)


@bp.route('/update_status/<int:order_id>', methods=['POST'])
def update_status(order_id):
    new_status = request.form['status']  # Get the selected status from the form
    order = Order.query.get(order_id)  # Fetch the order by ID from the database

    if order:
        # Update the order's status
        order.status = new_status

        # If the status is "Delivered Successfully", send a thank-you email
        if new_status == 'Delivered Successfully':
            send_thank_you_email(order)

        db.session.commit()

        # Update stats (optional, but if required to refresh stats)
        update_stats()

    return redirect(url_for('views.dashboard'))  # Redirect back to the dashboard or the orders list


def update_stats():
    # Recalculate stats for the dashboard or stats view
    stats = Stats.query.first()
    stats.total_orders = Order.query.count()
    stats.delivered = Order.query.filter_by(status='Delivered Successfully').count()
    stats.in_transit = Order.query.filter_by(status='In Transit').count()
    stats.failed = Order.query.filter_by(status='Failed').count()
    db.session.commit()


@bp.route('/view_orders', methods=['GET'])
@login_required
@is_admin
# def view_orders():
#     orders = Order.query.all()
#     orders_list = [order.__dict__ for order in orders]

#     # Remove the SQLAlchemy internal attribute '_sa_instance_state'
#     for order in orders_list:
#         order.pop('_sa_instance_state', None)

#     return jsonify(orders_list)

def view_orders():

    orders = Order.query.all()
    # Render the template to display all orders
    return render_template('view_order.html', orders=orders)

# @bp.route('/update_status/<int:order_id>', methods=['POST'])
# def update_status(order_id):
#     new_status = request.form['status']
#     order = Order.query.get(order_id)

#     if order:
#         # Update the order status
#         order.status = new_status
#         db.session.commit()

#         # If status is "Delivered Successfully", send an email to the user
#         if new_status == "Delivered Successfully":
#             send_rating_email(order)

#         # Update stats if needed
#         update_stats()

#     return redirect(url_for('views.dashboard'))
# #
# #
# def send_rating_email(order):
#     user_email = order.user.email  # Get the user's email (assuming the order has a user reference)
#     product = order.product  # Get the product related to the order

#     # Create the message
#     subject = "Your Order has been Delivered! Please Rate Your Product"
#     body = f"""
#     Hi {order.user.first_name},

#     We hope you're enjoying your new product: {product.name}.

#     Could you please rate the product from 1 to 5 (1 being the worst, 5 being the best)?
#     Your feedback helps us improve our products and services!

#     Click the link below to rate the product:
#     {url_for('views.submit_rating', order_id=order.id, _external=True)}

#     Thank you for your support!
#     """

#     # Send the email
#     msg = Message(subject, recipients=[user_email], body=body)
#     mail.send(msg)


####################################mail###################



@bp.route('/rate_product/<int:order_id>', methods=['GET', 'POST'])

def rate_product(order_id):
    # Fetch the order using the order_id
    order = Order.query.get_or_404(order_id)

    # Fetch the product associated with the order
    product = Product.query.get_or_404(order.product_id)

    if request.method == 'POST':
        try:
            # Get the user's rating from the form (rating is expected to be between 1 and 5)
            rating = request.form['rating']  # Assumes the form will send a 'rating' field as 1, 2, 3, 4, or 5
            customer_rating = int(rating)  # Convert rating to integer

            # Check if the product has already been rated
            if product.rating == 'not rated':
                # If not rated yet, store the customer's rating
                product.rating = str(customer_rating)
            else:
                # If rated, calculate the new average rating
                current_rating = float(product.rating)
                new_rating = (current_rating + customer_rating) / 2
                product.rating = str(new_rating)

            # Commit the changes to the database
            db.session.commit()

            # Flash success message and redirect to the product page or a thank-you page
            flash(f"Thank you for rating! Your rating of {customer_rating} has been saved.", "success")
            return redirect(url_for('auth.login'))

        except Exception as e:
            db.session.rollback()
            print(f"Error occurred while rating the product: {e}")
            flash("An error occurred while submitting your rating. Please try again later.", "danger")
            return redirect(url_for('views.view_product', id=product.id))

    return render_template('rate_product.html', product=product,order=order)

def send_thank_you_email(order):
    """
    Function to send a thank you email when an order is delivered.

    """
    rate_product_url = url_for('views.rate_product', order_id=order.id, _external=True)

    msg = Message(
        subject="Thank You for Shopping!",
        recipients=[order.mail]  # Send email to the customer's email
    )

    # Set the body of the email
    msg.body = f"""
    Dear {order.customer_name},

    Thank you for shopping with us! We hope you are happy with your purchase.
    
    We would love to hear your feedback! Please take a moment to rate the product you purchased:

    {rate_product_url}



    If you have any questions or need assistance, feel free to contact us.

    Best regards,
    Your Company Name
    """

    try:
        with current_app.app_context():
            current_app.extensions['mail'].send(msg)
        print("Thank you email sent successfully!")
    except Exception as e:
        print(f"Error sending email: {e}")



#
# @bp.route('/update_status/<int:order_id>', methods=['POST'])
# def update_status(order_id):
#     new_status = request.form['status']  # Get the selected status from the form
#     order = Order.query.get(order_id)  # Fetch the order by ID from the database
#
#     if order:
#         # Update the order's status
#         order.status = new_status
#         db.session.commit()
#
#         # Update stats (optional, but if required to refresh stats)
#         update_stats()
#
#     return redirect(url_for('views.dashboard'))  # Redirect back to the dashboard or the orders list
#
#
# def update_stats():
#     # Recalculate stats for the dashboard or stats view
#     stats = Stats.query.first()
#     stats.total_orders = Order.query.count()
#     stats.delivered = Order.query.filter_by(status='Delivered Successfully').count()
#     stats.in_transit = Order.query.filter_by(status='In Transit').count()
#     stats.failed = Order.query.filter_by(status='Failed').count()
#     db.session.commit()


