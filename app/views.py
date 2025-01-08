from flask import Blueprint, render_template, get_flashed_messages, redirect, url_for, Response, flash, request
from flask_login import login_required, current_user
from .models import db
from .forms import UpdateUserForm
from .decorators import is_delivery_person
from .constants import STATES_CITY
bp = Blueprint('views', __name__)


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
        ]
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
        ]
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
        ]
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
        ]
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
        ]
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


@bp.route('/deliver')
@is_delivery_person
def deliver():
    return Response("Delivered", status=200)