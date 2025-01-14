import unittest
from flask_testing import TestCase
from main import create_app, db
from werkzeug.security import generate_password_hash
from app.models import User, Product, Order, ProductAddLogs

class TestVisualization(TestCase):
    WTF_CSRF_ENABLED = False
    def create_app(self):
        """Configure the Flask app for testing."""
        app = create_app(config_class="TestConfig")
        return app

    def setUp(self):
        """Set up the test database and add sample data."""
        db.create_all()
        self.add_sample_data()

    def tearDown(self):
        """Tear down the test database."""
        db.session.remove()
        db.drop_all()

    def add_sample_data(self):
        """Add sample data for testing."""
        # Add admin user
        admin_user = User(
            password=generate_password_hash('123', method="pbkdf2:sha256"),
            email='admin@springboard.com',
            address_line_1='Admin Address',
            role='admin',
            firstname='Admin',
            lastname='User',
            pincode='123456',
            state='State1',
            city='City1'
        )
        db.session.add(admin_user)

        # Add sample products
        product1 = Product(name="Product A", stock_quantity=10, category="Category1", price=1023, brand="abx", size="M", target_user = "bots", type="clothing", image="sample", description="sample", details="sample", colour="sample")
        product2 = Product(name="Product B", stock_quantity=20, category="Category2", price=1023, brand="abx", size="M", target_user = "bots", type="clothing", image="sample", description="sample", details="sample", colour="sample")
        db.session.add_all([product1, product2])

        # Add sample orders
        order1 = Order(customer_id=1, product_id=1, price=100.0, status="Pending" )
        order2 = Order(customer_id=1, product_id=2, price=200.0, status="Delivered" )
        db.session.add_all([order1, order2])

        db.session.commit()

    
    def login_admin(self):
        """Log in as the admin user."""

        response = self.client.post('/login', data=dict(
            email="admin@springboard.com",
            password="123"
        ), follow_redirects=True)
        print(response.data)
        self.assertEqual(response.status_code, 200)


    def test_show_chart1(self):
        """Test the `/chart1` endpoint."""
        self.login_admin()
        response = self.client.get('admin/chart1')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'New Customers and Returning Customers', response.data)

    def test_show_chart2(self):
        """Test the `/chart2` endpoint."""
        self.login_admin()
        response = self.client.get('admin/chart2')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Revenue Over Time', response.data)

    def test_show_chart3(self):
        """Test the `/chart3` endpoint."""
        self.login_admin()
        response = self.client.get('admin/chart3')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Order Status Distribution', response.data)

    def test_show_chart4(self):
        """Test the `/chart4` endpoint."""
        self.login_admin()
        response = self.client.get('admin/chart4')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Inventory Stock Levels', response.data)

    def test_show_chart5(self):
        """Test the `/chart5` endpoint."""
        self.login_admin()
        response = self.client.get('admin/chart5')
        
        print(response.data)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Financial Overview', response.data)

    def test_get_stock_chart(self):
        """Test the `/get-stock-chart/<category>` endpoint."""
        self.login_admin()
        response = self.client.get('admin/get-stock-chart/Category1')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Product A', response.data)


if __name__ == '__main__':
    unittest.main()

