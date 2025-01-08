from .models import User, Product, Order
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from io import BytesIO

class Visualize:

    def __init__(self):
        pass

    @staticmethod
    def generate_new_old_customers_graph(dates_for_chart1: list, values_for_new_customers: list, values_for_returning_customers: list) -> BytesIO:
        
        plt.figure(figsize=(10, 5))
        plt.plot(dates_for_chart1, values_for_new_customers, label="New Customers", color="#FF9900")
        plt.plot(dates_for_chart1, values_for_returning_customers, label="Returning Customers", color="green")
        plt.xlabel('Date')
        plt.xticks(dates_for_chart1[::10], rotation=45)
        plt.ylabel('People')
        plt.title('New Customers and Returning Customers')
        plt.grid(True)
        plt.legend()
        plt.xticks(rotation=45)

        img = BytesIO()
        plt.savefig(img, format='png')
        img.seek(0)
        plt.close()

        return img

    @staticmethod
    def generate_revenue_overtime_graph(dates:list, revenue:list) -> BytesIO:
        plt.figure(figsize=(10, 5))
        plt.plot(dates, revenue, label="Revenue", color="green")
        plt.xticks(dates[::10], rotation=45)
        plt.xlabel('Date')
        plt.ylabel('Revenue')
        plt.title('Revenue Over Time')

        img = BytesIO()
        plt.savefig(img, format='png')
        img.seek(0)
        plt.close()

        return img
    
    @staticmethod
    def generate_order_status_graph(statuses: list, values: list) -> BytesIO:
        plt.pie(values, labels=statuses, autopct='%1.1f%%', startangle=140, wedgeprops={'width': 0.65})
        plt.title('Order Status Distribution')
        plt.legend(loc='upper left', bbox_to_anchor=(1, 1))
        img = BytesIO()
        plt.savefig(img, format='png')
        img.seek(0)
        plt.close()
        return img

    @staticmethod
    def generate_inventory_stocks_graph(products: list, stocks: list) -> BytesIO:
        plt.bar(products, stocks, color="#11FF33")
        plt.xlabel('Products')
        plt.ylabel('Stock')
        plt.title('Inventory Stock Levels')
        img = BytesIO()
        plt.savefig(img, format='png')
        img.seek(0)
        plt.close()
        return img
    
    def generate_finantial_overview_graph(data):
        ...