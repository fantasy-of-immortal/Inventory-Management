from flask import Flask
from flask_restful import Api
from flasgger import Swagger
from app.resources import ProductsAPI, ProductAPI,ProductsQueryAPI,UserAPI,UserInfoAPI,LoginAPI,OrderAPI,ProductCategoriesAPI,CategoryAPI

def create_app():
    app = Flask(__name__)
    app.config.from_object('app.config.Config')  # 加载配置

    # 初始化 Swagger
    swagger_config = {
        "swagger": "2.0",
        "info": {
            "title": "库存管理 API",
            "description": "库存管理系统的 API 文档",
            "version": "1.7.10",
        }
    }
    Swagger(app, template=swagger_config)

    # 初始化 RESTful API
    api = Api(app)
    api.add_resource(ProductsAPI, '/api/products')  # 注册获取所有产品的资源
    api.add_resource(ProductAPI,'/api/products/<int:product_id>')  # 注册获取单个产品的资源，假设使用 ProductAPI 和动态路由
    api.add_resource(ProductsQueryAPI, '/api/products/query')
    api.add_resource(UserAPI, '/api/users')  # 注册创建用户的资源
    api.add_resource(UserInfoAPI, '/api/users/me') #注册查询用户信息的资源
    api.add_resource(LoginAPI, '/api/users/login') #注册登录的资源
    api.add_resource(OrderAPI, '/api/orders')      #注册订单创建和查看资源
    api.add_resource(ProductCategoriesAPI, '/api/products?category={category}')      #注册商品分类查询资源
    api.add_resource(CategoryAPI, '/api/categories')      #注册商品分类管理资源


    return app