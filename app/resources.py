from flask_restful import Resource, reqparse
from app.db import get_db
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
import jwt
from flask import request

from datetime import datetime, timedelta
from functools import wraps

def jwt_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        # 获取当前用户的 JWT 令牌
        token = request.headers.get('Authorization')
        
        if not token:
            return {"message": "令牌缺失"}, 403
        
        try:
            # 解析 JWT 令牌
            token = token.split(" ")[1]  # 获取 Bearer 后面的 token
            data = jwt.decode(token, 'secret_key', algorithms=["HS256"])
            user_id = data['user_id']
            
            # 将用户ID传递到视图函数中
            # 可以通过kwargs方式传递
            kwargs['user_id'] = user_id

        except jwt.ExpiredSignatureError:
            return {"message": "令牌过期"}, 401
        except jwt.InvalidTokenError:
            return {"message": "无效的令牌"}, 401
        
        return f(*args, **kwargs)

    return decorator


def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 获取请求头中的 Authorization token
        token = request.headers.get('Authorization')
        if not token:
            print("令牌缺失")
            return {"message": "令牌缺失"}, 403
        
        try:
            token = token.split(" ")[1]  # 获取 Bearer 后面的 token
            # 解析 JWT
            data = jwt.decode(token, 'secret_key', algorithms=["HS256"])
            user_role = data.get('role')  # 从 token 中获取用户角色
            print(f"Token 解码成功，用户角色：{user_role}")
        except jwt.ExpiredSignatureError:
            print("令牌过期")
            return {"message": "令牌过期"}, 401
        except jwt.InvalidTokenError:
            print("无效的令牌")
            return {"message": "无效的令牌"}, 401

        # 检查用户是否为管理员
        if user_role != 'admin':
            print(f"权限不足，当前角色: {user_role}")
            return {"message": "权限不足，管理员权限所需"}, 403
        
        return f(*args, **kwargs)  # 角色是 admin 时，继续执行原 API
        
    return decorated_function


class ProductsAPI(Resource):

    def get(self):
        '''
        获取产品列表
        ---
        tags:
        - Products
        description: 检索所有产品，可以按分类过滤
        parameters:
          - name: category_id
            in: query
            type: integer
            required: false
            description: 按产品分类查询
        responses:
            200:
                description: 产品列表
                schema:
                    type: object
                    properties:
                        products:
                            type: array
                            items:
                                type: object
                                properties:
                                    id:
                                        type: integer
                                    name:
                                        type: string
                                    inventory:
                                        type: integer
                                    price:
                                        type: number
                                    category_id:
                                        type: integer
        '''
        # 获取查询参数中的分类 ID
        category_id = request.args.get('category_id', type=int)

        # 从数据库查询数据
        connection = get_db()
        cursor = connection.cursor()
        
        # 如果提供了 category_id 参数，进行分类过滤
        if category_id:
            cursor.execute("SELECT * FROM products WHERE category_id = %s;", (category_id,))
        else:
            cursor.execute("SELECT * FROM products;")
        
        rows = cursor.fetchall()
        cursor.close()
        
        # 转换为 JSON 格式
        products = [
            {"id": row[0], "name": row[1], "inventory": row[2], "price": float(row[3]), "category_id": row[4]}
            for row in rows
        ]
        return {"products": products}, 200

    @require_admin
    def put(self, product_id):
        """
        以 ID 修改单个产品
        ---
        tags:
          - Products
        description: 以 ID 更新单个产品的详情，包括分类信息
        parameters:
          - name: product_id
            in: path
            required: true
            type: integer
            description: 要更新的产品 ID
          - name: body
            in: body
            required: true
            schema:
              type: object
              properties:
                name:
                  type: string
                inventory:
                  type: integer
                price:
                  type: number
                category_id:
                  type: integer
        responses:
          200:
            description: 产品成功更新
        """
        parser = reqparse.RequestParser()
        parser.add_argument("name", required=False, type=str)
        parser.add_argument("inventory", required=False, type=int)
        parser.add_argument("price", required=False, type=float)
        parser.add_argument("category_id", required=False, type=int)  # 支持更新分类
        args = parser.parse_args()

        # 检查是否有至少一个字段需要更新
        if not any(value is not None for value in args.values()):
            return {"message": "没有提供有效的更新字段"}, 400

        connection = get_db()
        cursor = connection.cursor()

        # 检查产品是否存在
        cursor.execute("SELECT * FROM products WHERE id = %s;", (product_id,))
        if not cursor.fetchone():
            cursor.close()
            return {"message": "找不到产品"}, 404

        # 动态生成更新语句
        updates = []
        values = []
        for key, value in args.items():
            if value is not None:
                updates.append(f"{key} = %s")
                values.append(value)

        # 确保更新语句非空
        if updates:
            update_query = f"UPDATE products SET {', '.join(updates)} WHERE id = %s;"
            values.append(product_id)
            cursor.execute(update_query, tuple(values))
            connection.commit()

        cursor.close()
        return {"message": "产品成功更新"}, 200

    @require_admin
    def delete(self, product_id):
        '''
        以 ID 删除单个产品
        ---
        tags:
          - Products
        description: 以 ID 从库存中删除单个产品
        parameters:
          - name: product_id
            in: path
            required: true
            type: integer
            description: 要删除的产品 ID
        responses:
          200:
            description: 产品成功删除
        '''
        connection = get_db()
        cursor = connection.cursor()

        # 检查产品是否存在
        cursor.execute("SELECT * FROM products WHERE id = %s;", (product_id,))
        if not cursor.fetchone():
            cursor.close()
            return {"message": "找不到产品"}, 404
        
        try:
            cursor.execute("DELETE FROM products WHERE id = %s;", (product_id,))
            connection.commit()
            cursor.close()
            return {"message": "产品成功删除"}, 200
        except Exception as e:
            # 如果删除时遇到外键约束错误（例如，有订单项依赖该产品），返回 400 错误
            cursor.close()
            return {"message": "无法删除该产品，可能有依赖关系"}, 400

 
# 单个产品资源类，用于获取指定 ID 的产品
class ProductAPI(Resource):

    def get(self, product_id):
        '''
        获取单个产品
        ---
        tags:
        - Products
        description: 检索指定 ID 的产品
        parameters:
            - name: product_id
              in: path
              type: integer
              required: false
              description: 产品的唯一标识符
        responses:
            200:
                description: 单个产品信息
        '''
        # 从数据库查询指定 ID 的产品
        connection = get_db()
        cursor = connection.cursor()
        cursor.execute("SELECT id, name, inventory, price, category_id FROM products WHERE id = %s;", (product_id,))
        row = cursor.fetchone()
        cursor.close()
        
        if row:
            # 转换为 JSON 格式
            product = {
                "id": row[0],
                "name": row[1],
                "inventory": row[2],
                "price": float(row[3]),
                "category_id": row[4]  # 包含分类信息
            }
            return product, 200
        else:
            return {"message": "产品未找到"}, 404

    @require_admin
    def post(self):
        '''
        添加单个产品
        ---
        tags:
        - Products
        description: 添加一个新产品到库存
        parameters:
        - name: body
        in: body
        required: true
        schema:
            type: object
            properties:
            name:
                type: string
            inventory:
                type: integer
            price:
                type: number
            category_id:
                type: integer
        responses:
            201:
                description: 产品成功添加
        '''
        parser = reqparse.RequestParser()
        parser.add_argument('name', required=True, type=str, help="产品名称必需")
        parser.add_argument('inventory', required=True, type=int, help="库存数量必需")
        parser.add_argument('price', required=True, type=float, help="价格必需")
        parser.add_argument('category_id', required=True, type=int, help="分类 ID 必需")
        args = parser.parse_args()

        connection = get_db()
        cursor = connection.cursor()

        # 确保分类存在
        cursor.execute("SELECT id FROM categories WHERE id = %s", (args['category_id'],))
        category = cursor.fetchone()
        if not category:
            return {"message": "分类不存在"}, 404

        cursor.execute(
            "INSERT INTO products (name, inventory, price, category_id) VALUES (%s, %s, %s, %s);",
            (args['name'], args['inventory'], args['price'], args['category_id'])
        )
        connection.commit()
        cursor.close()
        return {"message": "产品成功添加"}, 201


class ProductsQueryAPI(Resource):
    def get(self):
        '''
        以条件组合查询产品
        ---
        tags:
          - Products
        description: 基于 name、inventory、price 和 category_id 查询产品
        parameters:
          - name: name
            in: query
            type: string
            required: false
          - name: inventory
            in: query
            type: integer
            required: false
          - name: price_min
            in: query
            type: float
            required: false
          - name: price_max
            in: query
            type: float
            required: false
          - name: category_id
            in: query
            type: integer
            required: false
            description: 根据分类 ID 过滤产品
        responses:
          200:
            description: 匹配查询条件的产品列表
        '''
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, location='args')
        parser.add_argument('inventory', type=int, location='args')
        parser.add_argument('price_min', type=float, location='args')
        parser.add_argument('price_max', type=float, location='args')
        parser.add_argument('category_id', type=int, location='args')  
        args = parser.parse_args()
 
        query = "SELECT * FROM products WHERE 1=1"  # 不带附加条件时返回所有产品
        values = []
 
        if args['name']:
            query += " AND name LIKE %s"  # 含有字符串
            values.append(f"%{args['name']}%")
 
        if args['inventory']:
            query += " AND inventory >= %s"  # 库存数量至少为
            values.append(args['inventory'])
 
        if args['price_min']:
            query += " AND price >= %s"  # 价格至少为
            values.append(args['price_min'])
 
        if args['price_max']:
            query += " AND price <= %s"  # 价格最高为
            values.append(args['price_max'])
        
        if args['category_id']:
            query += " AND category_id = %s"  # 根据 category_id 过滤
            values.append(args['category_id'])
 
        connection = get_db()
        cursor = connection.cursor()
        cursor.execute(query, tuple(values))
        rows = cursor.fetchall()
        cursor.close()
 
        if rows:
            products = [{"id": row[0], "name": row[1], "inventory": row[2], "price": float(row[3]), "category_id": row[4]} for row in rows]
            return {"products": products}, 200
        else:
            return {"message": "找不到产品"}, 404


class UserAPI(Resource):
    def post(self):
        '''
        创建新用户
        ---
        tags:
          - Users
        description: 基于用户名、密码和角色创建一个新用户
        parameters:
          - name: username
            in: body
            type: string
            required: true
            description: 用户名，必须唯一
          - name: password
            in: body
            type: string
            required: true
            description: 用户密码
          - name: role
            in: body
            type: string
            required: false
            enum: [admin, user]
            description: 用户角色，默认为"user"
        responses:
          201:
            description: 创建成功，返回用户信息
          400:
            description: 请求参数错误或用户名已存在
        '''
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True, help='用户名不能为空')
        parser.add_argument('password', type=str, required=True, help='密码不能为空')
        parser.add_argument('role', type=str, choices=('admin', 'user'), default='user', help='角色不合法')
        args = parser.parse_args()

        # 检查用户名是否已存在
        connection = get_db()
        cursor = connection.cursor()
        cursor.execute("SELECT id FROM users WHERE username = %s", (args['username'],))
        existing_user = cursor.fetchone()

        if existing_user:
            cursor.close()
            return {"message": "用户名已存在"}, 400
        
        # 创建用户
        hashed_password = generate_password_hash(args['password'])
        query = "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)"
        cursor.execute(query, (args['username'], hashed_password, args['role']))
        connection.commit()

        # 获取新创建的用户信息
        cursor.execute("SELECT id, username, role FROM users WHERE username = %s", (args['username'],))
        new_user = cursor.fetchone()
        cursor.close()

        # 返回新用户信息
        return {"id": new_user[0], "username": new_user[1], "role": new_user[2]}, 201



class UserInfoAPI(Resource):
    @jwt_required
    def get(self,user_id):
        '''
        获取当前登录用户的详细信息
        ---
        tags:
          - Users
        description: 获取当前登录用户的信息，需提供有效的 JWT 令牌
        responses:
          200:
            description: 用户信息
            schema:
              type: object
              properties:
                id:
                  type: integer
                username:
                  type: string
                role:
                  type: string
          401:
            description: 未授权，令牌无效或已过期
          403:
            description: 令牌缺失
        '''


        # 从数据库获取当前用户信息
        connection = get_db()
        cursor = connection.cursor()
        cursor.execute("SELECT id, username, role FROM users WHERE id = %s;", (user_id,))
        user = cursor.fetchone()

        cursor.close()

        if user:
            # 返回用户信息
            return {"id": user[0], "username": user[1], "role": user[2]}, 200
        else:
            return {"message": "用户未找到"}, 404




class LoginAPI(Resource):
    def post(self):
        '''
        用户登录并获取 JWT 令牌
        ---
        tags:
          - Users
        description: 用户使用用户名和密码登录，成功后返回 JWT 令牌
        parameters:
          - name: username
            in: body
            type: string
            required: true
            description: 用户名
          - name: password
            in: body
            type: string
            required: true
            description: 用户密码
        responses:
          200:
            description: 登录成功，返回 JWT 令牌
            schema:
              type: object
              properties:
                token:
                  type: string
          400:
            description: 无效的用户名或密码
          404:
            description: 用户未找到
        '''
        # 解析请求体中的参数
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True, help='用户名不能为空')
        parser.add_argument('password', type=str, required=True, help='密码不能为空')
        args = parser.parse_args()

        # 从数据库查询用户
        connection = get_db()
        cursor = connection.cursor()
        cursor.execute("SELECT id, username, password_hash, role FROM users WHERE username = %s", (args['username'],))
        user = cursor.fetchone()
        cursor.close()

        # 如果没有找到用户
        if not user:
            return {'message': '用户未找到'}, 404

        # 使用 werkzeug.security 的 check_password_hash 方法验证密码
        if not check_password_hash(user[2], args['password']):
            return {'message': '无效的用户名或密码'}, 400  # 密码错误

        # 密码验证成功，生成 JWT 令牌
        payload = {
            'user_id': user[0],  # 用户 ID
            "role": user[3],     #用户所属用户组
            'exp': datetime.utcnow() + timedelta(hours=1)  # 令牌有效期为 1 小时
        }

        token = jwt.encode(payload, 'secret_key', algorithm='HS256')

        return {'token': token}, 200





class OrderAPI(Resource):
    @jwt_required
    def post(self,user_id):
        '''
        创建订单
        ---
        tags:
          - Orders
        description: 用户可以创建一个订单，包含多个产品的购买信息，自动更新库存
        parameters:
          - name: order
            in: body
            required: true
            description: 创建订单的详细信息，包括购买的产品和数量
            schema:
              type: object
              properties:
                products:
                  type: array
                  items:
                    type: object
                    properties:
                      product_id:
                        type: integer
                      quantity:
                        type: integer
        responses:
          201:
            description: 订单已创建
            schema:
              type: object
              properties:
                order_id:
                  type: integer
          400:
            description: 请求格式错误
          404:
            description: 产品未找到
          500:
            description: 服务器错误，库存更新失败
        '''
        # 从请求中获取订单信息
        data = request.get_json()
        products = data.get('products', [])

        if not products:
            return {"message": "订单中没有任何产品"}, 400
        

        # 开始数据库事务
        connection = get_db()
        cursor = connection.cursor()

        try:
            # 创建订单
            cursor.execute("INSERT INTO orders (user_id, created_at) VALUES (%s, %s)", (user_id, datetime.now()))
            order_id = cursor.lastrowid  # 获取新创建的订单 ID

            # 为订单添加产品
            for item in products:
                product_id = item['product_id']
                quantity = item['quantity']

                # 查询产品库存
                cursor.execute("SELECT stock FROM products WHERE id = %s", (product_id,))
                product = cursor.fetchone()
                if not product:
                    return {"message": f"产品 {product_id} 未找到"}, 404

                stock = product[0]
                if stock < quantity:
                    return {"message": f"产品 {product_id} 库存不足"}, 400

                # 插入订单项
                cursor.execute("INSERT INTO order_items (order_id, product_id, quantity) VALUES (%s, %s, %s)", 
                               (order_id, product_id, quantity))

                # 更新库存
                new_stock = stock - quantity
                cursor.execute("UPDATE products SET stock = %s WHERE id = %s", (new_stock, product_id))

            # 提交事务
            connection.commit()

            return {"order_id": order_id}, 201
        
        except Exception as e:
            connection.rollback()  # 回滚事务
            return {"message": "服务器错误，订单创建失败"}, 500
        finally:
            cursor.close()
    
    @jwt_required
    def get(self,user_id):
        '''
        获取当前用户的订单列表
        ---
        tags:
          - Orders
        description: 获取当前用户所有订单的状态和历史记录
        responses:
          200:
            description: 用户的订单列表
            schema:
              type: array
              items:
                type: object
                properties:
                  order_id:
                    type: integer
                  status:
                    type: string
                  created_at:
                    type: string
                    format: date-time
          404:
            description: 用户未找到
        '''

        connection = get_db()
        cursor = connection.cursor()

        # 查询用户的所有订单
        cursor.execute("SELECT id, status, created_at FROM orders WHERE user_id = %s", (user_id,))
        orders = cursor.fetchall()

        cursor.close()

        if orders:
            return [{"order_id": order[0], "status": order[1], "created_at": order[2].isoformat()} for order in orders], 200
        else:
            return {"message": "没有找到订单记录"}, 404


class ProductCategoriesAPI(Resource):

    def get(self):
        '''
        按分类查询产品
        ---
        tags:
          - Products
        description: 查询某一分类下的所有产品
        parameters:
          - name: category
            in: query
            type: string
            required: true
            description: 产品的分类
        responses:
          200:
            description: 产品列表
            schema:
              type: array
              items:
                type: object
                properties:
                  id:
                    type: integer
                  name:
                    type: string
                  price:
                    type: number
                    format: float
                  stock:
                    type: integer
          404:
            description: 没有找到该分类的产品
        '''
        category = request.args.get('category')
        if not category:
            return {"message": "分类参数缺失"}, 400

        connection = get_db()
        cursor = connection.cursor()

        # 查询指定分类下的所有产品
        cursor.execute("SELECT id, name, price, stock FROM products WHERE category = %s", (category,))
        products = cursor.fetchall()

        cursor.close()

        if products:
            return [{"id": product[0], "name": product[1], "price": product[2], "stock": product[3]} for product in products], 200
        else:
            return {"message": "没有找到该分类的产品"}, 404


class CategoryAPI(Resource):
    @require_admin
    def post(self):
        '''
        创建新的产品分类
        ---
        tags:
          - Categories
        description: 创建新的产品分类
        parameters:
          - name: category
            in: body
            required: true
            description: 分类信息
            schema:
              type: object
              properties:
                name:
                  type: string
        responses:
          201:
            description: 分类创建成功
            schema:
              type: object
              properties:
                category_id:
                  type: integer
          400:
            description: 请求格式错误
        '''
        data = request.get_json()
        category_name = data.get('name')

        if not category_name:
            return {"message": "分类名称是必需的"}, 400

        connection = get_db()
        cursor = connection.cursor()

        try:
            cursor.execute("INSERT INTO categories (name) VALUES (%s)", (category_name,))
            category_id = cursor.lastrowid  # 获取新创建的分类 ID
            connection.commit()

            return {"category_id": category_id}, 201
        except Exception as e:
            connection.rollback()
            return {"message": "服务器错误，分类创建失败"}, 500
        finally:
            cursor.close()

